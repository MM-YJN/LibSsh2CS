using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS;

/// <summary>
/// A managed SSH-2.0 session. Owns the encrypted transport over a caller-supplied
/// <see cref="IDuplexPipe"/> and exposes handshake, disconnect, host-key retrieval,
/// algorithm preferences, session flags, and the rekey entry point. The userauth
/// methods live in the <see cref="SshUserAuth"/> extension class.
/// </summary>
/// <remarks>
/// <para>
/// <b>Lifecycle.</b> Construct with <see cref="SshSession()"/>; configure
/// preferences / flags via the indexer / <see cref="SetFlag"/>; call
/// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
/// (or the
/// <see cref="HandshakeAsync(Stream, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
/// convenience overload) to run banner exchange → KEXINIT → KEX → NEWKEYS → SERVICE_REQUEST. The
/// caller owns the underlying transport (socket / <see cref="System.Net.Sockets.NetworkStream"/>);
/// the session does NOT dispose it. <see cref="DisposeAsync"/> sends
/// <c>SSH_MSG_DISCONNECT</c> (best-effort) and disposes the packet reader/writer
/// it created from the pipe.
/// </para>
/// <para>
/// <b>Port scope.</b> Replaces <c>session.c:731-858</c> (handshake state machine),
/// <c>session.c:1189-1238</c> (disconnect), <c>session.c:1421-1439</c> (flags),
/// <c>session.c:390-419</c> (banner set), <c>session.c:1948-1958</c> (banner get),
/// and the KEX orchestration that delegates to <see cref="KeyExchange.RunExchangeAsync"/>.
/// The C <c>session_startup</c> state machine (idle → created → sent → sent1 →
/// sent2 → sent3 → sent4 → idle) collapses to local variables inside
/// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>'s async body — the compiler's state machine
/// replaces libssh2's hand-rolled one.
/// </para>
/// <para>
/// <b>Banner exchange parity</b> (<c>session.c:761-783</c>): the client sends its
/// banner BEFORE reading the server's (both may send independently per RFC 4253
/// §4.2). The server banner is read byte-by-byte into an 8192-byte buffer until
/// <c>\n</c>; trailing CR/LF stripped; NUL bytes rejected
/// (<c>LIBSSH2_ERROR_BANNER_RECV</c>); pre-banner non-<c>SSH-</c> lines are
/// discarded and re-read (<c>session.c:781</c>).
/// </para>
/// <para>
/// <b>EXT_INFO surfacing</b> (RFC 8308): <see cref="PacketQueue"/> stashes
/// <c>SSH_MSG_EXT_INFO</c> (type 7) during KEX. <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
/// retrieves it post-KEX and parses <c>server-sig-algs</c> into
/// <see cref="ServerSignatureAlgorithms"/> for <see cref="SshUserAuth"/>'s RSA-SHA2
/// selection (parity with <c>userauth.c:1351</c> <c>_libssh2_key_sign_algorithm</c>).
/// </para>
/// <para>
/// <b>Hostkey verification.</b> <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> requires a non-null
/// <c>verifyHostKeyAsync</c> callback
/// (<c>(hostKey, exchangeHash, cancellationToken) → bool</c>) wired into
/// <see cref="KeyExchange.RunExchangeAsync"/>'s verify seam for initial host trust.
/// Signature validity alone does not establish trust. Rekey callback behavior is unchanged.
/// </para>
/// </remarks>
public sealed class SshSession : IAsyncDisposable
{
    /// <summary>The maximum server banner length in bytes (session.c:121, buffer 8192).</summary>
    private const int MaxBannerLen = 8192;

    /// <summary>The default client identification string (without CRLF).</summary>
    private const string DefaultClientBanner = "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version;

    /// <summary>The SSH-2 service name requested after KEX (session.c:802-806).</summary>
    private const string UserService = "ssh-userauth";

    private readonly MethodPreferences _prefs = new();
    private SshFlag _flags = SshFlag.QuotePaths;   // QuotePaths defaults to true (session.c:475)

    // ── Rekey ────────────────────────────────────────────
    // TimeProvider injection lets tests substitute FakeTimeProvider for
    // deterministic time-trigger verification (production uses TimeProvider.System).
    private readonly TimeProvider _timeProvider;
    private long _handshakeTimestampTicks;   // _timeProvider.GetTimestamp() at handshake completion
    private RekeyPolicy _rekeyPolicy = RekeyPolicy.Default;
    private int _rekeyInProgress;   // 0/1; 1 while a rekey is in flight (Interlocked guard)

    // ── Keepalive ────────────────────────────────────────
    // Caller-driven SSH keepalive state. Mirrors libssh2's
    // session->keepalive_{interval,want_reply,last_sent} (keepalive.c).
    // _keepaliveIntervalSeconds == 0 disables keepalive (the SendKeepAliveAsync
    // no-op fast-path). _lastKeepaliveTimestampTicks is updated each time a
    // keepalive packet is actually sent; _keepaliveEverSent distinguishes the
    // never-sent state (the C's keepalive_last_sent == 0 calloc'ed value, which
    // makes the FIRST libssh2_keepalive_send always fire — keepalive.c:71).
    private int _keepaliveIntervalSeconds;
    private bool _keepaliveWantReply;
    private bool _keepaliveEverSent;
    private long _lastKeepaliveTimestampTicks;

    // ── Forward listeners ────────────────────────────────
    // Concurrent registry keyed by (host, port) for O(1) lookup during the
    // inbound CHANNEL_OPEN "forwarded-tcpip" dispatch in 5.6 (parity
    // packet.c:137-141). SshSession.ListenForwardAsync adds; SshListener.DisposeAsync
    // removes via SshSession.UnregisterListener.
    private readonly ConcurrentDictionary<(string Host, int Port), SshListener> _listeners = new();

    private PacketWriter? _writer;
    private PacketQueue? _queue;
    // CA2213 false positive: the dispose call `_channelRouter?.Dispose()`
    // in DisposeAsync is genuine, but the nullable annotation combined with
    // the listener-teardown block pushes the analyzer
    // past its flow-analysis budget. The field is disposed along every
    // code path that assigns it.
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "the dispose call `_channelRouter?.Dispose()` in DisposeAsync is genuine, but the nullable annotation combined with the listener-teardown block added in Phase 5.5 pushes the analyzer past its flow-analysis budget. The field is disposed along every code path that assigns it.")]
    private ChannelRouter? _channelRouter;
    private NegotiatedMethods? _negotiated;
    private string? _serverBanner;
    private byte[]? _hostKey;
    private byte[]? _sessionId;
    private string[]? _serverSigAlgs;
    // Read-only wrapper over _serverSigAlgs, installed whenever the field is
    // assigned so the public property cannot be cast back to string[] and
    // mutated by the caller.
    private IReadOnlyList<string>? _serverSigAlgsView;
    private string? _userAuthBanner;
    private bool _authenticated;
    private bool _handshakeCompleted;
    private int _handshakeStarted;   // 0/1 re-entry guard for HandshakeAsync (reset on failure so a retry is allowed)
    private int _disposed;   // 0/1 (Interlocked guard; bool fields cannot be exchanged atomically)

    /// <summary>
    /// True once <see cref="DisposeAsync"/> has started (or completed) the
    /// teardown. Read via the atomic-guarded int field; used by the public
    /// entry-point guards.
    /// </summary>
    internal bool IsDisposed => _disposed != 0;

    /// <summary>
    /// Constructs a new session with default preferences, flags, and rekey policy.
    /// Uses <see cref="TimeProvider.System"/> for the rekey time-trigger.
    /// </summary>
    public SshSession()
        : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Internal constructor that injects a <see cref="TimeProvider"/> for the
    /// rekey time-trigger. Tests pass <c>FakeTimeProvider</c> for deterministic
    /// time-based threshold verification (production callers use the public
    /// zero-arg ctor which wires <see cref="TimeProvider.System"/>).
    /// </summary>
    internal SshSession(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
        // NB: _lastKeepaliveTimestampTicks is intentionally NOT seeded here —
        // the never-sent state (_keepaliveEverSent == false) makes the first
        // SendKeepAliveAsync always fire, mirroring keepalive.c:71 where the
        // calloc'ed keepalive_last_sent == 0 makes the first call always send.
        // The previous construction-time baseline delayed the first keepalive
        // by a full interval.
    }

    // ── Public properties ──────────────────────────────────────────────────

    /// <summary>
    /// The raw server host-key blob, available after <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
    /// completes. Returns an empty value before handshake (a completed
    /// handshake always yields a non-empty <c>K_S</c>).
    /// </summary>
    /// <remarks>
    /// A read-only view over the session's private copy, not a snapshot. The
    /// type system prevents ordinary mutation; callers must not attempt to
    /// mutate the underlying buffer.
    /// </remarks>
    public ReadOnlyMemory<byte> HostKey => _hostKey ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// The negotiated host-key algorithm name (e.g. <c>"ssh-ed25519"</c>),
    /// available after handshake. Returns <see langword="null"/> before handshake.
    /// </summary>
    public string? HostKeyAlgorithm => _negotiated?.HostKeyName;

    /// <summary>
    /// The SSH session id — the first exchange hash <c>H</c>, immutable across
    /// rekeys. Returns an empty value before the first handshake completes.
    /// </summary>
    /// <remarks>
    /// A read-only view over the session's private copy, not a snapshot. The
    /// type system prevents ordinary mutation; the session id is prepended to
    /// every userauth signature, so callers must not attempt to mutate the
    /// underlying buffer.
    /// </remarks>
    public ReadOnlyMemory<byte> SessionId => _sessionId ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// The server's identification string (banner), CRLF-stripped. Returns
    /// <see langword="null"/> before handshake.
    /// </summary>
    public string? ServerBanner => _serverBanner;

    /// <summary>
    /// True after a userauth method succeeds. Set by <see cref="SshUserAuth"/>.
    /// </summary>
    public bool IsAuthenticated => _authenticated;

    /// <summary>
    /// The <c>server-sig-algs</c> extension value from <c>SSH_MSG_EXT_INFO</c>
    /// (RFC 8308 §3.1), split on commas. Empty if the server sent
    /// <c>SSH_MSG_EXT_INFO</c> without advertising <c>server-sig-algs</c>.
    /// Consulted by <see cref="SshUserAuth"/> for RSA-SHA2 algorithm selection.
    /// Returns <see langword="null"/> before handshake (no EXT_INFO received).
    /// </summary>
    /// <remarks>
    /// A read-only list over the parsed value. The <see langword="null"/> state
    /// is retained because it distinguishes "no EXT_INFO was received" from
    /// "EXT_INFO was received but did not carry <c>server-sig-algs</c>".
    /// </remarks>
    public IReadOnlyList<string>? ServerSignatureAlgorithms => _serverSigAlgsView;

    /// <summary>
    /// Sets <see cref="ServerSignatureAlgorithms"/> directly. Internal — used by
    /// tests to exercise RSA-SHA2 selection without running a full handshake
    /// against a real server (the value is normally populated from EXT_INFO by
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>).
    /// </summary>
    internal void SetServerSignatureAlgorithmsForTest(string[]? algs)
        => SetServerSignatureAlgorithms(algs);

    /// <summary>
    /// Installs <see cref="ServerSignatureAlgorithms"/> and its read-only view
    /// together, so the public property and the internal array never diverge.
    /// </summary>
    private void SetServerSignatureAlgorithms(string[]? algs)
    {
        _serverSigAlgs = algs;
        _serverSigAlgsView = algs is null ? null : Array.AsReadOnly(algs);
    }

    /// <summary>
    /// Sets the outbound packet writer directly, bypassing the
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
    /// path. Internal — used by keepalive
    /// tests to drive <see cref="SendKeepAliveAsync"/> against a cleartext pipe
    /// without running a full KEX. Mirrors the <c>ChannelTestHarness</c>
    /// pattern in the test project.
    /// </summary>
    internal void SetWriterForTest(PacketWriter writer) => _writer = writer;

    /// <summary>
    /// Sets the channel router directly, bypassing the
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> path. Internal — used by tests to
    /// drive <see cref="SendGlobalRequestAsync"/> against a cleartext pipe
    /// without running a full KEX.
    /// </summary>
    internal void SetChannelRouterForTest(ChannelRouter router) => _channelRouter = router;

    // ── Internal accessors for UserAuth ─────────────────────────────────────

    /// <summary>The outbound packet framer. Null before handshake.</summary>
    internal PacketWriter? Writer => _writer;

    /// <summary>The inbound packet queue. Null before handshake.</summary>
    internal PacketQueue? Queue => _queue;

    // ── IGNORE/DEBUG callbacks (libssh2_session_callback_set parity) ───────

    private Action<ReadOnlyMemory<byte>>? _ignoreCallback;
    private Action<bool, string, string>? _debugCallback;

    /// <summary>
    /// Optional callback invoked for every <c>SSH_MSG_IGNORE</c> packet with
    /// the raw payload bytes after the type byte. Parity with
    /// <c>libssh2_session_callback_set(LIBSSH2_CALLBACK_IGNORE)</c>
    /// (packet.c:787-796). May be set before or after the handshake; packets
    /// dispatched before the callback is set are simply discarded (the C's
    /// behavior when no callback is registered).
    /// </summary>
    public Action<ReadOnlyMemory<byte>>? IgnoreCallback
    {
        get => _ignoreCallback;
        set
        {
            _ignoreCallback = value;
            _queue?.IgnoreCallback = value;
        }
    }

    /// <summary>
    /// Optional callback invoked for every <c>SSH_MSG_DEBUG</c> packet with
    /// <c>(alwaysDisplay, message, language)</c> (RFC 4252 §5.3). Parity with
    /// <c>libssh2_session_callback_set(LIBSSH2_CALLBACK_DEBUG)</c>
    /// (packet.c:801-821). May be set before or after the handshake.
    /// </summary>
    public Action<bool, string, string>? DebugCallback
    {
        get => _debugCallback;
        set
        {
            _debugCallback = value;
            _queue?.DebugCallback = value;
        }
    }

    // ── Read timeout (libssh2_session_set_read_timeout parity) ─────────────

    private TimeSpan _readTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The packet-read deadline for the session's packet waits — parity with
    /// libssh2's <c>packet_read_timeout</c> (default 60 s; session.c:474,
    /// packet.c:1510-1526, 1633-1642: <c>LIBSSH2_ERROR_TIMEOUT</c> when the
    /// expected packet has not arrived). Values ≤ 0 reset to the 60 s default,
    /// exactly like <c>libssh2_session_set_read_timeout</c> (session.c:1500-1514).
    /// The timeout applies to the require/requirev-style waits (auth, rekey,
    /// channel-open, handshake); channel data delivery is unaffected (matching
    /// the C, whose deadline is enforced only in the packet-require layer).
    /// May be set before or after the handshake.
    /// </summary>
    public TimeSpan ReadTimeout
    {
        get => _readTimeout;
        set
        {
            _readTimeout = value <= TimeSpan.Zero ? TimeSpan.FromSeconds(60) : value;
            _queue?.ReadTimeout = _readTimeout;
        }
    }

    /// <summary>
    /// The channel demultiplexer. Null before handshake. Once channels exist,
    /// this is the SOLE reader of <see cref="Queue"/> (single-consumer contract).
    /// </summary>
    internal ChannelRouter? ChannelRouter => _channelRouter;

    /// <summary>
    /// Sets the authenticated flag and activates delayed compression. Called by
    /// <c>UserAuth</c> methods on SSH_MSG_USERAUTH_SUCCESS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For <c>zlib@openssh.com</c> (RFC 8370, "delayed compression"), the
    /// negotiated compressor is installed at NEWKEYS but stays inert until the
    /// auth-success transition — mirrors libssh2's
    /// <c>(session->state &amp; LIBSSH2_STATE_AUTHENTICATED) ||
    /// session->local.comp->use_in_auth</c> per-packet predicate
    /// (<c>transport.c:292-295, 1060-1063</c>). The activation calls are
    /// idempotent no-ops when the negotiated method is <c>zlib</c> (already
    /// active from NEWKEYS) or <c>none</c> (<see cref="ICompression.Compresses"/>
    /// gates the per-packet code path regardless of the flag).
    /// </para>
    /// <para>
    /// The <c>SSH_MSG_USERAUTH_SUCCESS</c> packet itself is uncompressed; the
    /// flag flip is therefore visible to the next read/write, which is the first
    /// potentially-compressed packet (RFC 4253 §6.1).
    /// </para>
    /// </remarks>
    internal void MarkAuthenticated()
    {
        _authenticated = true;
        _writer?.ActivateDelayedCompression();
        _queue?.Reader.ActivateDelayedCompression();
    }

    /// <summary>
    /// Gets or sets the pre-auth banner captured from <c>SSH_MSG_USERAUTH_BANNER</c>
    /// (type 53). Set by <c>UserAuth</c> response handlers.
    /// </summary>
    internal string? UserAuthBanner
    {
        get => _userAuthBanner;
        set => _userAuthBanner = value;
    }

    // ── Preferences + flags ─────────────────────────────────────────────────

    /// <summary>
    /// Gets or sets the comma-separated algorithm preference list for a category.
    /// Mirrors <c>libssh2_session_method_pref</c>: set before handshake to
    /// override the default preference order.
    /// </summary>
    /// <remarks>
    /// <b>Set-time filtering</b> (parity <c>kex.c:4283-4315</c>): names not in
    /// the in-scope method registry are stripped from the stored list (the C
    /// strips names its method table lacks); if everything is stripped the
    /// setter throws <see cref="SshErrorCode.MethodNotSupported"/> (the C's
    /// "The requested method(s) are not currently supported"), except for KEX
    /// where the prepended <c>ext-info-c,kex-strict-c-v00@openssh.com</c>
    /// extensions keep the list non-empty. Previously names were stored
    /// verbatim and only rejected at negotiation.
    /// An empty string still means "use the default list" (the C rejects an
    /// explicit empty list, but the empty-string sentinel is the port's
    /// unset convention).
    /// </remarks>
    public string this[SshMethodType type]
    {
        get => _prefs[type];
        set => _prefs[type] = FilterMethodPrefs(type, value ?? string.Empty);
    }

    /// <summary>
    /// Set-time filtering of a method preference list — port of
    /// <c>libssh2_session_method_pref</c>'s strip loop (kex.c:4283-4315).
    /// Categories with no method table (LANG_CS/LANG_SC/SIGN_ALGO — mlist
    /// NULL at kex.c:4253-4266) are stored verbatim.
    /// </summary>
    private static string FilterMethodPrefs(SshMethodType type, string prefs)
    {
        if (prefs.Length == 0)
        {
            return string.Empty;   // unset sentinel — the default list applies
        }

        IReadOnlyList<string>? known = type switch
        {
            SshMethodType.Kex => KexMethods.DefaultPreferences,
            SshMethodType.HostKey => HostKeyMethods.DefaultPreferences,
            SshMethodType.CryptCs or SshMethodType.CryptSc => CipherMethods.DefaultPreferences,
            SshMethodType.MacCs or SshMethodType.MacSc => MacMethods.DefaultPreferences,
            SshMethodType.CompCs or SshMethodType.CompSc => CompressionMethods.DefaultPreferences,
            _ => null,
        };

        if (known is null)
        {
            return prefs;
        }

        var knownSet = new HashSet<string>(known, StringComparer.Ordinal);
        string kept = string.Join(",",
            prefs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Where(n => knownSet.Contains(n)));

        if (kept.Length == 0 && type != SshMethodType.Kex)
        {
            throw new SshException(SshErrorCode.MethodNotSupported,
                "The requested method(s) are not currently supported");
        }

        return kept;
    }

    /// <summary>
    /// Sets a session behavioral flag. <see cref="SshFlag.Compress"/> must be
    /// set before <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> to take effect (it filters the
    /// client's compression name-list in KEXINIT). Mirrors
    /// <c>libssh2_session_flag</c>.
    /// </summary>
    public void SetFlag(SshFlag flag, bool value)
    {
        if (value)
        {
            _flags |= flag;
        }
        else
        {
            _flags &= ~flag;
        }
    }

    /// <summary>Gets the current session flags.</summary>
    public SshFlag Flags => _flags;

    // ── Rekey policy + counters ─────────────────────────────

    /// <summary>
    /// The rekey auto-trigger policy. Defaults to <see cref="RekeyPolicy.Default"/>
    /// (OpenSSH's 4 GB / 2³¹ packets / 1 hour). Set to <see cref="RekeyPolicy.Never"/>
    /// to disable auto-trigger and rely solely on server-initiated rekey (which
    /// the queue handles inline via the <c>SSH_MSG_KEXINIT</c> path). Set BEFORE
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>; changes after handshake are ignored by the
    /// auto-trigger (the router captures the value at handshake completion).
    /// </summary>
    public RekeyPolicy RekeyPolicy
    {
        get => _rekeyPolicy;
        set => _rekeyPolicy = value ?? RekeyPolicy.Never;
    }

    /// <summary>
    /// Bytes received under the current inbound key since the last NEWKEYS.
    /// Mirrors <see cref="PacketReader.InboundBytes"/>. Zero before
    /// handshake.
    /// </summary>
    public long InboundBytes => _queue?.Reader.InboundBytes ?? 0;

    /// <summary>
    /// Bytes sent under the current outbound key since the last NEWKEYS.
    /// Mirrors <see cref="PacketWriter.OutboundBytes"/>. Zero before
    /// handshake.
    /// </summary>
    public long OutboundBytes => _writer?.OutboundBytes ?? 0;

    /// <summary>
    /// Packets received under the current inbound key since the last NEWKEYS.
    /// Mirrors <see cref="PacketReader.InboundPackets"/>.
    /// </summary>
    public long InboundPackets => _queue?.Reader.InboundPackets ?? 0;

    /// <summary>
    /// Packets sent under the current outbound key since the last NEWKEYS.
    /// Mirrors <see cref="PacketWriter.OutboundPackets"/>.
    /// </summary>
    public long OutboundPackets => _writer?.OutboundPackets ?? 0;

    /// <summary>
    /// Elapsed time since the last NEWKEYS (or handshake completion, before the
    /// first rekey), measured via the session's <see cref="TimeProvider"/>. The
    /// rekey auto-trigger compares this against
    /// <see cref="RekeyPolicy.MaxInterval"/>. Returns <see cref="TimeSpan.Zero"/>
    /// before handshake completion.
    /// </summary>
    public TimeSpan ElapsedSinceHandshake
        => _handshakeCompleted
            ? _timeProvider.GetElapsedTime(_handshakeTimestampTicks, _timeProvider.GetTimestamp())
            : TimeSpan.Zero;

    /// <summary>
    /// Observability counter: number of rekey cycles that have completed since
    /// this session was constructed. Incremented in <see cref="RekeyAsync"/>'s
    /// <c>finally</c> block (both successful and failed attempts). Useful for
    /// diagnostics/telemetry on long-lived sessions and for verifying the
    /// auto-trigger fires during live traffic. Not consulted
    /// by any production code path.
    /// </summary>
    public int RekeyCount { get; private set; }

    // ── Host-key fingerprint ─────────────────────────────────────────────────

    /// <summary>
    /// Returns the SHA-1 or SHA-256 fingerprint of the server host key as a
    /// lowercase hex string. Mirrors <c>libssh2_hostkey_hash</c>. Throws if
    /// called before handshake.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if called before
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> completes.</exception>
    public string HostKeyHash(SshHostKeyHashType type)
    {
        if (_hostKey is null)
        {
            throw new InvalidOperationException("HostKey is not available until HandshakeAsync completes.");
        }

        byte[] digest = type switch
        {
            SshHostKeyHashType.Sha1 => SHA1Hash(_hostKey),
            SshHostKeyHashType.Sha256 => SHA256.HashData(_hostKey),
            _ => throw new ArgumentOutOfRangeException(nameof(type)),
        };
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>SHA-1 hash helper with the CA5350 suppression — SHA-1 use here
    /// is hostkey fingerprinting (a display value, not a signature), kept for
    /// parity with <c>libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1)</c>.</summary>
    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "SHA-1 use here is hostkey fingerprinting (a display value, not a signature), kept for parity with libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1).")]
    private static byte[] SHA1Hash(byte[] data) => SHA1.HashData(data);

    // ── Handshake ───────────────────────────────────────────────────────────

    /// <summary>
    /// Runs the full SSH-2 transport handshake over <paramref name="transport"/>:
    /// banner exchange → KEXINIT → KEX → NEWKEYS → SERVICE_REQUEST. Sets
    /// <see cref="HostKey"/>, <see cref="SessionId"/>, <see cref="ServerBanner"/>,
    /// and <see cref="ServerSignatureAlgorithms"/>. The caller owns the
    /// transport (socket/stream); the session does not dispose it.
    /// </summary>
    /// <param name="transport">The encrypted transport pipe. The session reads
    /// from <see cref="IDuplexPipe.Input"/> and writes to
    /// <see cref="IDuplexPipe.Output"/>.</param>
    /// <param name="verifyHostKeyAsync">Required initial host-trust verification callback
    /// invoked after the exchange hash is computed. Receives the raw host-key
    /// blob, the exchange hash <c>H</c>, and the cancellation token; returns
    /// <see langword="true"/> to accept, <see langword="false"/> to abort with
    /// <see cref="SshErrorCode.KeyExchangeFailure"/>. Use a previously trusted
    /// known_hosts file or another explicit trust policy. The server's signature over <c>H</c>
    /// is ALWAYS verified internally first (parity with libssh2's
    /// <c>sig_verify</c> at <c>kex.c:746-751</c>); this callback is the
    /// additional key-trust check, like libgit2's <c>check_certificate</c>.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="ArgumentNullException">The transport or trust callback is null.</exception>
    public async Task HandshakeAsync(
        IDuplexPipe transport,
        Func<byte[], byte[], CancellationToken, Task<bool>> verifyHostKeyAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifyHostKeyAsync);
        ArgumentNullException.ThrowIfNull(transport);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        // Re-entry guard: a second call (a retry after a failure, or a
        // concurrent call) would replace _writer/_queue/_channelRouter without
        // disposing the old instances (leaking their cipher/MAC state) and two
        // concurrent calls interleave writes on the same pipe. The exchange is
        // atomic so exactly one caller proceeds; the guard is reset on the
        // failure path so a retry starts clean. (Re-entry is equally undefined
        // in the C — session_startup re-runs the state machine — but the
        // undisposed-disposables leak and the write interleaving are
        // port-specific.)
        if (Interlocked.Exchange(ref _handshakeStarted, 1) != 0)
        {
            throw new InvalidOperationException(
                "HandshakeAsync may only be called once per session.");
        }

        try
        {
            await HandshakeCoreAsync(transport, verifyHostKeyAsync, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Failure-path cleanup: dispose the fresh writer/queue/router
            // (they hold cipher/MAC/semaphore state) so nothing leaks and a
            // retry starts clean. PacketWriter/PacketReader dispose only their
            // OWN state — the caller-owned pipes are untouched.
            if (_writer is not null)
            {
                await _writer.DisposeAsync().ConfigureAwait(false);
            }

            if (_queue is not null)
            {
                await _queue.Reader.DisposeAsync().ConfigureAwait(false);
            }

            _channelRouter?.Dispose();

            // Clear the cached handshake state so the public surface reports
            // "not available" after a failed handshake: HostKey/SessionId are
            // empty, ServerSignatureAlgorithms/ServerBanner are null. Without
            // this, a failure after the KEX (e.g. SERVICE_REQUEST rejected)
            // could leave stale values that look like a completed handshake.
            _hostKey = null;
            _sessionId = null;
            _serverBanner = null;
            _negotiated = null;
            SetServerSignatureAlgorithms(null);

            Interlocked.Exchange(ref _handshakeStarted, 0);
            throw;
        }
    }

    /// <summary>
    /// The handshake body (banner exchange → KEXINIT → KEX → SERVICE_REQUEST),
    /// invoked by <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
    /// under its re-entry guard.
    /// </summary>
    private async Task HandshakeCoreAsync(
        IDuplexPipe transport,
        Func<byte[], byte[], CancellationToken, Task<bool>> verifyHostKeyAsync,
        CancellationToken cancellationToken)
    {
        _writer = new PacketWriter(transport.Output);
        _queue = new PacketQueue(new PacketReader(transport.Input))
        {
            // Wire the IGNORE/DEBUG callbacks (may have been set before the
            // handshake; the property setters also push later assignments)
            // and the read timeout + clock.
            IgnoreCallback = _ignoreCallback,
            DebugCallback = _debugCallback,
            ReadTimeout = _readTimeout,
            TimeProvider = _timeProvider,
        };
        _channelRouter = new ChannelRouter(_queue, _writer);

        // ── 1. Banner exchange (session.c:761-783) ───────────────────────────
        // Client sends first, then reads the server's. Both may send
        // independently per RFC 4253 §4.2; libssh2 sends then reads.
        // NB: there is no libssh2_session_banner_set pref surface; only the
        // default banner is supported. The
        // LangCs preference MUST NOT double as a banner override: it only feeds
        // the KEXINIT language name-list (KeyExchange.BuildKexInit), exactly
        // like libssh2's LIBSSH2_METHOD_LANG_CS (kex.c:3426-3432). Reusing it
        // for the identification string sent a non-"SSH-" banner on the wire
        // when the caller set a language, and broke the rekey exchange hash.
        string clientBanner = DefaultClientBanner;
        byte[] cb = Encoding.ASCII.GetBytes(clientBanner + "\r\n");
        await transport.Output.WriteAsync(cb, cancellationToken).ConfigureAwait(false);
        await transport.Output.FlushAsync(cancellationToken).ConfigureAwait(false);

        _serverBanner = await ReadServerBannerAsync(transport.Input, cancellationToken).ConfigureAwait(false);

        // ── 2. KEXINIT (client sends first, kex.c:4092) ─────────────────────
        byte[] clientKexInit = BuildKexInitWithCompressFilter();
        await _writer.WritePacketAsync(PacketType.KexInit, clientKexInit, cancellationToken)
            .ConfigureAwait(false);

        RawPacket serverKexInitPkt = await _queue.WaitForTypeAsync(PacketType.KexInit, cancellationToken)
            .ConfigureAwait(false);
        byte[] serverKexInit = serverKexInitPkt.Payload;

        KexInit clientInit = KeyExchange.ParseKexInit(clientKexInit);
        KexInit serverInit = KeyExchange.ParseKexInit(serverKexInit);
        _negotiated = KeyExchange.Negotiate(clientInit, serverInit);
        _queue.StrictKex = _negotiated.StrictKex;

        // Strict-KEX rule (a): the server's KEXINIT must be the very first
        // packet it sent, so its inbound seqno must be 0 (packet.c:715-726).
        // Strict-KEX is only LEARNED from the KEXINIT itself (its kex
        // name-list carries kex-strict-s-v00@openssh.com), so the queue's
        // unexpected-type check cannot catch pre-KEXINIT injections — but the
        // injected packet consumed seqno 0, so the KEXINIT's nonzero seqno is
        // exactly the pre-NEWKEYS packet-injection signal the Terrapin
        // countermeasure detects. The C checks this in
        // _libssh2_packet_add the moment the KEXINIT arrives; the port checks
        // it right after negotiation, before anything else is sent.
        if (_negotiated.StrictKex && serverKexInitPkt.Seqno != 0)
        {
            throw new SshException(SshErrorCode.SocketDisconnect,
                "strict KEX violation: KEXINIT was not the first packet");
        }

        KeyExchange.KexExchangeResult kex = await KeyExchange.RunExchangeAsync(
            _writer, _queue, _negotiated,
            clientBanner, _serverBanner,
            clientKexInit, serverKexInit,
            verifyAsync: VerifyExchangeSignatureAsync, cancellationToken: cancellationToken).ConfigureAwait(false);

        _hostKey = kex.HostKey;
        _sessionId = kex.SessionId;

        // libssh2 ALWAYS verifies the hostkey signature over H internally on
        // every key exchange (kex.c:746-751) before proceeding; the caller's
        // callback is an ADDITIONAL key-level check (e.g. known_hosts) —
        // parity with libgit2's check_certificate running after libssh2's
        // internal sig_verify. The signature was previously dropped at this
        // boundary, so production never verified it.
        async Task<bool> VerifyExchangeSignatureAsync(byte[] hostKey, byte[] h, byte[] sig, CancellationToken ct)
        {
            if (!HostKeyVerifier.Verify(hostKey, h, sig, _negotiated!.HostKey))
            {
                return false;
            }

            // Hand the callback copies: K_S and H are the same arrays the KEX
            // layer keeps using for key derivation and stores as the session's
            // host key / session id. A callback that mutates its arguments must
            // not be able to corrupt that state (the same reason libssh2
            // recomputes its hashes from an owned copy).
            return await verifyHostKeyAsync((byte[])hostKey.Clone(), (byte[])h.Clone(), ct).ConfigureAwait(false);
        }

        // ── 4. SERVICE_REQUEST "ssh-userauth" (session.c:797-858) ──────────
        await SendServiceRequestAsync(_writer, cancellationToken).ConfigureAwait(false);
        await WaitForServiceAcceptAsync(_queue, cancellationToken).ConfigureAwait(false);

        // ── 5. Surface EXT_INFO (server-sig-algs) ───────────────────────────
        // The PacketQueue stashes SSH_MSG_EXT_INFO (type 7) when it arrives
        // inline during any packet read (TryHandleInlineAsync). Per RFC 8308 §2.1
        // the server sends EXT_INFO immediately after its NEWKEYS, so the packet
        // is typically read + stashed during the SERVICE_ACCEPT wait above (the
        // pump reads it from the pipe before the SERVICE_ACCEPT packet). Retrieve
        // it non-blockingly now; if present, parse server-sig-algs for UserAuth.
        if (_queue.TryTakeStashed(PacketType.ExtInfo, out RawPacket extInfoPkt))
        {
            var ext = ExtInfo.Parse(extInfoPkt.Payload);
            SetServerSignatureAlgorithms(ext.ServerSignatureAlgorithms);
        }

        _handshakeCompleted = true;

        // ── Rekey time-trigger baseline ───────────────────
        // Captured AFTER handshake completion so the 1hr window starts at the
        // first post-KEX moment (the moment the session is usable for auth).
        // Reset in RekeyAsync's finally block at each rekey.
        _handshakeTimestampTicks = _timeProvider.GetTimestamp();

        // ── Rekey trigger wiring ───────────────────────────
        // Server-initiated KEXINIT (a post-handshake SSH_MSG_KEXINIT from the
        // server) is a rekey request. PacketQueue.TryHandleInlineAsync invokes
        // this callback inline when it sees one — driving SshSession.RekeyAsync.
        // InitialKex is already false after RunExchangeAsync, so the initial
        // server KEXINIT (the one HandshakeAsync just consumed) did NOT fire
        // this callback (InitialKex=true guarded it out at packet.c:1355-1358).
        _queue.RekeyTriggerAsync = ct => RekeyAsync(ct);

        // ── Rekey auto-trigger wiring ─────────────────────
        // ChannelRouter checks thresholds before each pump and invokes this
        // callback (drives SshSession.RekeyAsync) when any counter exceeds
        // RekeyPolicy. The time-based check needs an accessor since the router
        // doesn't own a TimeProvider — close over this session's property.
        _channelRouter.ConfigureRekeyTrigger(_rekeyPolicy, ct => RekeyAsync(ct));
        _channelRouter.SetElapsedSinceHandshakeAccessor(() => ElapsedSinceHandshake);

        // ── Listener lookup wiring ─────────────────────────
        // The router's inbound CHANNEL_OPEN "forwarded-tcpip" dispatch calls
        // this closure to find the listener matching the (host, port) the
        // server is forwarding for.
        _channelRouter.ConfigureListenerLookup((host, port) => TryGetListener(host, port));
    }

    /// <summary>
    /// Convenience overload that wraps a bidirectional <see cref="Stream"/> as
    /// an <see cref="IDuplexPipe"/> via <see cref="StreamDuplexPipe"/> and runs
    /// the handshake with the required initial host-trust callback. The caller owns the stream.
    /// </summary>
    /// <param name="stream">Caller-owned bidirectional transport stream.</param>
    /// <param name="verifyHostKeyAsync">Required initial host-trust callback, invoked after
    /// exchange-signature verification. Receives the host-key blob, exchange hash and cancellation
    /// token. Return true to accept or false to abort with KeyExchangeFailure.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="ArgumentNullException">The stream or trust callback is null.</exception>
    public Task HandshakeAsync(
        Stream stream,
        Func<byte[], byte[], CancellationToken, Task<bool>> verifyHostKeyAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifyHostKeyAsync);
        ArgumentNullException.ThrowIfNull(stream);
        var duplex = new StreamDuplexPipe(stream);
        return HandshakeAsync(duplex, verifyHostKeyAsync, cancellationToken);
    }

    /// <summary>
    /// Re-runs the key exchange (rekey) on the existing transport, using the
    /// cached session id (which does not change across rekeys per RFC 4253 §7.4)
    /// and the current method preferences. Resets sequence numbers under
    /// strict-KEX. Replaces libssh2's <c>_libssh2_kex_exchange(session, 1, ...)</c>.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="InvalidOperationException">Thrown if called before
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> completes.</exception>
    public async Task RekeyAsync(CancellationToken cancellationToken = default)
    {
        if (_writer is null || _queue is null || _negotiated is null || _sessionId is null)
        {
            throw new InvalidOperationException("RekeyAsync requires a completed handshake.");
        }

        ObjectDisposedException.ThrowIf(IsDisposed, this);

        // ── Re-entry guard ──────────────────────────────
        // Two trigger paths converge here: server-initiated KEXINIT
        // (PacketQueue's inline dispatch) and client auto-trigger
        // (ChannelRouter's threshold check). If one fires while the other is
        // already mid-rekey, this guard short-circuits the second call. The
        // single-consumer contract (channel ops don't run concurrently) makes
        // this a defensive guard, not a hot-path synchronization primitive.
        // Atomic exchange — the plain-bool check-then-set let the public
        // RekeyAsync racing the pump-triggered rekey callback (different tasks)
        // both pass the guard and both send KEXINIT (protocol desync + two
        // RunExchangeAsync runs racing on the writer/queue). The exchange makes
        // the claim atomic: exactly one caller proceeds.
        if (Interlocked.Exchange(ref _rekeyInProgress, 1) != 0)
        {
            throw new SshException(SshErrorCode.Proto,
                "Rekey already in progress; concurrent rekey attempts are not allowed.");
        }
        try
        {
            // The strict-KEX flag is already set on the queue from the initial
            // negotiation; it persists across rekeys. RunExchangeAsync handles
            // the second-call path (InitialKex is already false after the first
            // KEX, so the strict-KEX type-enforcement is not re-armed for rekey).
            byte[] clientKexInit = BuildKexInitWithCompressFilter();
            await _writer.WritePacketAsync(PacketType.KexInit, clientKexInit, cancellationToken)
                .ConfigureAwait(false);

            RawPacket serverKexInitPkt = await _queue.WaitForTypeAsync(PacketType.KexInit, cancellationToken)
                .ConfigureAwait(false);
            byte[] serverKexInit = serverKexInitPkt.Payload;

            KexInit clientInit = KeyExchange.ParseKexInit(clientKexInit);
            KexInit serverInit = KeyExchange.ParseKexInit(serverKexInit);
            _negotiated = KeyExchange.Negotiate(clientInit, serverInit);

            // The user's key callback is not re-invoked on rekey (the host key
            // is already trusted from the initial handshake), but libssh2 DOES
            // re-verify the hostkey signature over the NEW exchange hash on
            // every exchange including rekey (kex.c:746-751). Previously this
            // passed null, so rekey signatures were never checked.
            KeyExchange.KexExchangeResult kex = await KeyExchange.RunExchangeAsync(
                _writer, _queue, _negotiated,
                DefaultClientBanner, _serverBanner ?? string.Empty,
                clientKexInit, serverKexInit,
                verifyAsync: (hostKey, h, sig, ct) =>
                    Task.FromResult(HostKeyVerifier.Verify(hostKey, h, sig, _negotiated.HostKey)),
                existingSessionId: _sessionId,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            // Refresh the host-key state from the NEW K_S (parity kex.c:4051-4075:
            // a rekey re-copies K_S and recomputes the SHA1/SHA256 fingerprints,
            // so libssh2_hostkey_hash reflects the new key). Previously the
            // result was discarded and HostKey / HostKeyHash stayed stale —
            // a server that rotates its key mid-session would keep reporting
            // the OLD fingerprint.
            _hostKey = kex.HostKey;

            // session_id is immutable across rekeys — do not overwrite.
        }
        finally
        {
            Interlocked.Exchange(ref _rekeyInProgress, 0);
            RekeyCount++;

            // ── Restart the rekey time window ─────────────
            // After a successful rekey (or a failed one — the failed attempt
            // itself doesn't consume a meaningful time budget, and the caller
            // is about to dispose the session anyway), restart the 1hr clock
            // from now. Counter reset happens inside PacketReader/Writer
            // SetInboundKeys/SetOutboundKeys (called by RunExchangeAsync).
            _handshakeTimestampTicks = _timeProvider.GetTimestamp();
        }
    }

    // ── Channels ────────────────────────────────────────────────────────────

    /// <summary>
    /// Opens a new <c>"session"</c>-type channel on this authenticated session.
    /// Mirrors <c>libssh2_channel_open_session</c>
    /// (<c>libssh2.h:844-848</c> → <c>_libssh2_channel_open("session", ...)</c>).
    /// The caller owns the returned channel and must <see cref="IAsyncDisposable.DisposeAsync"/>
    /// it.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if called before
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> completes.</exception>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelFailure"/> if the server rejects the open
    /// (parity <c>channel.c:285-310</c>).</exception>
    public Task<SshChannel> OpenSessionAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (_writer is null || _channelRouter is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before opening a channel.");
        }

        return SshChannel.OpenAsync(_writer, _channelRouter, cancellationToken);
    }

    /// <summary>
    /// Opens a <c>"direct-tcpip"</c> channel — a client-side TCP tunnel
    /// through the SSH server to <c>(host, port)</c>. Mirrors
    /// <c>libssh2_channel_direct_tcpip_ex</c> (<c>channel.c:381-435</c>).
    /// </summary>
    /// <param name="host">The host the server should connect to.</param>
    /// <param name="port">The port the server should connect to.</param>
    /// <param name="originatorAddress">Optional originator address (defaults
    /// to <c>"127.0.0.1"</c>). The server logs this for audit; it does not
    /// affect routing.</param>
    /// <param name="originatorPort">Optional originator port (defaults to
    /// <c>22</c> — the C convenience macro
    /// <c>libssh2_channel_direct_tcpip</c> passes
    /// <c>"127.0.0.1", 22</c>, libssh2.h:852-853).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task<SshChannel> OpenDirectTcpIpAsync(
        string host, int port,
        string originatorAddress = "127.0.0.1", int originatorPort = 22,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (_writer is null || _channelRouter is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before opening a channel.");
        }

        return SshChannel.OpenDirectTcpIpAsync(
            _writer, _channelRouter, host, port, originatorAddress, originatorPort,
            cancellationToken);
    }

    /// <summary>
    /// Opens a <c>"direct-streamlocal@openssh.com"</c> channel — a
    /// client-side UNIX-socket tunnel through the SSH server (OpenSSH
    /// extension). Mirrors <c>libssh2_channel_direct_streamlocal_ex</c>
    /// (<c>channel.c:462-513</c>).
    /// </summary>
    /// <param name="socketPath">The UNIX socket path the server should
    /// connect to.</param>
    /// <param name="originatorAddress">Optional originator address (defaults
    /// to <c>"127.0.0.1"</c>).</param>
    /// <param name="originatorPort">Optional originator port (defaults to
    /// <c>0</c>).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task<SshChannel> OpenDirectStreamLocalAsync(
        string socketPath,
        string originatorAddress = "127.0.0.1", int originatorPort = 0,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (_writer is null || _channelRouter is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before opening a channel.");
        }

        return SshChannel.OpenDirectStreamLocalAsync(
            _writer, _channelRouter, socketPath, originatorAddress, originatorPort,
            cancellationToken);
    }

    // ── Forward listener ───────────────────────────────────

    /// <summary>
    /// Asks the server to bind a TCP port and forward inbound connections as
    /// <c>SSH_MSG_CHANNEL_OPEN "forwarded-tcpip"</c> messages. Mirrors
    /// <c>libssh2_channel_forward_listen_ex</c> (<c>channel.c:541-688</c>).
    /// Returns a <see cref="SshListener"/> whose <see cref="SshListener.AcceptAsync"/>
    /// yields each forwarded channel as it arrives.
    /// </summary>
    /// <param name="host">The address the server should bind to. Pass
    /// <see langword="null"/> for the libssh2 default <c>"0.0.0.0"</c>
    /// (<c>channel.c:550-551</c>).</param>
    /// <param name="port">The port the server should bind. Pass <c>0</c> to
    /// let the server choose; the assigned port is exposed via
    /// <see cref="SshListener.BoundPort"/> (parsed from the
    /// <c>REQUEST_SUCCESS</c> body — <c>channel.c:650-656</c>).</param>
    /// <param name="queueMaxSize">Maximum number of un-accept()ed channels
    /// before the router refuses inbound opens with
    /// <c>SSH_OPEN_RESOURCE_SHORTAGE</c>. Default 16 — the C convenience
    /// macro <c>libssh2_channel_forward_listen</c> passes 16
    /// (libssh2.h:864-865). <c>0</c> means
    /// unlimited (packet.c:147-148).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The new listener, registered with this session.</returns>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.RequestDenied"/> if the server refuses
    /// (REQUEST_FAILURE).</exception>
    public async Task<SshListener> ListenForwardAsync(
        string? host, int port, int queueMaxSize = 16,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (_channelRouter is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before listening for forwards.");
        }

        // channel.c:550-551 — default host when null.
        host ??= "0.0.0.0";

        // channel.c:577-582 — tcpip-forward request body. UTF-8 encode (the C
        // sends raw bytes; ASCII would replace non-ASCII bytes with '?' —
        // consistent with the direct-tcpip path).
        byte[] hostBytes = Encoding.UTF8.GetBytes(host);
        byte[] extra = new byte[4 + hostBytes.Length + 4];
        int o = 0;
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), hostBytes.Length);
        o += 4;
        Buffer.BlockCopy(hostBytes, 0, extra, o, hostBytes.Length);
        o += hostBytes.Length;
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), port);

        // want_reply=1 — the reply carries the server-assigned port (when
        // caller passed 0) or an empty body.
        RawPacket reply = await SendGlobalRequestAsync(
            name: "tcpip-forward",
            extra: extra,
            wantReply: true,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        // channel.c:650-656 — if the caller passed port=0 and the reply body
        // has a u32, use that as the bound port.
        int boundPort = port;
        if (port == 0 && reply.Payload.Length >= 1 + 4)
        {
            boundPort = (int)BinaryPrimitives.ReadUInt32BigEndian(reply.Payload.AsSpan(1, 4));
        }

        var listener = new SshListener(this, host, boundPort, queueMaxSize);
        _listeners[(host, boundPort)] = listener;
        return listener;
    }

    /// <summary>
    /// Removes a listener from the session's registry. Called by
    /// <see cref="SshListener.DisposeAsync"/> after it has sent
    /// <c>cancel-tcpip-forward</c> and drained its accept queue. Internal
    /// — listeners are unregistered only by their own Dispose path.
    /// </summary>
    internal void UnregisterListener(SshListener listener)
        => _listeners.TryRemove((listener.Host, listener.BoundPort), out _);

    /// <summary>
    /// Looks up a listener by (host, port). Internal — used by the
    /// <see cref="ChannelRouter"/>'s inbound <c>SSH_MSG_CHANNEL_OPEN
    /// "forwarded-tcpip"</c> dispatch (parity packet.c:137-141).
    /// Returns <see langword="null"/> if no listener matches — the router
    /// then sends <c>CHANNEL_OPEN_FAILURE</c> with
    /// <c>SSH_OPEN_ADMINISTRATIVELY_PROHIBITED</c>.
    /// </summary>
    internal SshListener? TryGetListener(string host, int port)
        => _listeners.TryGetValue((host, port), out SshListener? listener) ? listener : null;

    // ── KeepAlive ───────────────────────────────────────────

    /// <summary>
    /// Configures caller-driven keepalive behavior. Mirrors
    /// <c>libssh2_keepalive_config</c> (<c>keepalive.c:45-55</c>). After this
    /// call, the application is responsible for invoking
    /// <see cref="SendKeepAliveAsync"/> on its own timer at the configured
    /// interval. The library never creates background threads or timers.
    /// </summary>
    /// <param name="wantReply">If <see langword="true"/>, keepalive packets
    /// carry <c>want_reply=1</c>, but <see cref="SendKeepAliveAsync"/>
    /// does not await the reply.</param>
    /// <param name="intervalSeconds">The interval between keepalive sends, in
    /// seconds. Pass <c>0</c> to disable keepalive (the send method becomes a
    /// no-op that returns <c>0</c>). <b>Parity quirk</b> (<c>keepalive.c:50-51</c>):
    /// an interval of <c>1</c> is silently rewritten to <c>2</c> (libssh2
    /// workaround for buggy servers that mis-handle sub-second keepalives).</param>
    public void ConfigureKeepAlive(bool wantReply, int intervalSeconds)
    {
        // keepalive.c:50-51 — exact verbatim quirk port.
        _keepaliveIntervalSeconds = intervalSeconds == 1 ? 2 : intervalSeconds;
        _keepaliveWantReply = wantReply;
    }

    /// <summary>
    /// Sends a keepalive message if the configured interval has elapsed since
    /// the last send, and returns the number of seconds until the next keepalive
    /// is due. Mirrors <c>libssh2_keepalive_send</c> (<c>keepalive.c:57-101</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Return value semantics</b> (verbatim from <c>keepalive.c:60-100</c>):
    /// <list type="bullet">
    /// <item>If keepalive is disabled (interval == 0): returns <c>0</c>
    /// immediately without sending.</item>
    /// <item>If enough time has elapsed (<c>last_sent + interval &lt;= now</c>):
    /// sends the keepalive packet, updates <c>last_sent = now</c>, and returns
    /// the full <c>interval</c> (the caller schedules the next call that far
    /// out).</item>
    /// <item>If not enough time has elapsed: does NOT send, and returns
    /// <c>last_sent - now + interval</c> (the remaining seconds until the next
    /// send is due — the caller uses this hint to schedule the next call).</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>Fire-and-forget in both want_reply modes.</b> When
    /// <see cref="ConfigureKeepAlive"/> was called with <c>wantReply=true</c>,
    /// the packet is sent with <c>want_reply=1</c> but the reply is NOT
    /// awaited — parity with <c>keepalive.c:82-93</c>, where libssh2 never
    /// reads the reply. A late <c>SSH_MSG_REQUEST_SUCCESS/FAILURE</c> (81/82)
    /// is dropped by the router when no global-request waiter is registered.
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The number of seconds until the next keepalive send is due
    /// (see remarks for the three cases).</returns>
    /// <exception cref="InvalidOperationException">Thrown if called before
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> completes.</exception>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.SocketSend"/> if the underlying transport send
    /// fails. (libssh2 silently ignores EAGAIN; in C# the await blocks instead
    /// and a real transport error propagates.)</exception>
    public ValueTask<int> SendKeepAliveAsync(CancellationToken cancellationToken = default)
    {
        // keepalive.c:63-67 — disabled fast-path.
        if (_keepaliveIntervalSeconds == 0)
        {
            return ValueTask.FromResult(0);
        }

        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (_writer is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before sending keepalive.");
        }

        long nowTicks = _timeProvider.GetTimestamp();
        // keepalive.c:71 — last_sent + interval <= now ? The C's
        // keepalive_last_sent starts at 0 (calloc), so the first call always
        // fires. Mirror that with the never-sent sentinel.
        long elapsedSeconds = _keepaliveEverSent
            ? (long)_timeProvider.GetElapsedTime(_lastKeepaliveTimestampTicks, nowTicks).TotalSeconds
            : long.MaxValue;

        // keepalive.c:71 — last_sent + interval <= now ? Not elapsed is the
        // majority case — return the remaining time synchronously.
        if (_keepaliveIntervalSeconds > elapsedSeconds)
        {
            // keepalive.c:95-98 — not enough time elapsed; return remaining.
            return ValueTask.FromResult(_keepaliveIntervalSeconds - (int)elapsedSeconds);
        }

        return new ValueTask<int>(SendKeepAliveSlowAsync(nowTicks, cancellationToken));
    }

    /// <summary>Slow path of <see cref="SendKeepAliveAsync"/>: sends the GLOBAL_REQUEST packet (network IO).</summary>
    private async Task<int> SendKeepAliveSlowAsync(long nowTicks, CancellationToken cancellationToken)
    {
        // Build + send the GLOBAL_REQUEST packet (keepalive.c:74-89).
        // Fire-and-forget in BOTH want_reply modes — parity with
        // keepalive.c:82-93, where libssh2 sends the keepalive with the
        // configured want_reply flag but NEVER reads the reply (a late
        // 81/82 is dropped by the router when no waiter is registered).
        // Previously wantReply=true routed through
        // ChannelRouter.SendGlobalRequestAsync, which awaits the reply
        // under the single-slot global-request semaphore: a server that
        // ignores the request left SendKeepAliveAsync blocked indefinitely
        // and blocked concurrent tcpip-forward/cancel requests.
        byte[] payload = KeepAlive.BuildPayload(wantReply: _keepaliveWantReply);
        await _writer!.WritePacketAsync(PacketType.GlobalRequest, payload, cancellationToken)
            .ConfigureAwait(false);

        // keepalive.c:91 — update last_sent AFTER a successful send.
        _lastKeepaliveTimestampTicks = nowTicks;
        _keepaliveEverSent = true;

        // keepalive.c:92-93 — return the full interval.
        return _keepaliveIntervalSeconds;
    }

    /// <summary>
    /// Sends an <c>SSH_MSG_GLOBAL_REQUEST</c> (RFC 4254 §4) and, when
    /// <paramref name="wantReply"/> is <see langword="true"/>, awaits the
    /// peer's <c>REQUEST_SUCCESS</c> (81) or <c>REQUEST_FAILURE</c> (82).
    /// Internal — used by listener setup (<c>tcpip-forward</c>) and
    /// teardown (<c>cancel-tcpip-forward</c>). Delegates to the channel router,
    /// which owns the single-slot reply machinery.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if called before
    /// <see cref="HandshakeAsync(IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> completes.</exception>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.RequestDenied"/> when the server returns
    /// <c>REQUEST_FAILURE</c> and <paramref name="wantReply"/> was true.</exception>
    internal Task<RawPacket> SendGlobalRequestAsync(
        string name, ReadOnlyMemory<byte> extra, bool wantReply, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (_channelRouter is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before sending a global request.");
        }

        return _channelRouter.SendGlobalRequestAsync(name, extra, wantReply, cancellationToken);
    }

    // ── Disconnect ───────────────────────────────────────────────────────────

    /// <summary>
    /// Sends an <c>SSH_MSG_DISCONNECT</c> message (RFC 4253 §11.1) and returns.
    /// Fire-and-forget: the server does not acknowledge. Description and
    /// language over 256 UTF-8 BYTES throw <see cref="SshErrorCode.Inval"/>
    /// (session.c:1207-1212 — the C rejects, it does not truncate). Mirrors
    /// <c>libssh2_session_disconnect_ex</c>.
    /// </summary>
    public async Task DisconnectAsync(
        SshDisconnectReason reason,
        string description,
        string lang = "",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(description);
        ArgumentNullException.ThrowIfNull(lang);
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        await DisconnectCoreAsync(reason, description, lang, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The unguarded disconnect-send core shared by <see cref="DisconnectAsync"/>
    /// (public, guard-checked) and <see cref="DisposeAsync"/> (teardown path —
    /// must still send the DISCONNECT after <c>_disposed</c> is set).
    /// </summary>
    private async Task DisconnectCoreAsync(
        SshDisconnectReason reason,
        string description,
        string lang,
        CancellationToken cancellationToken)
    {
        if (_writer is null)
        {
            return;   // nothing to disconnect — handshake not started
        }

        // The C rejects a description/language longer than 256 BYTES
        // with LIBSSH2_ERROR_INVAL (session.c:1207-1212); the pre-fix port
        // truncated at 256 CHARACTERS, so a multi-byte description shipped an
        // over-long field on the wire.
        byte[] desc = Encoding.UTF8.GetBytes(description);
        if (desc.Length > 256)
        {
            throw new SshException(SshErrorCode.Inval, "too long description");
        }

        byte[] langBytes = Encoding.UTF8.GetBytes(lang);
        if (langBytes.Length > 256)
        {
            throw new SshException(SshErrorCode.Inval, "too long language string");
        }

        // Packet: [1 (type)] [4 (reason)] [4 + desc] [4 + lang]
        int payloadLen = 1 + 4 + 4 + desc.Length + 4 + langBytes.Length;
        byte[] payload = new byte[payloadLen];
        int offset = 0;
        payload[offset++] = (byte)PacketType.Disconnect;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(offset, 4), (int)reason);
        offset += 4;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(offset, 4), desc.Length);
        offset += 4;
        desc.CopyTo(payload, offset);
        offset += desc.Length;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(offset, 4), langBytes.Length);
        offset += 4;
        langBytes.CopyTo(payload, offset);

        try
        {
            await _writer.WritePacketAsync(PacketType.Disconnect, payload, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SshException)
        {
            // Teardown is best-effort; a half-closed transport is not an error here.
        }
    }

    // ── Dispose ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Sends a best-effort <c>SSH_MSG_DISCONNECT</c> and disposes the packet
    /// reader/writer. Does NOT dispose the caller-owned <see cref="IDuplexPipe"/>
    /// or underlying socket. Safe to call multiple times.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        // Atomic exchange — two concurrent disposers cannot both run the
        // full teardown (a duplicated DISCONNECT send, double writer/queue
        // disposal). "Safe to call multiple times" now holds under concurrency.
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        // Tear down any live listeners BEFORE the writer goes away
        // (so each listener's cancel-tcpip-forward send has a chance). Swallow
        // errors — teardown is best-effort.
        if (_listeners is not null && !_listeners.IsEmpty)
        {
            foreach (SshListener listener in _listeners.Values)
            {
                try
                {
                    await listener.DisposeAsync().ConfigureAwait(false);
                }
                catch (SshException) { }
            }
        }

        if (_handshakeCompleted && _writer is not null)
        {
            try
            {
                // NB: _disposed is already true here, so this must go through
                // the unguarded core — the public DisconnectAsync would throw
                // ObjectDisposedException instantly and the DISCONNECT would
                // never be sent.
                await DisconnectCoreAsync(SshDisconnectReason.ByApplication, "session closed",
                    lang: "", cancellationToken: CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // Best-effort; ignore errors during teardown.
            }
        }

        if (_writer is not null)
        {
            await _writer.DisposeAsync().ConfigureAwait(false);
        }

        if (_queue is not null)
        {
            await _queue.Reader.DisposeAsync().ConfigureAwait(false);
        }

        // Dispose the cooperative-pumper lock owned by the router.
        _channelRouter?.Dispose();
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Builds the KEXINIT payload, filtering compression to <c>none</c> when
    /// the <see cref="SshFlag.Compress"/> flag is not set (parity with
    /// <c>session.c:1428-1429</c> / <c>comp.c:374-381</c>).
    /// </summary>
    private byte[] BuildKexInitWithCompressFilter()
    {
        // The Compress flag gates the DEFAULT compression name-list; the C
        // reads the flag live at each KEXINIT build and never rewrites user
        // prefs (comp.c:374-381). Previously this method overwrote
        // _prefs[CompCs/Sc] permanently, so preference introspection and any
        // rekey AFTER the flag was enabled kept advertising "none" forever. A user-set comp pref is still filtered
        // to "none" while the flag is off — matching the C's set-time
        // validation which strips zlib when the flag is off (kex.c:4244-4250).
        if ((_flags & SshFlag.Compress) != 0)
        {
            return KeyExchange.BuildKexInit(_prefs);
        }

        var filtered = new MethodPreferences(_prefs);
        filtered[SshMethodType.CompCs] = "none";
        filtered[SshMethodType.CompSc] = "none";
        return KeyExchange.BuildKexInit(filtered);
    }

    /// <summary>
    /// Reads the server identification line byte-by-byte until <c>\n</c>,
    /// stripping trailing CR/LF and rejecting NUL bytes. Discards pre-banner
    /// lines that do not begin with <c>"SSH-"</c> (session.c:781). Throws
    /// <see cref="SshErrorCode.BannerRecv"/> on EOF, NUL, or empty result.
    /// </summary>
    private static async Task<string> ReadServerBannerAsync(PipeReader reader, CancellationToken ct)
    {
        byte[] buf = new byte[MaxBannerLen];
        int len = 0;

        while (true)
        {
            // Read one byte at a time. The PipeReader returns at least one byte
            // per ReadAsync (or completes). We examine + advance one byte.
            ReadResult result = await reader.ReadAsync(ct).ConfigureAwait(false);
            if (result.IsCompleted && result.Buffer.IsEmpty)
            {
                throw new SshException(SshErrorCode.BannerRecv, "EOF reading server banner");
            }

            if (result.IsCanceled)
            {
                throw new OperationCanceledException(ct);
            }

            // Take the first byte; leave the rest for the packet layer.
            ReadOnlySequence<byte> buffer = result.Buffer;
            if (buffer.IsEmpty)
            {
                // Should not happen (completed+empty handled above), but guard anyway.
                reader.AdvanceTo(buffer.Start);
                continue;
            }

            byte b = buffer.First.Span[0];
            reader.AdvanceTo(buffer.GetPosition(1));

            if (b == 0)
            {
                throw new SshException(SshErrorCode.BannerRecv, "NUL byte in server banner");
            }

            buf[len++] = b;

            // End of line — or the buffer filled without a newline (the
            // C's banner_receive loop exits when the buffer fills, session.c:121,
            // and proceeds with the bytes it has; the pre-fix port kept
            // consuming bytes and waited for '\n' forever). Strip trailing
            // CR/LF.
            if (b == (byte)'\n' || len == MaxBannerLen)
            {
                int end = len;
                while (end > 0 && (buf[end - 1] == '\r' || buf[end - 1] == '\n'))
                {
                    end--;
                }

                string line = Encoding.ASCII.GetString(buf, 0, end);

                // Discard non-SSH- pre-banner lines (session.c:781).
                if (!line.StartsWith("SSH-", StringComparison.Ordinal))
                {
                    len = 0;   // reset and read the next line
                    continue;
                }

                if (line.Length == 0)
                {
                    throw new SshException(SshErrorCode.BannerRecv, "empty server banner");
                }

                return line;
            }
        }
    }

    /// <summary>
    /// Sends <c>SSH_MSG_SERVICE_REQUEST "ssh-userauth"</c> (session.c:797-809).
    /// </summary>
    private static async Task SendServiceRequestAsync(PacketWriter writer, CancellationToken ct)
    {
        byte[] service = Encoding.ASCII.GetBytes(UserService);
        byte[] payload = new byte[1 + 4 + service.Length];
        payload[0] = (byte)PacketType.ServiceRequest;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(1, 4), service.Length);
        service.CopyTo(payload, 5);
        await writer.WritePacketAsync(PacketType.ServiceRequest, payload, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits for <c>SSH_MSG_SERVICE_ACCEPT "ssh-userauth"</c> and validates the
    /// service name matches (session.c:825-858).
    /// </summary>
    private static async Task WaitForServiceAcceptAsync(PacketQueue queue, CancellationToken ct)
    {
        RawPacket pkt = await queue.WaitForTypeAsync(PacketType.ServiceAccept, ct).ConfigureAwait(false);
        if (pkt.Payload.Length < 1 + 4)
        {
            throw new SshException(SshErrorCode.Proto, "truncated SERVICE_ACCEPT");
        }

        // Payload: [6 (type)] [4 (len)] [service name]
        var r = new PacketWireReader(new ReadOnlySequence<byte>(pkt.Payload));
        _ = r.ReadByte();   // type byte (6)
        string service = r.ReadString();
        if (service != UserService)
        {
            throw new SshException(SshErrorCode.Proto,
                $"SERVICE_ACCEPT service mismatch: expected '{UserService}', got '{service}'");
        }
    }
}
