using System.Buffers;

using LibSsh2CS.Util;

namespace LibSsh2CS.Transport;

/// <summary>
/// The inbound packet queue — a 1:1 managed port of libssh2's
/// <c>session-&gt;packets</c> linked list + <c>_libssh2_packet_ask</c> /
/// <c>_libssh2_packet_require</c> / <c>_libssh2_packet_requirev</c>
/// (<c>packet.c:1397-1658</c>). Wraps a single <see cref="PacketReader"/> and
/// provides type-filtered awaits: <see cref="WaitForTypeAsync"/> blocks until a
/// packet of the requested type arrives, stashing non-matching packets for later
/// waiters.
/// </summary>
/// <remarks>
/// <para>
/// <b>Concurrency model: pull-on-demand.</b> There is no background pump task.
/// <see cref="WaitForTypeAsync"/> loops <see cref="PacketReader.ReadPacketAsync"/>,
/// inspecting each packet: matching packets return to the caller; non-matching
/// packets are stashed in <see cref="_stash"/> for a later wait. This mirrors
/// libssh2's <c>_libssh2_packet_require</c> (which polls
/// <c>_libssh2_transport_read</c> in a loop, <c>packet.c:1480-1533</c>) and is
/// consistent with the LibGit2CS inline-polling convention (no
/// <c>Channel&lt;T&gt;</c>, no <c>TaskCompletionSource</c>, no background task).
/// </para>
/// <para>
/// <b>Inline handling of transport-layer messages</b> (port of
/// <c>_libssh2_packet_add</c>, <c>packet.c:678-908</c>): SSH_MSG_DISCONNECT (1)
/// throws <see cref="SshException"/>(<see cref="SshErrorCode.SocketDisconnect"/>);
/// SSH_MSG_IGNORE (2) and SSH_MSG_DEBUG (4) are silently discarded; SSH_MSG_EXT_INFO
/// (7) is stashed for userauth (it carries <c>server-sig-algs</c>); all
/// other types are stashed for typed waiters. This inline dispatch happens
/// before the strict-KEX policy check (matching <c>packet.c</c>'s order).
/// </para>
/// <para>
/// <b>Strict-KEX enforcement</b> (Terrapin mitigation, <c>packet.c:715-739</c>):
/// when <see cref="StrictKex"/> is true and <see cref="InitialKex"/> is true,
/// any packet that is not the expected type (<see cref="ExpectedType"/>) triggers
/// a <see cref="SshException"/>(<see cref="SshErrorCode.SocketDisconnect"/>)
/// with the message "strict KEX violation: unexpected packet type". The
/// <c>SshSession</c> sets <see cref="InitialKex"/>=false after the
/// initial KEX completes. <see cref="StrictKex"/> is set once from
/// <see cref="NegotiatedMethods.StrictKex"/> after KEXINIT negotiation.
/// </para>
/// <para>
/// <b>Single-consumer.</b> Only one <see cref="WaitForTypeAsync"/> call may be
/// outstanding at a time — the underlying <see cref="PacketReader"/> is a
/// single-reader <see cref="System.IO.Pipelines.PipeReader"/>. SSH protocol
/// flow is inherently sequential (request → response), so this is never a
/// bottleneck. Concurrent waiters would require a background pump, which the
/// codebase convention avoids.
/// </para>
/// </remarks>
internal sealed class PacketQueue
{
    private readonly PacketReader _reader;

    /// <summary>
    /// The underlying <see cref="PacketReader"/>. Exposed so the KEX layer
    /// (<c>KeyExchange.RunExchangeAsync</c>) can call
    /// <see cref="PacketReader.SetInboundKeys"/> at the NEWKEYS transition (the
    /// queue owns the reader, so this avoids passing it separately).
    /// </summary>
    internal PacketReader Reader => _reader;

    /// <summary>
    /// Stashed packets keyed by type, awaiting a future
    /// <see cref="WaitForTypeAsync"/>/<see cref="WaitForTypesAsync"/> call. Port
    /// of libssh2's <c>session-&gt;packets</c> linked list — a dict-of-queues
    /// gives O(1) type-filtered dequeue (vs libssh2's O(n) list scan, which is
    /// fine there because the list is short).
    /// </summary>
    private readonly Dictionary<int, Queue<RawPacket>> _stash = [];

    /// <summary>
    /// True iff strict-KEX was negotiated (server's kex name-list contained
    /// <c>kex-strict-s-v00@openssh.com</c>). Set from
    /// <see cref="NegotiatedMethods.StrictKex"/> after KEXINIT negotiation.
    /// When true, unexpected packet types during <see cref="InitialKex"/> cause
    /// a disconnect (<c>packet.c:728-739</c>).
    /// </summary>
    public bool StrictKex { get; set; }

    /// <summary>
    /// True while the initial key exchange is in progress (the first KEXINIT →
    /// NEWKEYS cycle). The <c>SshSession</c> sets this to false after
    /// NEWKEYS is received and the post-NEWKEYS keys are installed. While true
    /// and <see cref="StrictKex"/> is also true, only <see cref="ExpectedType"/>
    /// packets are accepted; all others trigger a strict-KEX violation
    /// disconnect (<c>packet.c:715-739</c>).
    /// </summary>
    public bool InitialKex { get; set; } = true;

    /// <summary>
    /// The single packet type the caller is currently waiting for (set by
    /// <see cref="WaitForTypeAsync"/> before each read loop, cleared after).
    /// Used by the strict-KEX policy check. Zero (unset) disables the
    /// unexpected-type check.
    /// </summary>
    public int ExpectedType { get; set; }

    /// <summary>
    /// Constructs a queue wrapping the given <see cref="PacketReader"/>. The
    /// queue starts in <see cref="InitialKex"/>=true (the session begins in the
    /// initial KEX state, <c>LIBSSH2_STATE_INITIAL_KEX</c>).
    /// </summary>
    public PacketQueue(PacketReader reader)
    {
        _reader = reader;
    }

    /// <summary>
    /// Parses a DEBUG payload: <c>[4][bool always_display][string message]
    /// [string language]</c> (RFC 4252 §5.3). When the packet is too short
    /// to carry the strings, empty strings are passed to the callback (the C
    /// would pass stale values — packet.c:807-818; not reproduced). A
    /// malformed string (declared length beyond the payload) is likewise
    /// surfaced as empty (the C's <c>_libssh2_get_string</c> failure).
    /// </summary>
    private static (bool AlwaysDisplay, string Message, string Language) ParseDebugMessage(byte[] payload)
    {
        if (payload.Length < 2)
        {
            return (false, string.Empty, string.Empty);
        }

        bool alwaysDisplay = payload[1] != 0;
        if (payload.Length < 6)
        {
            return (alwaysDisplay, string.Empty, string.Empty);
        }

        try
        {
            var r = new PacketWireReader(new ReadOnlySequence<byte>(payload));
            _ = r.ReadByte();   // type
            _ = r.ReadByte();   // always_display
            string message = r.ReadString();
            string language = r.ReadString();
            return (alwaysDisplay, message, language);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            return (alwaysDisplay, string.Empty, string.Empty);
        }
    }

    /// <summary>
    /// The rekey trigger callback — invoked when the queue sees a
    /// <b>post-handshake</b> <c>SSH_MSG_KEXINIT</c> from the server (a
    /// server-initiated rekey). The callback should call
    /// <see cref="SshSession.RekeyAsync"/> and return after the rekey completes.
    /// The stashed server KEXINIT is then retrievable via
    /// <see cref="TryTakeStashed"/>/<see cref="WaitForTypeAsync"/> in the rekey
    /// flow (parity with libssh2's <c>packet.c:1355-1388</c>).
    /// </summary>
    /// <remarks>
    /// Set by <see cref="SshSession.HandshakeAsync(System.IO.Pipelines.IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> after the initial KEX
    /// completes. Stays <see langword="null"/> during the initial KEX so that
    /// the initial server KEXINIT falls through to the normal stash path
    /// (which <see cref="SshSession.HandshakeAsync(System.IO.Pipelines.IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>'s
    /// <see cref="WaitForTypeAsync"/>/<see cref="PacketType.KexInit"/> retrieves
    /// directly).
    /// </remarks>
    public Func<CancellationToken, Task>? RekeyTriggerAsync { get; set; }

    /// <summary>
    /// The packet-read deadline for <see cref="WaitForTypeAsync"/> /
    /// <see cref="WaitForTypesAsync"/> — parity with libssh2's
    /// <c>packet_read_timeout</c> (default 60 s; session.c:474, packet.c:1510-1526,
    /// 1633-1642: <c>LIBSSH2_ERROR_TIMEOUT</c> when the expected packet has not
    /// arrived within the deadline). Wired from
    /// <see cref="SshSession.ReadTimeout"/> (which enforces the C's
    /// "&lt;= 0 → default" semantics, so this is only ever zero for
    /// direct-queue tests). The deadline covers the whole wait — including
    /// inline-dispatched IGNORE/DEBUG/EXT_INFO and the inline rekey — exactly
    /// like the C's wall-clock <c>left</c> computation.
    /// </summary>
    public TimeSpan ReadTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The clock used for the read deadline. Wired from the owning session's
    /// <see cref="TimeProvider"/> so tests using
    /// <c>FakeTimeProvider</c> get deterministic timeouts.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// Creates the read-deadline scope for a wait (or returns
    /// <see langword="null"/> when <see cref="ReadTimeout"/> is disabled).
    /// The deadline is driven by <see cref="TimeProvider"/> so tests using
    /// <c>FakeTimeProvider</c> get deterministic timeouts.
    /// </summary>
    private ReadTimeoutScope? CreateReadTimeoutScope(CancellationToken cancellationToken)
    {
        return ReadTimeout <= TimeSpan.Zero
            ? null
            : new ReadTimeoutScope(ReadTimeout, TimeProvider, cancellationToken);
    }

    /// <summary>
    /// A linked CTS whose token cancels when <see cref="ReadTimeout"/>
    /// elapses (or when the caller cancels). Disposing the scope disposes
    /// both the timer and the CTS.
    /// </summary>
    private sealed class ReadTimeoutScope : IDisposable
    {
        private readonly CancellationTokenSource _cts;
        private readonly ITimer? _timer;

        public ReadTimeoutScope(TimeSpan timeout, TimeProvider timeProvider, CancellationToken cancellationToken)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _timer = timeProvider.CreateTimer(
                static s => CancelSafely((CancellationTokenSource)s!),
                _cts, timeout, Timeout.InfiniteTimeSpan);
        }

        public CancellationToken Token => _cts.Token;

        public void Dispose()
        {
            _timer?.Dispose();
            _cts.Dispose();
        }

        /// <summary>
        /// Cancels the scope's CTS, swallowing the
        /// <see cref="ObjectDisposedException"/> a deadline callback already
        /// dispatched to the threadpool hits when the wait completed and
        /// disposed the scope concurrently (<c>ITimer.Dispose</c> prevents
        /// future fires but not in-flight callbacks; without the guard the
        /// exception escapes on a threadpool thread). The C reference
        /// polls single-threaded with no timer and cannot hit this race; the
        /// guard keeps the managed-only lifecycle hazard benign.
        /// </summary>
        private static void CancelSafely(CancellationTokenSource cts)
        {
            try
            {
                cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The wait already completed; the deadline is moot.
            }
        }
    }

    /// <summary>
    /// Optional callback invoked for every <c>SSH_MSG_IGNORE</c> packet with
    /// the raw payload bytes after the type byte (the C passes
    /// <c>data + 1, datalen - 1</c> — the string field INCLUDING its length
    /// prefix; an empty span when the packet is shorter than 2 bytes).
    /// Parity with <c>libssh2_session_callback_set(LIBSSH2_CALLBACK_IGNORE)</c>
    /// (packet.c:787-796). Wired from <see cref="SshSession.IgnoreCallback"/>.
    /// </summary>
    public Action<ReadOnlyMemory<byte>>? IgnoreCallback { get; set; }

    /// <summary>
    /// Optional callback invoked for every <c>SSH_MSG_DEBUG</c> packet with
    /// <c>(alwaysDisplay, message, language)</c> (the message/language are
    /// parsed per RFC 4252 §5.3; empty strings when the packet is too short
    /// to carry them — the C leaves them stale in that case, which is not
    /// worth reproducing). Parity with
    /// <c>libssh2_session_callback_set(LIBSSH2_CALLBACK_DEBUG)</c>
    /// (packet.c:801-821). Wired from <see cref="SshSession.DebugCallback"/>.
    /// </summary>
    public Action<bool, string, string>? DebugCallback { get; set; }

    /// <summary>
    /// Waits for a packet of the given type, stashing any non-matching packets
    /// for later. Port of <c>_libssh2_packet_require</c> (<c>packet.c:1480</c>).
    /// Returns the matching packet's payload (beginning with the type byte).
    /// </summary>
    /// <param name="type">The <c>SSH_MSG_*</c> type to wait for.</param>
    /// <param name="cancellationToken">Cooperative cancellation; the await
    /// unwinds and the underlying <c>PipeReader.ReadAsync</c> is cancelled.</param>
    public async Task<RawPacket> WaitForTypeAsync(int type, CancellationToken cancellationToken = default)
    {
        // Fast path: a previously-stashed packet of this type is available.
        if (TryTakeStashed(type, out RawPacket stashed))
        {
            return stashed;
        }

        ExpectedType = type;

        // The C's require deadline (packet.c:1510-1526) covers the whole
        // wait, including inline-dispatched packets.
        using ReadTimeoutScope? timeout = CreateReadTimeoutScope(cancellationToken);
        CancellationToken waitToken = timeout?.Token ?? cancellationToken;
        try
        {
            while (true)
            {
                RawPacket pkt = await _reader.ReadPacketAsync(waitToken).ConfigureAwait(false);
                if (pkt.Type == type)
                {
                    return pkt;
                }

                // Strict-KEX policy: during INITIAL_KEX, only the expected type
                // is allowed (packet.c:728-739). The C checks this BEFORE the
                // per-type exception switch in _libssh2_packet_add, so under
                // strict KEX even IGNORE/DEBUG/EXT_INFO/DISCONNECT are
                // violations — the pre-fix port inline-handled them first,
                // silently swallowing the Terrapin signal. Inline
                // dispatch runs only when the strict rule does not apply.
                if (StrictKex && InitialKex)
                {
                    throw new SshException(SshErrorCode.SocketDisconnect,
                        "strict KEX violation: unexpected packet type");
                }

                // Inline dispatch for transport-layer messages (packet.c:678-908).
                // This runs after the strict-KEX check because DISCONNECT/IGNORE/
                // DEBUG/EXT_INFO and server-initiated KEXINIT are subject to the
                // "unexpected type" rule during strict initial KEX (C parity).
                if (await TryHandleInlineAsync(pkt, cancellationToken).ConfigureAwait(false))
                {
                    continue;
                }

                // Non-matching, non-inline packet: stash for a later waiter.
                AddStash(pkt);
            }
        }
        catch (OperationCanceledException) when (timeout is not null && !cancellationToken.IsCancellationRequested)
        {
            // Parity packet.c:1520-1526 — LIBSSH2_ERROR_TIMEOUT when the
            // expected packet hasn't arrived within packet_read_timeout.
            throw new SshException(SshErrorCode.Timeout,
                $"Timeout waiting for SSH packet ({ReadTimeout.TotalSeconds:0}s)");
        }
        finally
        {
            ExpectedType = 0;
        }
    }

    /// <summary>
    /// Waits for a packet of any of the given types, stashing non-matching
    /// packets for later. Port of <c>_libssh2_packet_requirev</c>
    /// (<c>packet.c:1607</c>). Returns the first matching packet.
    /// </summary>
    /// <param name="types">The <c>SSH_MSG_*</c> types to wait for (any match).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public async Task<RawPacket> WaitForTypesAsync(int[] types, CancellationToken cancellationToken = default)
    {
        // Fast path: check the stash for any of the requested types.
        foreach (int t in types)
        {
            if (TryTakeStashed(t, out RawPacket stashed))
            {
                return stashed;
            }
        }

        // For strict-KEX, the "expected" set is the whole array. We can't
        // express a multi-type ExpectedType without refactoring the policy
        // check; instead, disable the unexpected-type check during requirev
        // (the caller is explicitly waiting for several types, so any of them
        // is "expected"). The INITIAL_KEX + strict-KEX combination with
        // requirev is not used by the KEX flow (KEXINIT/NEWKEYS use single-type
        // waits), so this is safe.
        bool savedStrict = StrictKex;
        if (StrictKex && InitialKex)
        {
            StrictKex = false;
        }

        // The C's requirev deadline (packet.c:1633-1642) covers the whole
        // wait, including inline-dispatched packets.
        using ReadTimeoutScope? timeout = CreateReadTimeoutScope(cancellationToken);
        CancellationToken waitToken = timeout?.Token ?? cancellationToken;
        try
        {
            while (true)
            {
                RawPacket pkt = await _reader.ReadPacketAsync(waitToken).ConfigureAwait(false);
                if (Array.IndexOf(types, pkt.Type) >= 0)
                {
                    return pkt;
                }

                if (await TryHandleInlineAsync(pkt, cancellationToken).ConfigureAwait(false))
                {
                    continue;
                }

                AddStash(pkt);
            }
        }
        catch (OperationCanceledException) when (timeout is not null && !cancellationToken.IsCancellationRequested)
        {
            // Parity packet.c:1639-1642 — LIBSSH2_ERROR_TIMEOUT when the
            // expected packet hasn't arrived within packet_read_timeout.
            throw new SshException(SshErrorCode.Timeout,
                $"Timeout waiting for SSH packet ({ReadTimeout.TotalSeconds:0}s)");
        }
        finally
        {
            StrictKex = savedStrict;
        }
    }

    /// <summary>
    /// Tries to take a stashed packet of the given type without blocking.
    /// Returns <see langword="false"/> if none is stashed. Port of the
    /// <c>_libssh2_packet_ask</c> non-blocking peek (<c>packet.c:1397</c>) —
    /// exposed (not just used internally) so <c>SshSession.HandshakeAsync</c>
    /// can retrieve the stashed <c>SSH_MSG_EXT_INFO</c> (type 7, stashed by
    /// <see cref="TryHandleInlineAsync"/>) post-KEX to parse
    /// <c>server-sig-algs</c> for RSA-SHA2 selection.
    /// </summary>
    public bool TryTakeStashed(int type, out RawPacket packet)
    {
        if (_stash.TryGetValue(type, out Queue<RawPacket>? q) && q.Count > 0)
        {
            packet = q.Dequeue();
            if (q.Count == 0)
            {
                _stash.Remove(type);
            }

            return true;
        }

        packet = default;
        return false;
    }

    /// <summary>
    /// Tries to read one packet from the pipe NON-BLOCKING.
    /// Returns <see cref="ValueTask{RawPacket}"/> with a non-default
    /// <see cref="RawPacket"/> if a full one is immediately available; returns
    /// <see cref="ValueTask{RawPacket}"/> with <c>default(RawPacket)</c> if no
    /// full packet is buffered without blocking. The cooperative pumper uses
    /// this to drain immediately-available packets after its first blocking
    /// read, so multiple packets arriving in one batch all get routed in a
    /// single pump cycle (preventing non-pumping waiters from starving).
    /// </summary>
    /// <remarks>
    /// Does inline dispatch (DISCONNECT/IGNORE/DEBUG/EXT_INFO/server-KEXINIT)
    /// exactly like <see cref="WaitForTypesAsync"/> — packets consumed inline
    /// return <see langword="false"/> here so the caller re-attempts. Inline
    /// handling is synchronous for DISCONNECT/IGNORE/DEBUG (which never block)
    /// but the server-KEXINIT branch (<see cref="RekeyTriggerAsync"/>) MAY
    /// await — so this method is async.
    /// </remarks>
    /// <param name="cancellationToken">Inherited from the calling pumper.</param>
    /// <returns>A <see cref="RawPacket"/> whose <see cref="RawPacket.Payload"/>
    /// is non-null if a packet was read; otherwise <c>default</c>.</returns>
    public async ValueTask<RawPacket> TryTakeAvailableAsync(CancellationToken cancellationToken)
    {
        // Loop instead of recurse. A flood of inline-handled
        // packets (SSH_MSG_IGNORE / SSH_MSG_DEBUG — both legal to coalesce;
        // an attacker could send thousands) would otherwise grow the stack
        // unboundedly via the prior recursive call.
        while (true)
        {
            if (!_reader.TryReadPacket(out RawPacket pkt, out bool isCompleted))
            {
                // No full packet immediately available. Either the pipe is empty
                // (more data might arrive) or the pipe is completed (EOF, no more
                // data ever). In both cases the drain caller should stop — return
                // default. The next BLOCKING read (ReadPacketAsync) handles the
                // disconnect-throw when appropriate.
                _ = isCompleted;
                return default;
            }

            // Apply the same inline dispatch as WaitForTypesAsync. If the packet
            // is consumed inline (DISCONNECT/IGNORE/DEBUG/EXT_INFO/server-KEXINIT),
            // loop and try the next.
            if (await TryHandleInlineAsync(pkt, cancellationToken).ConfigureAwait(false))
            {
                // Inline-handled — loop to drain more if available.
                continue;
            }

            return pkt;
        }
    }

    /// <summary>
    /// Stashes a packet for a future typed waiter. Port of
    /// <c>_libssh2_packet_add</c>'s queue-insert path (<c>packet.c:910+</c>).
    /// </summary>
    private void AddStash(RawPacket packet)
    {
        if (!_stash.TryGetValue(packet.Type, out Queue<RawPacket>? q))
        {
            q = new Queue<RawPacket>();
            _stash[packet.Type] = q;
        }

        q.Enqueue(packet);
    }

    /// <summary>
    /// Inline-dispatches a transport-layer message that is not subject to the
    /// type-filtered wait. Port of <c>_libssh2_packet_add</c>'s per-type
    /// switch (<c>packet.c:678-908</c>). Returns <see langword="true"/> if the
    /// packet was consumed (caller should continue the read loop);
    /// <see langword="false"/> if it should be stashed or strict-KEX-checked.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><see cref="PacketType.Disconnect"/> (1): throws
    /// <see cref="SshException"/>(<see cref="SshErrorCode.SocketDisconnect"/>)
    /// with the server's description if present. Port of <c>packet.c:694-713</c>.</item>
    /// <item><see cref="PacketType.Ignore"/> (2): silently discarded
    /// (<c>packet.c:760-766</c>).</item>
    /// <item><see cref="PacketType.Debug"/> (4): silently discarded
    /// (<c>packet.c:768-775</c>). libssh2 invokes a trace callback; we have no
    /// trace plumbing, so the packet is dropped.</item>
    /// <item><see cref="PacketType.ExtInfo"/> (7): stashed separately for
    /// userauth (it carries <c>server-sig-algs</c>, used for RSA-SHA2 algorithm
    /// selection). libssh2 parses it inline (<c>packet.c:848-908</c>); we defer
    /// parsing until after the key exchange and stash the raw packet here
    /// so the KEX flow doesn't choke on it.</item>
    /// <item><see cref="PacketType.KexInit"/> (20) <b>post-InitialKex</b>:
    /// server-initiated rekey (parity with
    /// <c>packet.c:1355-1388</c>). The server KEXINIT is stashed (so the
    /// rekey flow's <see cref="WaitForTypeAsync"/>/<see cref="PacketType.KexInit"/>
    /// retrieves it via the fast path), then <see cref="RekeyTriggerAsync"/> is
    /// invoked. The initial-KEX server KEXINIT (when <see cref="InitialKex"/>
    /// is still true) falls through to the stash path so
    /// <see cref="SshSession.HandshakeAsync(System.IO.Pipelines.IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>'s
    /// <see cref="WaitForTypeAsync"/>/<see cref="PacketType.KexInit"/> retrieves
    /// it directly — matching libssh2's behavior at <c>packet.c:1355-1358</c>
    /// where the rekey branch only fires when
    /// <c>!(session->state &amp; LIBSSH2_STATE_EXCHANGING_KEYS)</c>.</item>
    /// </list>
    /// </remarks>
    private async ValueTask<bool> TryHandleInlineAsync(RawPacket packet, CancellationToken cancellationToken)
    {
        switch (packet.Type)
        {
            case PacketType.Disconnect:
                // SSH_MSG_DISCONNECT: parse the reason + description and throw.
                // packet.c:694-713. The payload is: u32 reason | string desc |
                // string lang. We surface the description in the exception message.
                throw new SshException(SshErrorCode.SocketDisconnect,
                    ParseDisconnectDescription(packet.Payload));

            case PacketType.Ignore:
                // SSH_MSG_IGNORE: silently discard; an optional callback
                // observes the data (parity packet.c:787-796 — the payload
                // after the type byte, or empty when the packet is too
                // short).
                if (IgnoreCallback is { } onIgnore)
                {
                    onIgnore(packet.Payload.Length > 1
                        ? packet.Payload.AsMemory(1)
                        : ReadOnlyMemory<byte>.Empty);
                }

                return true;

            case PacketType.Debug:
                // SSH_MSG_DEBUG: libssh2 invokes the debug callback when one
                // is registered; the packet is discarded either way
                // (parity packet.c:801-821).
                if (DebugCallback is { } onDebug)
                {
                    (bool alwaysDisplay, string message, string language) = ParseDebugMessage(packet.Payload);
                    onDebug(alwaysDisplay, message, language);
                }

                return true;

            case PacketType.ExtInfo:
                // SSH_MSG_EXT_INFO: stash for userauth. The packet
                // carries server-sig-algs (used by RSA-SHA2 auth). We stash it
                // under its own type so a future WaitForTypeAsync(ExtInfo) can
                // retrieve it. libssh2 parses it inline (packet.c:848-908); we
                // defer parsing until after the key exchange.
                AddStash(packet);
                return true;

            case PacketType.KexInit:
                // ── Server-initiated rekey ───────────────
                // A KEXINIT from the server AFTER the initial KEX completes is
                // a server-initiated rekey request (parity with
                // packet.c:1355-1388). We stash the server's KEXINIT (so the
                // rekey flow's WaitForTypeAsync(KexInit) retrieves it via the
                // fast path), then invoke the rekey callback to drive
                // SshSession.RekeyAsync.
                //
                // During the INITIAL_KEX phase (InitialKex=true), the server's
                // first KEXINIT is the normal initial-KEX exchange, NOT a
                // rekey. We let it fall through to the caller's stash path
                // (which HandshakeAsync's WaitForTypeAsync retrieves directly),
                // matching packet.c:1355-1358's guard on
                // !(state & LIBSSH2_STATE_EXCHANGING_KEYS).
                //
                // If the rekey callback is unset (e.g. during unit tests that
                // don't wire SshSession), fall through to the stash path — the
                // caller is responsible for retrieving it later.
                if (!InitialKex && RekeyTriggerAsync is not null)
                {
                    AddStash(packet);
                    await RekeyTriggerAsync(cancellationToken).ConfigureAwait(false);
                    return true;
                }

                // Initial KEX or no callback wired: NOT inline-handled; let the
                // caller's WaitForTypeAsync retrieve it via stash + type match.
                return false;

            default:
                // Not an inline-handled type; the caller stashes or strict-KEX-
                // checks it.
                return false;
        }
    }

    /// <summary>
    /// Extracts the human-readable description from an SSH_MSG_DISCONNECT
    /// payload (RFC 4253 §11.1): <c>u32 reason | string description | string
    /// language</c>. The payload begins with the type byte (1). Returns a
    /// formatted string for the exception message.
    /// </summary>
    private static string ParseDisconnectDescription(byte[] payload)
    {
        if (payload.Length < 1 + 4 + 4)
        {
            return "SSH_MSG_DISCONNECT (truncated)";
        }

        // Slice past the type byte; read reason + description.
        var seq = new ReadOnlySequence<byte>(payload);
        var r = new PacketWireReader(seq);
        _ = r.ReadByte(); // type byte
        uint reason = r.ReadUInt32BigEndian();
        string desc;
        try
        {
            desc = r.ReadString();
        }
        catch (SshException)
        {
            desc = string.Empty;
        }

        return desc.Length > 0
            ? $"SSH_MSG_DISCONNECT (reason {reason}): {desc}"
            : $"SSH_MSG_DISCONNECT (reason {reason})";
    }
}
