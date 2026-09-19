using System.Buffers;

using LibSsh2CS.Util;

namespace LibSsh2CS.Agent;

/// <summary>
/// SSH agent client (<c>$SSH_AUTH_SOCK</c> on POSIX; Pageant / Windows OpenSSH
/// named pipe on Windows — future backends). Implements
/// <see cref="IAsyncDisposable"/>: callers use <c>await using</c>. Parity with
/// libssh2's <c>LIBSSH2_AGENT</c> (<c>libssh2.h:1328-1456</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Backend selection.</b> <c>new SshAgent()</c> auto-discovers via
/// <see cref="AgentTransports.Create()"/> (Unix socket today; Pageant + Windows
/// OpenSSH pipe when those backends ship). Pass an explicit socket path via
/// <c>new SshAgent(socketPath)</c> for the Unix backend. The
/// <c>internal SshAgent(IAgentTransport)</c> ctor is the test seam + future
/// explicit-backend constructor.
/// </para>
/// <para>
/// <b>Lifecycle.</b>
/// <list type="number">
///   <item><see cref="ConnectAsync"/> — connect to the backend</item>
///   <item><see cref="ListIdentitiesAsync"/> — query the agent for loaded keys</item>
///   <item><see cref="SignAsync"/> — sign data with a chosen identity</item>
///   <item><see cref="DisconnectAsync"/> — close the connection (optional —
///   <see cref="DisposeAsync"/> also disconnects)</item>
///   <item><see cref="DisposeAsync"/> — finalize</item>
/// </list>
/// Each operation throws <see cref="SshException"/> with
/// <see cref="SshErrorCode.AgentProtocol"/> (or a more specific code) on
/// failure — there is no silent-failure mode.
/// </para>
/// <para>
/// <b>Concurrency.</b> The agent protocol is single-connection: at most one
/// outstanding request at a time. <see cref="SshAgent"/> serializes every
/// transaction via a <see cref="SemaphoreSlim"/> — concurrent callers block
/// cleanly rather than corrupting the agent stream.
/// </para>
/// <para>
/// <b>File IO.</b> LibSsh2CS does no file IO — the async-convention test
/// <c>NoBufferedFileIO</c> forbids it. The caller is responsible for the
/// agent socket file existing and readable (it lives in the user's runtime
/// directory on POSIX). The agent library only opens the socket.
/// </para>
/// </remarks>
public sealed class SshAgent : IAsyncDisposable
{
    /// <summary>Serializes every agent transaction (single-connection protocol).</summary>
    private readonly SemaphoreSlim _transactionLock = new(1, 1);

    /// <summary>
    /// The underlying byte transport. Set in the constructor; replaced only if
    /// <see cref="IdentityPath"/> is changed before <see cref="ConnectAsync"/>.
    /// </summary>
    private IAgentTransport? _transport;

    /// <summary>
    /// Whether this instance owns the transport (true for the public ctors that
    /// construct one; false for the internal test ctor that takes an existing
    /// transport). Owned transports are disposed by <see cref="DisposeAsync"/>.
    /// </summary>
    private readonly bool _ownsTransport;

    /// <summary>
    /// Override for the Unix socket path. When set, <see cref="ConnectAsync"/>
    /// rebuilds the transport via <see cref="AgentTransports.Create(string)"/>
    /// before connecting. Equivalent to <c>libssh2_agent_set_identity_path</c>.
    /// </summary>
    private string? _identityPath;

    private bool _connected;
    private bool _disposed;

    // ════════════════════════════════════════════════════════════════════════
    // Constructors
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates an SSH agent client with auto-discovered backend. On POSIX,
    /// resolves <c>$SSH_AUTH_SOCK</c> at <see cref="ConnectAsync"/> time. On
    /// Windows (future), tries Pageant then OpenSSH named pipe.
    /// </summary>
    public SshAgent()
    {
        _transport = AgentTransports.Create();
        _ownsTransport = true;
    }

    /// <summary>
    /// Creates an SSH agent client bound to an explicit Unix socket path
    /// (overrides <c>$SSH_AUTH_SOCK</c>). Mirrors
    /// <c>libssh2_agent_set_identity_path</c> + connect.
    /// </summary>
    /// <param name="socketPath">The Unix socket path to connect to.</param>
    public SshAgent(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        _transport = AgentTransports.Create(socketPath);
        _ownsTransport = true;
        _identityPath = socketPath;
    }

    /// <summary>
    /// Internal constructor for tests + future explicit-backend scenarios.
    /// The supplied transport is NOT disposed by this instance (the test owns
    /// its lifetime — e.g. a fake transport shared across tests).
    /// </summary>
    internal SshAgent(IAgentTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);
        _transport = transport;
        _ownsTransport = false;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Properties
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Override for the agent socket path. Set BEFORE calling
    /// <see cref="ConnectAsync"/> — changes after connect are ignored.
    /// Equivalent to <c>libssh2_agent_set_identity_path</c>
    /// (<c>agent.c:1004-1021</c>). Setting to null clears the override (revert
    /// to <c>$SSH_AUTH_SOCK</c>).
    /// </summary>
    /// <remarks>
    /// For the auto-discovery ctor (<c>new SshAgent()</c>), setting
    /// <see cref="IdentityPath"/> before <see cref="ConnectAsync"/> swaps the
    /// transport to a Unix socket bound to that path. For the explicit-path
    /// ctor (<c>new SshAgent(socketPath)</c>), this is just a readable mirror
    /// of the same value.
    /// </remarks>
    public string? IdentityPath
    {
        get => _identityPath;
        set
        {
            ThrowIfDisposed();
            if (_connected)
            {
                throw new InvalidOperationException(
                    "Cannot change IdentityPath after the agent is connected");
            }

            _identityPath = value;
            // Swap transport to honor the new path.
            if (_ownsTransport)
            {
                _transport = value is null ? AgentTransports.Create() : AgentTransports.Create(value);
            }
        }
    }

    /// <summary>True after a successful <see cref="ConnectAsync"/>.</summary>
    public bool IsConnected => _connected;

    // ════════════════════════════════════════════════════════════════════════
    // Connection lifecycle
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Connects to the SSH agent backend. After this returns,
    /// <see cref="ListIdentitiesAsync"/> and <see cref="SignAsync"/> can be
    /// called. Mirrors <c>libssh2_agent_connect</c> (<c>agent.c:815-826</c>).
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_connected)
        {
            throw new InvalidOperationException("SshAgent is already connected");
        }

        IAgentTransport transport = _transport ?? throw new InvalidOperationException(
            "SshAgent has no transport (this is a bug — should not happen)");

        await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
        _connected = true;
    }

    /// <summary>
    /// Disconnects from the agent gracefully (sends any pending close).
    /// Idempotent — calling on an already-disconnected agent is a no-op.
    /// Mirrors <c>libssh2_agent_disconnect</c> (<c>agent.c:970-975</c>).
    /// </summary>
    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!_connected)
        {
            return;
        }

        // Serialize against in-flight transactions — the transport's
        // socket must not be shut down mid-transaction (a concurrent
        // transaction would hit a closed socket). A transaction already in
        // flight completes (or faults) before the disconnect proceeds.
        await _transactionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_connected)
            {
                return;   // re-check after the wait (a concurrent disconnect won)
            }

            IAgentTransport? transport = _transport;
            if (transport is not null)
            {
                await transport.DisconnectAsync(cancellationToken).ConfigureAwait(false);
            }

            _connected = false;
        }
        finally
        {
            // A caller parked on the lock during a concurrent
            // DisposeAsync may race the semaphore disposal; a release on the
            // disposed semaphore would mask the caller's real error.
            try
            {
                _transactionLock.Release();
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Operations
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Queries the agent for its loaded identities. Returns the list in the
    /// order the agent returned them. Mirrors <c>libssh2_agent_list_identities</c>
    /// (<c>agent.c:835-842</c> + the inner <c>agent_list_identities</c>
    /// 610-742). Safe to call multiple times — each call re-queries the agent.
    /// </summary>
    public async Task<IReadOnlyList<SshAgentIdentity>> ListIdentitiesAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ThrowIfNotConnected();

        byte[] request = AgentProtocol.BuildRequestIdentities();
        using var writer = new MemoryPoolBufferWriter();
        await TransactWithLockAsync(request, writer, cancellationToken)
            .ConfigureAwait(false);

        // Check for FAILURE response.
        ReadOnlySequence<byte> response = writer.GetReadOnlySequence();
        if (response.Length > 0 && response.FirstSpan[0] == AgentProtocol.MsgFailure)
        {
            throw AgentProtocol.CreateFailureException("list identities");
        }

        List<(byte[] Blob, string Comment)> rawIds =
            AgentProtocol.ParseIdentitiesAnswer(response);

        // Map tuples to AgentIdentity records.
        var identities = new List<SshAgentIdentity>(rawIds.Count);
        foreach ((byte[] blob, string comment) in rawIds)
        {
            identities.Add(new SshAgentIdentity { Blob = blob, Comment = comment });
        }

        return identities;
    }

    /// <summary>
    /// Signs data using a loaded agent identity. The agent chooses the
    /// signature algorithm based on the key type; for RSA keys, the
    /// <paramref name="flags"/> parameter requests SHA-2 variants (ignored for
    /// non-RSA keys). Returns the full SSH signature blob
    /// (<c>[string algoName][string rawSig]</c>). Mirrors <c>agent_sign</c>
    /// (<c>agent.c:447-607</c>).
    /// </summary>
    /// <param name="identity">
    /// An identity returned by <see cref="ListIdentitiesAsync"/>. Only the
    /// <see cref="SshAgentIdentity.Blob"/> field is read.
    /// </param>
    /// <param name="data">The data to sign (typically <c>session_id ‖ USERAUTH_REQUEST</c>).</param>
    /// <param name="flags">
    /// Optional RSA-SHA2 hint (<see cref="SshAgentSignFlags.RsaSha256"/> /
    /// <see cref="SshAgentSignFlags.RsaSha512"/>). Ignored for non-RSA keys.
    /// </param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The SSH signature blob (<c>[string algoName][string rawSig]</c>).</returns>
    public async Task<byte[]> SignAsync(
        SshAgentIdentity identity,
        ReadOnlyMemory<byte> data,
        SshAgentSignFlags flags = SshAgentSignFlags.None,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ThrowIfNotConnected();
        ArgumentNullException.ThrowIfNull(identity);

        int requestLength = AgentProtocol.GetSignRequestPayloadLength(identity.Blob.Length, data.Length);
        byte[] requestBuffer = ArrayPool<byte>.Shared.Rent(requestLength);
        try
        {
            AgentProtocol.BuildSignRequest(requestBuffer, identity.Blob, data.Span, (uint)flags);
            using var writer = new MemoryPoolBufferWriter();
            await TransactWithLockAsync(requestBuffer.AsMemory(0, requestLength), writer, cancellationToken).ConfigureAwait(false);

            ReadOnlySequence<byte> response = writer.GetReadOnlySequence();
            if (response.Length > 0 && response.FirstSpan[0] == AgentProtocol.MsgFailure)
            {
                throw AgentProtocol.CreateFailureException("sign");
            }

            return AgentProtocol.ParseSignResponse(response);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(requestBuffer);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Dispose
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Disconnects (if connected) and releases transport resources. Idempotent.
    /// Mirrors <c>libssh2_agent_free</c> (<c>agent.c:983-996</c>) — disconnects
    /// first, then frees the underlying transport.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Acquire the transaction lock so no transaction is mid-flight on
        // the transport when it is torn down (a concurrent transaction would
        // hit a disposed socket — a raw ObjectDisposedException the transport's
        // error contract does not surface) and no caller is parked on the
        // semaphore when it is disposed. An in-flight transaction completes (or
        // faults) first; disposal is not cancellable, like the rest of the
        // teardown.
        await _transactionLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            try
            {
                if (_connected && _transport is not null)
                {
                    await _transport.DisconnectAsync(CancellationToken.None).ConfigureAwait(false);
                    _connected = false;
                }
            }
            catch (SshException)
            {
                // Best-effort disconnect — swallow agent-side errors at dispose.
            }

            if (_ownsTransport && _transport is not null)
            {
                await _transport.DisposeAsync().ConfigureAwait(false);
            }

            _transport = null;
        }
        finally
        {
            // Wake any caller parked on the lock: it observes the disposed
            // state (clean ObjectDisposedException from the entry guard in
            // TransactWithLockAsync) rather than staying parked forever.
            _transactionLock.Release();
            _transactionLock.Dispose();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Acquires the transaction lock and forwards to the transport. Centralizes
    /// the single-connection serialization so <see cref="ListIdentitiesAsync"/>
    /// and <see cref="SignAsync"/> share the same locking discipline.
    /// </summary>
    private async Task TransactWithLockAsync(
        ReadOnlyMemory<byte> request, IBufferWriter<byte> responseWriter,
        CancellationToken cancellationToken)
    {
        await _transactionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // DisposeAsync may have completed (and released the lock)
            // while this caller was parked — fail with the clean entry guard,
            // not the null-transport message or a disposed-semaphore error.
            ObjectDisposedException.ThrowIf(_disposed, this);

            IAgentTransport transport = _transport ?? throw new InvalidOperationException(
                "SshAgent has no transport (disposed mid-call?)");
            await transport.TransactAsync(request, responseWriter, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // A concurrent DisposeAsync may dispose the semaphore right
            // after releasing it; a release on the disposed semaphore would
            // mask the transaction's real error.
            try
            {
                _transactionLock.Release();
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private void ThrowIfNotConnected()
    {
        if (!_connected)
        {
            throw new InvalidOperationException("SshAgent is not connected; call ConnectAsync first");
        }
    }
}
