using System.Buffers;
using System.Diagnostics.CodeAnalysis;

using LibSsh2CS.Util;

namespace LibSsh2CS.Agent;

/// <summary>
/// SSH agent client (<c>$SSH_AUTH_SOCK</c> on POSIX; Pageant on Windows).
/// Implements <see cref="IAsyncDisposable"/>: callers use <c>await using</c>.
/// Parity with libssh2's <c>LIBSSH2_AGENT</c> (<c>libssh2.h:1328-1456</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Backend selection.</b> <c>new SshAgent()</c> discovers its backend when
/// <see cref="ConnectAsync"/> runs — Pageant first on Windows, then the Unix
/// socket named by <c>$SSH_AUTH_SOCK</c> — so a Pageant that starts after the
/// client was constructed is still found. Passing an explicit socket path
/// (<c>new SshAgent(socketPath)</c> or <see cref="IdentityPath"/>) disables
/// discovery and uses that socket only. The
/// <c>internal SshAgent(IAgentTransport)</c> ctor is the test seam.
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
/// failure — there is no silent-failure mode. Disposal publishes itself before
/// it waits for the gate, so a backend that finishes connecting after disposal
/// began is released instead of installed, and the connect caller sees
/// <see cref="ObjectDisposedException"/>.
/// </para>
/// <para>
/// <b>Concurrency.</b> The agent protocol is single-connection: at most one
/// outstanding request at a time. <see cref="SshAgent"/> serializes every
/// operation — connect, disconnect, transactions, and disposal — through one
/// gate, so concurrent callers block cleanly rather than corrupting the agent
/// stream, and a lifecycle transition cannot race an in-flight operation. A
/// connect also freezes the client's configuration for as long as it runs:
/// <see cref="IdentityPath"/> rejects changes from the moment a
/// <see cref="ConnectAsync"/> call starts, so the path the property reports can
/// never disagree with the backend that was resolved.
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
    /// <summary>
    /// Serializes every operation — connect, disconnect, transactions, and
    /// disposal — because the agent protocol is single-connection and a
    /// lifecycle transition must not race an in-flight operation. It is
    /// deliberately never disposed: callers parked on it must be able to wake
    /// up, observe disposal, and fail cleanly instead of being stranded.
    /// </summary>
    [SuppressMessage(
        "Usage",
        "CA2213:Disposable fields should be disposed",
        Justification = "Disposing the gate would strand callers parked behind disposal (SemaphoreSlim does not wake async waiters when it is disposed) and a caller that passed the disposed check just before disposal began could then hit a disposed semaphore. SemaphoreSlim holds no unmanaged resources unless AvailableWaitHandle is used, which this type never touches.")]
    private readonly SemaphoreSlim _operationLock = new(1, 1);

    /// <summary>
    /// Guards connection publication, disposal, <see cref="_identityPath"/>, and
    /// <see cref="_connectingAttempts"/> — the state that decides whether the
    /// client's configuration may still change. It is separate from
    /// <see cref="_operationLock"/>, which serializes transport work and is
    /// acquired with an await; this lock is synchronous and is never held
    /// across an await, so no caller is ever parked inside it.
    /// </summary>
    private readonly object _stateLock = new();

    /// <summary>
    /// Backend factories used by auto-discovery. <c>null</c> means "use the
    /// platform defaults" (<see cref="AgentTransports.GetFactories"/>); tests
    /// inject their own list.
    /// </summary>
    private readonly IReadOnlyList<Func<IAgentTransport?>>? _discoveryFactories;

    /// <summary>
    /// The underlying byte transport. Stays <c>null</c> until
    /// <see cref="ConnectAsync"/> resolves it — by discovery, by explicit path,
    /// or because a test injected one.
    /// </summary>
    private IAgentTransport? _transport;

    /// <summary>
    /// Whether this instance owns the transport (true for the public ctors that
    /// resolve one, and for discovered transports; false for the internal test
    /// ctor that takes an existing transport). Owned transports are disposed by
    /// <see cref="DisconnectAsync"/> and by <see cref="DisposeAsync"/>.
    /// </summary>
    private readonly bool _ownsTransport;

    /// <summary>
    /// Override for the Unix socket path. When set, <see cref="ConnectAsync"/>
    /// rebuilds the transport via <see cref="AgentTransports.Create(string)"/>
    /// before connecting. Equivalent to <c>libssh2_agent_set_identity_path</c>.
    /// Guarded by <see cref="_stateLock"/>; a registered connect attempt reads
    /// it under the operation gate, where it cannot change while the attempt is
    /// in flight.
    /// </summary>
    private string? _identityPath;

    /// <summary>
    /// Whether a transport is connected and usable. Guarded by
    /// <see cref="_stateLock"/>, so a reader never observes the connected state
    /// in the gap between the transport being installed and the flag being
    /// published.
    /// </summary>
    private bool _connected;

    /// <summary>
    /// Number of <see cref="ConnectAsync"/> calls that have started and not yet
    /// finished, including the ones still parked on the operation gate.
    /// Incremented under <see cref="_stateLock"/> before a connect's first
    /// await, so <see cref="IdentityPath"/> can reject a change that would
    /// otherwise retarget a connect already committed to a backend.
    /// </summary>
    private int _connectingAttempts;

    /// <summary>
    /// Disposal flag: <c>0</c> while the agent is usable, <c>1</c> once
    /// <see cref="DisposeAsync"/> has published disposal. It is set under the state lock
    /// before the gate is acquired, so a connect that is still resolving its
    /// backend can observe it and clean up instead of installing a transport
    /// into a disposed agent.
    /// </summary>
    private int _disposed;

    // ════════════════════════════════════════════════════════════════════════
    // Constructors
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates an SSH agent client that discovers its backend when
    /// <see cref="ConnectAsync"/> runs: Pageant first on Windows, then the Unix
    /// socket named by <c>$SSH_AUTH_SOCK</c>. Resolution is deliberately
    /// deferred so constructing a client cannot fail on a machine whose agent
    /// is not running yet.
    /// </summary>
    public SshAgent()
    {
        _ownsTransport = true;
    }

    /// <summary>
    /// Creates an SSH agent client bound to an explicit Unix socket path. The
    /// path disables auto-discovery (Pageant is not consulted) and overrides
    /// <c>$SSH_AUTH_SOCK</c>. Mirrors
    /// <c>libssh2_agent_set_identity_path</c> + connect.
    /// </summary>
    /// <param name="socketPath">The Unix socket path to connect to.</param>
    public SshAgent(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        _identityPath = ValidateSocketPath(socketPath, nameof(socketPath));
        _ownsTransport = true;
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

    /// <summary>
    /// Internal constructor for tests: supplies the backend factories used by
    /// auto-discovery so candidate ordering, fallback, and disposal can be
    /// exercised without depending on which agents happen to run on the test
    /// machine. Discovered transports are owned by this instance.
    /// </summary>
    /// <param name="discoveryFactories">Candidate factories in preference order.</param>
    internal SshAgent(IReadOnlyList<Func<IAgentTransport?>> discoveryFactories)
    {
        ArgumentNullException.ThrowIfNull(discoveryFactories);
        _discoveryFactories = discoveryFactories;
        _ownsTransport = true;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Properties
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Override for the agent socket path. Set BEFORE calling
    /// <see cref="ConnectAsync"/>; setting it while a connect is in flight or
    /// after the agent is connected throws. Equivalent to
    /// <c>libssh2_agent_set_identity_path</c> (<c>agent.c:1004-1021</c>).
    /// Setting to null clears the override and restores auto-discovery (or
    /// <c>$SSH_AUTH_SOCK</c> on POSIX).
    /// </summary>
    /// <remarks>
    /// For the auto-discovery ctor (<c>new SshAgent()</c>), setting
    /// <see cref="IdentityPath"/> before <see cref="ConnectAsync"/> pins the
    /// agent to a Unix socket at that path and skips Pageant. For the
    /// explicit-path ctor (<c>new SshAgent(socketPath)</c>), this is just a
    /// readable mirror of the same value.
    /// </remarks>
    public string? IdentityPath
    {
        get
        {
            lock (_stateLock)
            {
                return _identityPath;
            }
        }

        set
        {
            ThrowIfDisposed();
            lock (_stateLock)
            {
                ThrowIfDisposed();

                // A connect that already started has committed to a backend
                // (discovery, an explicit path, or an injected transport), so a
                // change here would either be ignored or contradict the state
                // this property reports. A failed or canceled attempt releases
                // the claim in its own finally.
                if (_connected || _connectingAttempts > 0)
                {
                    throw new InvalidOperationException(
                        "Cannot change IdentityPath while the agent is connecting or connected");
                }

                // The next connect resolves the transport from this value, so
                // the property never has to swap (or dispose) a live transport.
                _identityPath = value is null ? null : ValidateSocketPath(value, nameof(value));
            }
        }
    }

    /// <summary>True after a successful <see cref="ConnectAsync"/>.</summary>
    public bool IsConnected
    {
        get
        {
            lock (_stateLock)
            {
                return _connected;
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Connection lifecycle
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Connects to the SSH agent backend. After this returns,
    /// <see cref="ListIdentitiesAsync"/> and <see cref="SignAsync"/> can be
    /// called. With no explicit transport or path, the backend is discovered
    /// here and the first one that connects wins — parity with
    /// <c>libssh2_agent_connect</c> (<c>agent.c:815-826</c>).
    /// </summary>
    /// <remarks>
    /// The gate is held across backend resolution, so a queued disconnect or
    /// disposal never observes a half-published connect, and
    /// <see cref="DisconnectAsync"/> cannot return before a connect that is
    /// already in flight has published or abandoned its result. If disposal
    /// wins the race while discovery is still running, the backend that
    /// connected is disconnected (and disposed when this instance owns it) and
    /// the caller gets <see cref="ObjectDisposedException"/>.
    /// </remarks>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Claim the client's configuration before the first await: from here
        // until this call finishes, IdentityPath must not change, because this
        // call is committed to resolving the backend that the property would
        // otherwise appear to describe.
        lock (_stateLock)
        {
            ThrowIfDisposed();
            if (_connected)
            {
                throw new InvalidOperationException("SshAgent is already connected");
            }

            _connectingAttempts++;
        }

        try
        {
            await ConnectTransportAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Whatever the outcome — connected, failed, or canceled — the
            // attempt is over. A successful connect keeps the property closed
            // through the connected flag; a failure or cancellation makes it
            // settable again.
            lock (_stateLock)
            {
                _connectingAttempts--;
            }
        }
    }

    /// <summary>
    /// Resolves and connects the backend while holding the operation gate.
    /// Split out of <see cref="ConnectAsync"/> so the connect-attempt claim is
    /// released for every outcome, including the exceptions thrown before the
    /// gate is reached.
    /// </summary>
    private async Task ConnectTransportAsync(CancellationToken cancellationToken)
    {
        await _operationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check under the gate: a queued connect, disconnect, or
            // disposal may have won the race while this caller was parked.
            ThrowIfDisposed();
            if (IsConnected)
            {
                throw new InvalidOperationException("SshAgent is already connected");
            }

            if (_transport is null && _identityPath is null)
            {
                // Auto-discovery. A backend that is missing or unreachable
                // falls through to the next one; only the cancellation token
                // stops the search early.
                IAgentTransport discovered = await AgentTransports
                    .ConnectAsync(_discoveryFactories ?? AgentTransports.GetFactories(), cancellationToken)
                    .ConfigureAwait(false);

                // Disposal can start while discovery is in flight. Installing
                // the transport afterwards would leak it and leave a disposed
                // agent logically connected, so the winner is released and the
                // caller sees the disposed state.
                if (!TryPublishConnected(discovered))
                {
                    await ReleaseAfterLostRaceAsync(discovered, CancellationToken.None).ConfigureAwait(false);
                    ThrowIfDisposed();
                }

                return;
            }

            // An explicit path or an injected transport pins the client to one
            // backend, so a failure is reported rather than masked by
            // connecting to some other agent.
            IAgentTransport transport = _transport ?? AgentTransports.Create(_identityPath!);
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);

            if (!TryPublishConnected(transport))
            {
                await ReleaseAfterLostRaceAsync(transport, CancellationToken.None).ConfigureAwait(false);
                ThrowIfDisposed();
            }
        }
        finally
        {
            _operationLock.Release();
        }
    }

    /// <summary>
    /// Disconnects from the agent gracefully (sends any pending close).
    /// Idempotent — calling on an already-disconnected agent is a no-op.
    /// Mirrors <c>libssh2_agent_disconnect</c> (<c>agent.c:970-975</c>).
    /// </summary>
    /// <remarks>
    /// The operation gate is taken even when the agent currently looks
    /// disconnected, because a connect may still be resolving its backend: it
    /// holds the gate until it has published or abandoned the result, so this
    /// method cannot return before that connect settles, and the re-check below
    /// then observes what the connect actually left behind.
    /// </remarks>
    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Serialize against connect, transactions, and disposal — the
        // transport's socket must not be shut down mid-transaction (a
        // concurrent transaction would hit a closed socket), and a queued
        // operation must observe the disconnected state rather than a
        // torn-down transport.
        await _operationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            if (!IsConnected)
            {
                // A concurrent disconnect already won, or the connect this
                // call waited behind failed and published nothing.
                return;
            }

            IAgentTransport? transport = _transport;
            if (transport is not null)
            {
                await transport.DisconnectAsync(cancellationToken).ConfigureAwait(false);

                if (_ownsTransport)
                {
                    // Drop the backend so the next connect resolves it again.
                    // For auto-discovery that means re-running discovery, which
                    // is what lets a reconnect pick up a Pageant (or socket)
                    // that was started after the previous connect.
                    await transport.DisposeAsync().ConfigureAwait(false);
                    _transport = null;
                }
            }

            SetConnected(false);
        }
        finally
        {
            _operationLock.Release();
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
        // Publish disposal before waiting for the gate. New operations fail
        // immediately, and a second DisposeAsync becomes a no-op instead of
        // tearing down the same state twice.
        lock (_stateLock)
        {
            if (IsDisposed)
            {
                return;
            }

            Volatile.Write(ref _disposed, 1);
        }

        // Acquire the gate so no operation is mid-flight on the transport when
        // it is torn down (a concurrent transaction would hit a disposed
        // socket — a raw ObjectDisposedException the transport's error contract
        // does not surface). An in-flight operation completes (or faults)
        // first; disposal is not cancellable, like the rest of the teardown.
        // A connect that is still resolving its backend observes the published
        // disposal flag and releases what it connected instead of installing
        // it.
        await _operationLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            try
            {
                if (IsConnected && _transport is not null)
                {
                    await _transport.DisconnectAsync(CancellationToken.None).ConfigureAwait(false);
                    SetConnected(false);
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
            // Wake every caller parked behind disposal: each one observes the
            // disposed state (a clean ObjectDisposedException from the entry
            // guards) instead of staying parked. The gate is deliberately never
            // disposed, so no waiter can be stranded on a semaphore that is
            // already gone.
            _operationLock.Release();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Acquires the lifecycle gate and forwards to the transport. Centralizes
    /// the single-connection serialization so <see cref="ListIdentitiesAsync"/>
    /// and <see cref="SignAsync"/> share the same gating discipline as the
    /// lifecycle methods.
    /// </summary>
    private async Task TransactWithLockAsync(
        ReadOnlyMemory<byte> request, IBufferWriter<byte> responseWriter,
        CancellationToken cancellationToken)
    {
        await _operationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // A queued operation may have been overtaken by disconnect or
            // disposal while it was parked — report the state that actually
            // changed instead of a stale success or a null-transport error.
            ThrowIfDisposed();
            ThrowIfNotConnected();

            IAgentTransport transport = _transport ?? throw new InvalidOperationException(
                "SshAgent has no transport (disposed mid-call?)");
            await transport.TransactAsync(request, responseWriter, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    private static string ValidateSocketPath(string socketPath, string parameterName)
    {
        if (socketPath.Length == 0)
        {
            throw new ArgumentException("Socket path must not be empty", parameterName);
        }

        return socketPath;
    }

    /// <summary>True once <see cref="DisposeAsync"/> has published disposal.</summary>
    private bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// Commits a successful connect atomically with respect to disposal.
    /// Called with the operation gate held; cleanup of a losing transport is
    /// awaited by the caller after the state lock has been released.
    /// </summary>
    private bool TryPublishConnected(IAgentTransport transport)
    {
        lock (_stateLock)
        {
            if (IsDisposed)
            {
                return false;
            }

            _transport = transport;
            _connected = true;
            return true;
        }
    }

    /// <summary>
    /// Publishes the connected state under <see cref="_stateLock"/>. Always
    /// called while the operation gate is held, after the transport is
    /// installed (or dropped), so the flag and the transport change together
    /// from an observer's point of view.
    /// </summary>
    private void SetConnected(bool connected)
    {
        lock (_stateLock)
        {
            _connected = connected;
        }
    }

    /// <summary>
    /// Releases a transport that finished connecting after disposal had already
    /// been published. It was never installed on the agent, so this is the only
    /// place that can tear it down: best-effort disconnect, then dispose only
    /// when the agent owns it (an injected transport belongs to the caller).
    /// </summary>
    /// <param name="transport">The transport that lost the race.</param>
    /// <param name="cancellationToken">
    /// Forwarded to the best-effort disconnect. The disposal path passes
    /// <see cref="CancellationToken.None"/> so the release cannot be skipped.
    /// </param>
    private async Task ReleaseAfterLostRaceAsync(
        IAgentTransport transport, CancellationToken cancellationToken)
    {
        try
        {
            await transport.DisconnectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best effort: the caller is about to see ObjectDisposedException,
            // which is the signal that matters here.
        }

        if (_ownsTransport)
        {
            try
            {
                await transport.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Best effort, and deliberately after the disconnect so a
                // failed disconnect cannot skip the disposal.
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
    }

    private void ThrowIfNotConnected()
    {
        if (!IsConnected)
        {
            throw new InvalidOperationException("SshAgent is not connected; call ConnectAsync first");
        }
    }
}
