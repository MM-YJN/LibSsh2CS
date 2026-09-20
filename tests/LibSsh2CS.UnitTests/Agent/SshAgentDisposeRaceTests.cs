using System.Buffers;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Regression tests for <see cref="SshAgent"/> lifecycle races: disposal and
/// disconnect must serialize with in-flight transactions, a connect that is
/// still resolving its backend must not install that backend after disposal,
/// and a connect in flight must both block a concurrent disconnect (which would
/// otherwise report success and leave the agent connected) and reject
/// configuration changes that would contradict what it resolves.
/// <c>DisposeAsync</c> publishes disposal before it acquires the single
/// operation gate, so parked callers wake up and fail with a clean
/// <see cref="ObjectDisposedException"/>, and a transport that connected during
/// disposal is released instead of leaking into a disposed agent. The
/// transport also maps disposed-socket errors to
/// <see cref="SshErrorCode.SocketRecv"/>.
/// Managed-only lifecycle issue — the C has no dispose.
/// </summary>
public class SshAgentDisposeRaceTests
{
    [Fact]
    public async Task DisposeAsync_WaitsForInFlightTransaction_TransactionCompletesCleanly()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingTransport();
        var agent = new SshAgent(transport);
        await agent.ConnectAsync(ct);

        // Transaction 1 blocks inside the transport (the agent holds the
        // transaction lock for its whole duration).
        Task<IReadOnlyList<SshAgentIdentity>> tx =
            agent.ListIdentitiesAsync(ct);
        await transport.WaitForTransactionStartedAsync(TimeSpan.FromSeconds(5));

        // Dispose while the transaction is in flight. Pre-fix: dispose tore the
        // transport down and disposed the semaphore without the lock — the
        // in-flight transaction's lock release then hit the disposed semaphore
        // (ObjectDisposedException). Post-fix: dispose waits for the lock.
        Task dispose = agent.DisposeAsync().AsTask();

        // Let the transaction complete; dispose then proceeds.
        transport.Release();

        IReadOnlyList<SshAgentIdentity> identities =
            await tx.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await dispose.WaitAsync(TimeSpan.FromSeconds(10), ct);

        Assert.Empty(identities);
        Assert.True(transport.DisconnectCalled);
    }

    [Fact]
    public async Task DisposeAsync_ParkedTransactionWaiter_FailsCleanly()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingTransport();
        var agent = new SshAgent(transport);
        await agent.ConnectAsync(ct);

        // Transaction 1 holds the lock; transaction 2 parks on it.
        Task<IReadOnlyList<SshAgentIdentity>> tx1 =
            agent.ListIdentitiesAsync(ct);
        await transport.WaitForTransactionStartedAsync(TimeSpan.FromSeconds(5));

        Task<IReadOnlyList<SshAgentIdentity>> tx2 =
            agent.ListIdentitiesAsync(ct);
        await Task.Delay(50, ct);

        Task dispose = agent.DisposeAsync().AsTask();
        transport.Release();   // tx1 completes → dispose proceeds → tx2 wakes

        _ = await tx1.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await dispose.WaitAsync(TimeSpan.FromSeconds(10), ct);

        // Post-fix tx2 wakes with the lock, observes the disposed state, and
        // fails with a clean ObjectDisposedException (the entry guard), not a
        // hang and not a raw error from the disposed semaphore.
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            tx2.WaitAsync(TimeSpan.FromSeconds(10), ct));
    }

    [Fact]
    public async Task DisconnectAsync_WaitsForInFlightTransaction()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingTransport();
        var agent = new SshAgent(transport);
        await agent.ConnectAsync(ct);

        Task<IReadOnlyList<SshAgentIdentity>> tx =
            agent.ListIdentitiesAsync(ct);
        await transport.WaitForTransactionStartedAsync(TimeSpan.FromSeconds(5));

        // Disconnect while the transaction is in flight: post-fix it waits for
        // the lock (the socket is not shut down mid-transaction).
        Task disconnect = agent.DisconnectAsync(ct);

        transport.Release();
        _ = await tx.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await disconnect.WaitAsync(TimeSpan.FromSeconds(10), ct);

        Assert.True(transport.DisconnectCalled);
        Assert.False(agent.IsConnected);
    }

    /// <summary>
    /// Disposal can begin while a connect is still resolving its backend, and
    /// the connect must not install that backend afterwards: the winner is
    /// disconnected and disposed (the agent owns discovered transports) and the
    /// caller sees ObjectDisposedException instead of a connected agent.
    /// </summary>
    [Fact]
    public async Task DisposeAsync_DuringAutoDiscovery_ReleasesTheWinnerAndLeavesAgentDisconnected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingConnectTransport();
        var agent = new SshAgent([() => transport]);

        Task connect = agent.ConnectAsync(ct);
        await transport.WaitForConnectStartedAsync(TimeSpan.FromSeconds(5));

        // Disposal publishes itself immediately, but it must wait for the
        // connect that still holds the gate.
        Task dispose = agent.DisposeAsync().AsTask();
        Assert.False(dispose.IsCompleted);

        // Discovery succeeds after disposal has already begun.
        transport.ReleaseConnect();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => connect.WaitAsync(TimeSpan.FromSeconds(10), ct));
        await dispose.WaitAsync(TimeSpan.FromSeconds(10), ct);

        Assert.False(agent.IsConnected);
        Assert.Equal(1, transport.ConnectCalls);
        Assert.Equal(1, transport.DisconnectCalls);
        Assert.Equal(1, transport.DisposeCalls);
    }

    /// <summary>
    /// The same race for an injected transport: the agent must release what it
    /// never installed, but it must not dispose a transport the caller owns.
    /// </summary>
    [Fact]
    public async Task DisposeAsync_DuringExplicitConnect_DisconnectsInjectedTransportWithoutDisposingIt()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingConnectTransport();
        var agent = new SshAgent(transport);

        Task connect = agent.ConnectAsync(ct);
        await transport.WaitForConnectStartedAsync(TimeSpan.FromSeconds(5));

        Task dispose = agent.DisposeAsync().AsTask();
        Assert.False(dispose.IsCompleted);

        transport.ReleaseConnect();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => connect.WaitAsync(TimeSpan.FromSeconds(10), ct));
        await dispose.WaitAsync(TimeSpan.FromSeconds(10), ct);

        Assert.False(agent.IsConnected);
        Assert.Equal(1, transport.DisconnectCalls);
        Assert.Equal(0, transport.DisposeCalls);
    }

    /// <summary>
    /// A second connect never resolves a backend in parallel with the first: it
    /// waits for the gate and then reports the already-connected state.
    /// </summary>
    [Fact]
    public async Task ConnectAsync_SecondConnectBehindTheFirst_FailsAsAlreadyConnected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingConnectTransport();
        var agent = new SshAgent([() => transport]);

        Task first = agent.ConnectAsync(ct);
        await transport.WaitForConnectStartedAsync(TimeSpan.FromSeconds(5));

        Task second = agent.ConnectAsync(ct);
        transport.ReleaseConnect();

        await first.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => second.WaitAsync(TimeSpan.FromSeconds(10), ct));

        Assert.True(agent.IsConnected);
        Assert.Equal(1, transport.ConnectCalls);

        await agent.DisposeAsync();
        Assert.Equal(1, transport.DisposeCalls);
    }

    /// <summary>
    /// A disconnect issued while a connect is still resolving its backend must
    /// not return early: the pending connect would then publish itself and
    /// leave the agent connected after the caller observed a successful
    /// disconnect. The gate makes the disconnect wait for the connect, so its
    /// re-check sees the state the connect published and tears it down.
    /// </summary>
    [Fact]
    public async Task DisconnectAsync_DuringConnect_WaitsForTheConnectAndDisconnects()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingConnectTransport();
        var agent = new SshAgent([() => transport]);

        Task connect = agent.ConnectAsync(ct);
        await transport.WaitForConnectStartedAsync(TimeSpan.FromSeconds(5));

        // Pre-fix the disconnected fast path returned immediately here, while
        // the connect still held the gate and had published nothing.
        Task disconnect = agent.DisconnectAsync(ct);
        await Task.Delay(100, ct);
        Assert.False(disconnect.IsCompleted);

        transport.ReleaseConnect();

        await connect.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await disconnect.WaitAsync(TimeSpan.FromSeconds(10), ct);

        Assert.False(agent.IsConnected);
        Assert.Equal(1, transport.ConnectCalls);
        Assert.Equal(1, transport.DisconnectCalls);
        Assert.Equal(1, transport.DisposeCalls);
    }

    /// <summary>
    /// <see cref="SshAgent.IdentityPath"/> describes the backend the client
    /// resolved, so it must not change while a connect is resolving one — the
    /// property would otherwise expose an explicit socket path while discovery
    /// goes on to install Pageant.
    /// </summary>
    [Fact]
    public async Task IdentityPath_DuringConnectDiscovery_IsRejected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingConnectTransport();
        var agent = new SshAgent([() => transport]);

        Task connect = agent.ConnectAsync(ct);
        await transport.WaitForConnectStartedAsync(TimeSpan.FromSeconds(5));

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => agent.IdentityPath = "/tmp/explicit-agent.sock");
        Assert.Contains("connecting or connected", ex.Message);
        Assert.Null(agent.IdentityPath);

        transport.ReleaseConnect();
        await connect.WaitAsync(TimeSpan.FromSeconds(10), ct);

        // The discovered backend won, so the property still reports no explicit
        // path, and stays closed now that the agent is connected.
        Assert.True(agent.IsConnected);
        Assert.Null(agent.IdentityPath);
        Assert.Throws<InvalidOperationException>(
            () => agent.IdentityPath = "/tmp/after-connect.sock");
    }

    /// <summary>
    /// A failed connect releases its configuration claim, so the caller can
    /// point the agent at a different backend and try again.
    /// </summary>
    [Fact]
    public async Task IdentityPath_AfterFailedConnect_IsAccepted()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var transport = new BlockingConnectTransport
        {
            ConnectFailure = new SshException(SshErrorCode.AgentProtocol, "failed connecting agent"),
        };
        var agent = new SshAgent([() => transport]);

        Task connect = agent.ConnectAsync(ct);
        await transport.WaitForConnectStartedAsync(TimeSpan.FromSeconds(5));
        transport.ReleaseConnect();

        await Assert.ThrowsAsync<SshException>(() => connect.WaitAsync(TimeSpan.FromSeconds(10), ct));
        Assert.False(agent.IsConnected);

        agent.IdentityPath = "/tmp/after-failure.sock";
        Assert.Equal("/tmp/after-failure.sock", agent.IdentityPath);
    }

    /// <summary>
    /// A fake transport whose <see cref="TransactAsync"/> blocks until the
    /// test releases it — lets the test hold the agent's operation gate for
    /// a deterministic window while dispose/disconnect runs.
    /// </summary>
    private sealed class BlockingTransport : IAgentTransport
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _started =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool DisconnectCalled { get; private set; }

        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public async Task TransactAsync(
            ReadOnlyMemory<byte> request,
            IBufferWriter<byte> responseWriter,
            CancellationToken cancellationToken)
        {
            _started.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);

            // Empty identities-answer: [12][u32 nkeys=0].
            responseWriter.Write(new byte[] { AgentProtocol.MsgIdentitiesAnswer, 0, 0, 0, 0 });
        }

        public Task DisconnectAsync(CancellationToken cancellationToken)
        {
            DisconnectCalled = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public Task WaitForTransactionStartedAsync(TimeSpan timeout)
            => _started.Task.WaitAsync(timeout);

        public void Release() => _release.TrySetResult();
    }

    /// <summary>
    /// A fake transport whose <see cref="ConnectAsync"/> parks until the test
    /// releases it — the deterministic window in which disposal can begin while
    /// a connect is still resolving its backend.
    /// </summary>
    private sealed class BlockingConnectTransport : IAgentTransport
    {
        private readonly TaskCompletionSource _started =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int ConnectCalls { get; private set; }

        public int DisconnectCalls { get; private set; }

        public int DisposeCalls { get; private set; }

        /// <summary>Thrown (as a faulted task) after the test releases the connect.</summary>
        public Exception? ConnectFailure { get; set; }

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            ConnectCalls++;
            _started.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);

            if (ConnectFailure is not null)
            {
                throw ConnectFailure;
            }
        }

        public Task TransactAsync(
            ReadOnlyMemory<byte> request,
            IBufferWriter<byte> responseWriter,
            CancellationToken cancellationToken)
            => throw new NotSupportedException($"{nameof(BlockingConnectTransport)} does not transact");

        public Task DisconnectAsync(CancellationToken cancellationToken)
        {
            DisconnectCalls++;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }

        public Task WaitForConnectStartedAsync(TimeSpan timeout)
            => _started.Task.WaitAsync(timeout);

        public void ReleaseConnect() => _release.TrySetResult();
    }
}
