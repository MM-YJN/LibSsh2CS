using System.Buffers;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Regression tests: <c>SshAgent.DisposeAsync</c> /
/// <c>DisconnectAsync</c> raced in-flight transactions — the transaction lock
/// serialized only transactions, so disposal tore down the socket and disposed
/// the semaphore without the lock: an in-flight transaction hit a disposed
/// socket (raw ObjectDisposedException, which the transport's error contract
/// did not surface) and a caller parked in <c>WaitAsync</c> was stranded.
/// Post-fix the dispose/disconnect paths acquire the transaction lock first
/// (the in-flight transaction completes or faults before teardown) and the
/// transport maps disposed-socket errors to <see cref="SshErrorCode.SocketRecv"/>.
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
    /// A fake transport whose <see cref="TransactAsync"/> blocks until the
    /// test releases it — lets the test hold the agent's transaction lock for
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
}
