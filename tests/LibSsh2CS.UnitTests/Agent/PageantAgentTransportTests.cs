using System.Buffers;
using System.Diagnostics;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Tests for <see cref="PageantAgentTransport"/> driven through a fake
/// <see cref="IPageantWindowChannel"/>, so the transport's size limits, state
/// machine, error mapping, cancellation, timeout, and cleanup rules are covered on every
/// platform without a running Pageant. The real window/mapping behavior is
/// covered by the Windows IPC integration tests, which exercise
/// <see cref="PageantWindowChannel"/> against a separate process.
/// </summary>
public class PageantAgentTransportTests
{
    // ════════════════════════════════════════════════════════════════════════
    // Constants and platform gating
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void MessageLimits_MatchUpstreamConstants()
    {
        // PAGEANT_MAX_MSGLEN (agent.c:337) with room for the 4-byte prefix.
        Assert.Equal(8192, PageantIpc.MaxMessageLength);
        Assert.Equal(8188, PageantIpc.MaxPayloadLength);
    }

    [Fact]
    public async Task TryCreate_IsWindowsOnly()
    {
        var transport = PageantAgentTransport.TryCreate();

        if (!OperatingSystem.IsWindows())
        {
            Assert.Null(transport);
            return;
        }

        // Constructing the transport must not touch any native API; only
        // connecting does, so this is safe even with no agent running.
        Assert.NotNull(transport);
        await transport.DisposeAsync();
    }

    // ════════════════════════════════════════════════════════════════════════
    // Connect / disconnect lifecycle
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Connect_NoPageantWindow_ThrowsAgentProtocol()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: false);
        await using var transport = new PageantAgentTransport(channel);

        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.ConnectAsync(cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("failed connecting agent", ex.Message);
        Assert.Equal(1, channel.FindWindowCalls);

        // A failed connect must not leave the transport usable.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => transport.TransactAsync(new byte[] { 1 }, new ArrayBufferWriter<byte>(), cancellationToken));
    }

    [Fact]
    public async Task Connect_WindowPresent_SucceedsThenRejectsSecondConnect()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);

        await transport.ConnectAsync(cancellationToken);
        Assert.Equal(1, channel.FindWindowCalls);

        // The window is only probed once per connect; transactions do their own
        // lookup inside the channel.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => transport.ConnectAsync(cancellationToken));
        Assert.Equal(1, channel.FindWindowCalls);
    }

    [Fact]
    public async Task Connect_AfterFailedConnect_CanRetry()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: false);
        await using var transport = new PageantAgentTransport(channel);

        await Assert.ThrowsAsync<SshException>(() => transport.ConnectAsync(cancellationToken));

        // Pageant may have been started in between; a retry must probe again.
        channel.WindowPresent = true;
        await transport.ConnectAsync(cancellationToken);
        Assert.Equal(2, channel.FindWindowCalls);
    }

    [Fact]
    public async Task Connect_AfterDisconnect_Reconnects()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);

        await transport.ConnectAsync(cancellationToken);
        await transport.DisconnectAsync(cancellationToken);
        await transport.ConnectAsync(cancellationToken);

        Assert.Equal(2, channel.FindWindowCalls);
    }

    [Fact]
    public async Task Connect_AfterDispose_ThrowsObjectDisposed()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        var transport = new PageantAgentTransport(channel);
        await transport.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => transport.ConnectAsync(cancellationToken));
    }

    [Fact]
    public async Task Disconnect_IsIdempotent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);

        await transport.ConnectAsync(cancellationToken);
        await transport.DisconnectAsync(cancellationToken);
        await transport.DisconnectAsync(cancellationToken);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => transport.TransactAsync(new byte[] { 1 }, new ArrayBufferWriter<byte>(), cancellationToken));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Transactions
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Transact_PassesPayloadThroughAndWritesResponseVerbatim()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        channel.Enqueue([12, 0, 0, 0, 0]);
        await using var transport = new PageantAgentTransport(channel);
        await transport.ConnectAsync(cancellationToken);

        var writer = new ArrayBufferWriter<byte>();
        await transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken);

        // The transport frames nothing: the payload arrives whole and the
        // response is written whole (the prefix lives in the channel, because
        // it is part of the mapping layout Pageant reads).
        Assert.Single(channel.Requests);
        Assert.Equal([11], channel.Requests[0]);
        Assert.Equal([12, 0, 0, 0, 0], writer.WrittenSpan.ToArray());
    }

    [Fact]
    public async Task Transact_PayloadAtLimit_IsAccepted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        channel.Enqueue([12]);
        await using var transport = new PageantAgentTransport(channel);
        await transport.ConnectAsync(cancellationToken);

        byte[] request = new byte[PageantIpc.MaxPayloadLength];
        var writer = new ArrayBufferWriter<byte>();
        await transport.TransactAsync(request, writer, cancellationToken);

        Assert.Single(channel.Requests);
        Assert.Equal(request.Length, channel.Requests[0].Length);
    }

    [Fact]
    public async Task Transact_PayloadOverLimit_ThrowsInvalWithoutTouchingChannel()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);
        await transport.ConnectAsync(cancellationToken);

        byte[] request = new byte[PageantIpc.MaxPayloadLength + 1];
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.TransactAsync(request, new ArrayBufferWriter<byte>(), cancellationToken));

        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
        Assert.Contains("8192", ex.Message);
        Assert.Empty(channel.Requests);
    }

    [Fact]
    public async Task Transact_BeforeConnect_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => transport.TransactAsync(new byte[] { 11 }, new ArrayBufferWriter<byte>(), cancellationToken));
        Assert.Empty(channel.Requests);
    }

    [Fact]
    public async Task Transact_ChannelFailure_PropagatesAndLeavesWriterEmpty()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true)
        {
            TransactFailure = new SshException(SshErrorCode.AgentProtocol, "found no pageant"),
        };
        await using var transport = new PageantAgentTransport(channel);
        await transport.ConnectAsync(cancellationToken);

        var writer = new ArrayBufferWriter<byte>();
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Equal(0, writer.WrittenCount);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Cancellation
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Connect_PreCanceled_DoesNotProbeWindow()
    {
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => transport.ConnectAsync(new CancellationToken(canceled: true)));

        Assert.Equal(0, channel.FindWindowCalls);
    }

    [Fact]
    public async Task Transact_PreCanceled_DoesNotTouchChannel()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        await using var transport = new PageantAgentTransport(channel);
        await transport.ConnectAsync(cancellationToken);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => transport.TransactAsync(new byte[] { 11 }, new ArrayBufferWriter<byte>(), new CancellationToken(canceled: true)));

        Assert.Empty(channel.Requests);
    }

    /// <summary>
    /// The native round trip cannot be interrupted, so cancellation releases
    /// the caller while the worker is still blocked — and the worker keeps the
    /// request, the mapping, and the message data alive until it returns,
    /// because Pageant may still act on them. The late response never reaches
    /// the writer.
    /// </summary>
    [Fact]
    public async Task Transact_CanceledWhileNativeCallIsRunning_ReleasesCallerAndDiscardsLateResponse()
    {
        var channel = new FakeChannel(windowPresent: true);
        channel.Enqueue([12]);
        channel.ReleaseTransact = new ManualResetEventSlim(initialState: false);
        await using var transport = new PageantAgentTransport(channel);

        using var cts = new CancellationTokenSource();
        await transport.ConnectAsync(cts.Token);

        var writer = new ArrayBufferWriter<byte>();
        Task transaction = transport.TransactAsync(new byte[] { 11 }, writer, cts.Token);

        // Wait until the worker is inside the native call, then cancel.
        Assert.True(channel.EnteredTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        await cts.CancelAsync();

        // The caller is released while the worker is still blocked.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transaction);
        Assert.False(channel.ExitedTransact.IsSet);
        Assert.Equal(0, writer.WrittenCount);

        // Releasing the worker lets it finish on its own; its response is
        // discarded rather than written.
        channel.ReleaseTransact.Set();
        Assert.True(channel.ExitedTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        Assert.Equal(0, writer.WrittenCount);
    }

    /// <summary>
    /// A worker abandoned by cancellation can still fault later (Pageant may
    /// fail or the window may vanish). That late fault is observed rather than
    /// left to the unobserved-task handler, and it does not poison the
    /// transport: the next transaction starts from a clean slate.
    /// </summary>
    [Fact]
    public async Task Transact_CanceledWorkerFailsLater_NextTransactionStillSucceeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var gate = new ManualResetEventSlim(initialState: false);
        var channel = new FakeChannel(windowPresent: true)
        {
            TransactFailure = new SshException(SshErrorCode.AgentProtocol, "found no pageant"),
            ReleaseTransact = gate,
        };

        await using var transport = new PageantAgentTransport(channel);
        using var cts = new CancellationTokenSource();
        await transport.ConnectAsync(cts.Token);

        var abandonedWriter = new ArrayBufferWriter<byte>();
        Task abandoned = transport.TransactAsync(new byte[] { 11 }, abandonedWriter, cts.Token);

        Assert.True(channel.EnteredTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => abandoned);

        // Let the abandoned worker run into its failure, then make the next
        // transaction behave normally. The failed worker never dequeued a
        // response, so the queue is still clean.
        channel.ReleaseTransact = null;
        gate.Set();
        Assert.True(channel.ExitedTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));

        channel.TransactFailure = null;
        channel.Enqueue([12, 34]);

        var writer = new ArrayBufferWriter<byte>();
        await transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken);

        Assert.Equal([12, 34], writer.WrittenSpan.ToArray());
        Assert.Equal(0, abandonedWriter.WrittenCount);
    }

    /// <summary>
    /// A transaction already in flight keeps its own state: disposing the
    /// transport must not corrupt or abort the worker, which owns and releases
    /// the mapping it created.
    /// </summary>
    [Fact]
    public async Task Transact_DisposedWhileNativeCallIsRunning_StillCompletes()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        channel.Enqueue([12, 9]);
        channel.ReleaseTransact = new ManualResetEventSlim(initialState: false);
        var transport = new PageantAgentTransport(channel);
        await transport.ConnectAsync(cancellationToken);

        var writer = new ArrayBufferWriter<byte>();
        Task transaction = transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken);

        Assert.True(channel.EnteredTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        await transport.DisposeAsync();
        channel.ReleaseTransact.Set();

        await transaction;
        Assert.Equal([12, 9], writer.WrittenSpan.ToArray());
    }

    // ════════════════════════════════════════════════════════════════════════
    // Managed timeout
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A native round trip that outlasts the transport's timeout is abandoned,
    /// not interrupted: the caller gets an AgentProtocol failure while the
    /// worker is still inside the channel, because the receiver can reach the
    /// request state only while that call is running. The late response never
    /// reaches the writer.
    /// </summary>
    [Fact]
    public async Task Transact_NativeCallOutlastsTimeout_ReleasesCallerAndDiscardsLateResponse()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var channel = new FakeChannel(windowPresent: true);
        channel.Enqueue([12]);
        var gate = new ManualResetEventSlim(initialState: false);
        channel.ReleaseTransact = gate;
        await using var transport = new PageantAgentTransport(channel, TimeSpan.FromMilliseconds(100));
        await transport.ConnectAsync(cancellationToken);

        var writer = new ArrayBufferWriter<byte>();
        long startedAt = Stopwatch.GetTimestamp();
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken));
        TimeSpan elapsed = Stopwatch.GetElapsedTime(startedAt);

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("did not answer within 100 ms", ex.Message);

        // Generous ceiling: the point is that the timeout releases the caller,
        // not that it elapses at an exact millisecond.
        Assert.True(elapsed < TimeSpan.FromSeconds(30), $"The timeout took {elapsed}.");

        // The worker is still inside the channel, which owns the mapping and
        // the message data until it returns.
        Assert.True(channel.EnteredTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        Assert.False(channel.ExitedTransact.IsSet);
        Assert.Equal(0, writer.WrittenCount);

        // Releasing the worker lets it finish on its own; its response is
        // discarded rather than written.
        gate.Set();
        Assert.True(channel.ExitedTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        Assert.Equal(0, writer.WrittenCount);
    }

    /// <summary>
    /// A worker abandoned by the transport timeout can still fault later
    /// (Pageant may fail or the window may vanish). That late fault is observed
    /// rather than left to the unobserved-task handler, and it does not poison
    /// the transport: the next transaction starts from a clean slate.
    /// </summary>
    [Fact]
    public async Task Transact_TimedOutWorkerFailsLater_NextTransactionStillSucceeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var gate = new ManualResetEventSlim(initialState: false);
        var channel = new FakeChannel(windowPresent: true)
        {
            TransactFailure = new SshException(SshErrorCode.AgentProtocol, "found no pageant"),
            ReleaseTransact = gate,
        };

        await using var transport = new PageantAgentTransport(channel, TimeSpan.FromMilliseconds(100));
        await transport.ConnectAsync(cancellationToken);

        var abandonedWriter = new ArrayBufferWriter<byte>();
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.TransactAsync(new byte[] { 11 }, abandonedWriter, cancellationToken));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);

        // Let the abandoned worker run into its failure, then make the next
        // transaction behave normally. The failed worker never dequeued a
        // response, so the queue is still clean.
        channel.ReleaseTransact = null;
        gate.Set();
        Assert.True(channel.ExitedTransact.Wait(
            TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));

        channel.TransactFailure = null;
        channel.Enqueue([12, 34]);

        var writer = new ArrayBufferWriter<byte>();
        await transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken);

        Assert.Equal([12, 34], writer.WrittenSpan.ToArray());
        Assert.Equal(0, abandonedWriter.WrittenCount);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Outstanding-request slot
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A native send that cannot be interrupted keeps its slot after its caller
    /// is released, so the next request waits for it and starts only once the
    /// abandoned worker has returned — retries cannot pile up native sends.
    /// </summary>
    [Fact]
    public async Task Transact_QueuedBehindAbandonedWorker_StartsOnlyAfterItReturns()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var gate = new ManualResetEventSlim(initialState: false);
        var channel = new FakeChannel(windowPresent: true) { ReleaseTransact = gate };
        channel.Enqueue([12, 34]);   // Dequeued by the abandoned worker, discarded.
        channel.Enqueue([12, 35]);   // Dequeued by the queued request.
        await using var transport = new PageantAgentTransport(channel);
        using var firstCts = new CancellationTokenSource();
        await transport.ConnectAsync(cancellationToken);

        var firstWriter = new ArrayBufferWriter<byte>();
        Task first = transport.TransactAsync(new byte[] { 11 }, firstWriter, firstCts.Token);
        Assert.True(channel.EnteredTransact.Wait(TimeSpan.FromSeconds(10), cancellationToken));
        await firstCts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.Equal(0, firstWriter.WrittenCount);

        var secondWriter = new ArrayBufferWriter<byte>();
        Task second = transport.TransactAsync(new byte[] { 11 }, secondWriter, cancellationToken);

        // The queued caller waits for the outstanding native send: if a second
        // send started it would register its request immediately.
        await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken);
        Assert.Single(channel.Requests);
        Assert.False(second.IsCompleted);

        // Releasing the receiver lets the abandoned worker return, which hands
        // the slot to the queued request.
        gate.Set();
        await second.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);

        Assert.Equal([12, 35], secondWriter.WrittenSpan.ToArray());
        Assert.Equal(2, channel.Requests.Count);
    }

    /// <summary>
    /// A caller that queues behind an outstanding send is released by the same
    /// timeout instead of waiting indefinitely, and no native send is started
    /// for it.
    /// </summary>
    [Fact]
    public async Task Transact_QueuedBehindAbandonedWorker_TimesOutWithoutStartingASend()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var gate = new ManualResetEventSlim(initialState: false);
        var channel = new FakeChannel(windowPresent: true) { ReleaseTransact = gate };
        channel.Enqueue([12]);
        await using var transport = new PageantAgentTransport(channel, TimeSpan.FromMilliseconds(100));
        await transport.ConnectAsync(cancellationToken);

        var firstWriter = new ArrayBufferWriter<byte>();
        Task first = transport.TransactAsync(new byte[] { 11 }, firstWriter, cancellationToken);

        // The first caller is already released by its timeout while its worker
        // is still inside the channel.
        SshException firstEx = await Assert.ThrowsAsync<SshException>(() => first);
        Assert.Contains("did not answer within 100 ms", firstEx.Message);
        Assert.False(channel.ExitedTransact.IsSet);

        var secondWriter = new ArrayBufferWriter<byte>();
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.TransactAsync(new byte[] { 11 }, secondWriter, cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("still outstanding", ex.Message);
        Assert.Single(channel.Requests);
        Assert.Equal(0, secondWriter.WrittenCount);

        // Release the abandoned worker so the test leaves nothing blocked.
        gate.Set();
        Assert.True(channel.ExitedTransact.Wait(TimeSpan.FromSeconds(10), cancellationToken));
    }

    /// <summary>
    /// A queued caller can cancel while it waits for the outstanding send; the
    /// slot it never received is not lost to the worker that still holds it.
    /// </summary>
    [Fact]
    public async Task Transact_QueuedBehindAbandonedWorker_CanceledWhileWaiting_DoesNotStartASend()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var gate = new ManualResetEventSlim(initialState: false);
        var channel = new FakeChannel(windowPresent: true) { ReleaseTransact = gate };
        channel.Enqueue([12]);
        await using var transport = new PageantAgentTransport(channel);
        using var firstCts = new CancellationTokenSource();
        using var secondCts = new CancellationTokenSource();
        await transport.ConnectAsync(cancellationToken);

        var firstWriter = new ArrayBufferWriter<byte>();
        Task first = transport.TransactAsync(new byte[] { 11 }, firstWriter, firstCts.Token);
        Assert.True(channel.EnteredTransact.Wait(TimeSpan.FromSeconds(10), cancellationToken));
        await firstCts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);

        var secondWriter = new ArrayBufferWriter<byte>();
        Task second = transport.TransactAsync(new byte[] { 11 }, secondWriter, secondCts.Token);
        await secondCts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);

        Assert.Single(channel.Requests);
        Assert.Equal(0, secondWriter.WrittenCount);

        // Release the abandoned worker so the test leaves nothing blocked.
        gate.Set();
        Assert.True(channel.ExitedTransact.Wait(TimeSpan.FromSeconds(10), cancellationToken));
    }

    /// <summary>
    /// A request that queued behind the outstanding send must not start that
    /// send after the transport was torn down while it waited: the teardown is
    /// observed before the native call, not after.
    /// </summary>
    /// <param name="dispose">
    /// <c>true</c> to dispose the transport while the request is queued,
    /// <c>false</c> to disconnect it.
    /// </param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Transact_QueuedBehindAbandonedWorker_DoesNotStartAfterTeardown(bool dispose)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var gate = new ManualResetEventSlim(initialState: false);
        var channel = new FakeChannel(windowPresent: true) { ReleaseTransact = gate };
        channel.Enqueue([12]);
        var transport = new PageantAgentTransport(channel);
        using var firstCts = new CancellationTokenSource();
        await transport.ConnectAsync(cancellationToken);

        var firstWriter = new ArrayBufferWriter<byte>();
        Task first = transport.TransactAsync(new byte[] { 11 }, firstWriter, firstCts.Token);
        Assert.True(channel.EnteredTransact.Wait(TimeSpan.FromSeconds(10), cancellationToken));
        await firstCts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);

        var secondWriter = new ArrayBufferWriter<byte>();
        Task second = transport.TransactAsync(new byte[] { 11 }, secondWriter, cancellationToken);

        if (dispose)
        {
            await transport.DisposeAsync();
        }
        else
        {
            await transport.DisconnectAsync(cancellationToken);
        }

        // The abandoned worker still owns the slot; releasing it hands the slot
        // to the queued caller, which must observe the teardown instead of
        // starting a send.
        gate.Set();
        Assert.True(channel.ExitedTransact.Wait(TimeSpan.FromSeconds(10), cancellationToken));

        if (dispose)
        {
            await Assert.ThrowsAsync<ObjectDisposedException>(
                () => second.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken));
        }
        else
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => second.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken));
        }

        Assert.Single(channel.Requests);
        Assert.Equal(0, secondWriter.WrittenCount);
        await transport.DisposeAsync();
    }

    // ════════════════════════════════════════════════════════════════════════
    // Fake channel
    // ════════════════════════════════════════════════════════════════════════

    private sealed class FakeChannel : IPageantWindowChannel
    {
        private readonly Queue<byte[]> _responses = new();

        public FakeChannel(bool windowPresent)
        {
            WindowPresent = windowPresent;
        }

        public bool WindowPresent { get; set; }

        public int FindWindowCalls { get; private set; }

        public List<byte[]> Requests { get; } = [];

        public Exception? TransactFailure { get; set; }

        /// <summary>Set to block inside <see cref="Transact"/> until released.</summary>
        public ManualResetEventSlim? ReleaseTransact { get; set; }

        /// <summary>
        /// Set as soon as <see cref="Transact"/> is entered. Created eagerly so
        /// a test can start waiting before the worker is scheduled.
        /// </summary>
        public ManualResetEventSlim EnteredTransact { get; } = new(initialState: false);

        /// <summary>
        /// Set when <see cref="Transact"/> returns or throws — lets a test watch
        /// an abandoned worker finish on its own.
        /// </summary>
        public ManualResetEventSlim ExitedTransact { get; } = new(initialState: false);

        public void Enqueue(byte[] response) => _responses.Enqueue(response);

        public nint FindWindow()
        {
            FindWindowCalls++;
            return WindowPresent ? 1 : 0;
        }

        public byte[] Transact(ReadOnlyMemory<byte> requestPayload)
        {
            try
            {
                lock (Requests)
                {
                    Requests.Add(requestPayload.ToArray());
                }

                EnteredTransact.Set();
                ReleaseTransact?.Wait();

                if (TransactFailure is not null)
                {
                    throw TransactFailure;
                }

                return _responses.Dequeue();
            }
            finally
            {
                ExitedTransact.Set();
            }
        }
    }
}
