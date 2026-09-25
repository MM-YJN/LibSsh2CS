using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Isolates the cooperative-pumper's parked-wait registration: a wait that
/// cannot take the pump lock immediately registers a wait handle and (when a
/// cancellation token is supplied) a cancellation registration before awaiting.
/// </summary>
/// <remarks>
/// <para>
/// A blocker (<see cref="ChannelRouter.PumpOneBatchForTestAsync"/>) takes the
/// pump lock once in setup and stays parked on the empty inbound pipe for the
/// whole run, so every measured wait fails the non-blocking lock attempt and
/// registers its callback before parking. <see cref="ParkWaiters"/> starts
/// <see cref="WaiterCount"/> such waits and returns without waking them: the
/// allocations made synchronously before each <c>await</c> are exactly the
/// registration cost, and because no waiter is resumed during measurement, no
/// continuation can migrate off the benchmark thread and skew the per-thread
/// allocation figure. (<c>TaskCreationOptions.RunContinuationsAsynchronously</c>
/// sends wake continuations to the pool, so a benchmark that awaits a wake
/// cannot use per-thread allocation counting reliably.)
/// </para>
/// <para>
/// The <c>none</c> mode is the headline case: <c>CancellationToken.None</c>
/// cannot cancel, yet the lambda capture closure + delegate for
/// <c>Register</c> are still allocated per wait. The <c>cancellable</c> mode
/// quantifies the real registration path
/// (<see cref="CancellationTokenRegistration"/> bookkeeping).
/// </para>
/// <para>
/// One invocation per iteration is enforced with <see cref="InvocationCountAttribute"/>
/// so parked waiters do not accumulate across invocations:
/// <see cref="GlobalCleanup"/> cancels the cancellable tokens (completing those
/// waiters through the registration under test) and then completes the inbound
/// pipe, which releases the blocker and signals every remaining waiter.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("waiter")]
[InvocationCount(1)]
public class WaiterRegisterAllocBenchmarks
{
    /// <summary><c>none</c> = CancellationToken.None; <c>cancellable</c> = live tokens.</summary>
    [Params("none", "cancellable")]
    public string TokenMode { get; set; } = "none";

    /// <summary>Parked waiters per invocation.</summary>
    [Params(8)]
    public int WaiterCount { get; set; } = 8;

    // Pre-sized so List growth never lands in the measured region (BDN runs
    // many iterations and each parks WaiterCount more).
    private readonly List<Task<bool>> _parked = new(capacity: 4096);

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;
    private CancellationTokenSource _waitCts = null!;
    private CancellationToken[] _tokens = null!;
    private Task _blocker = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 1);
        _h.Queue.ReadTimeout = TimeSpan.Zero;
        _channel = _h.CreateChannel();

        _waitCts = new CancellationTokenSource();
        _tokens = new CancellationToken[WaiterCount];
        for (int i = 0; i < WaiterCount; i++)
        {
            _tokens[i] = TokenMode == "cancellable" ? _waitCts.Token : CancellationToken.None;
        }

        // Take the pump lock once and leave the blocker parked on the empty
        // pipe. Every measured wait then fails its non-blocking lock attempt.
        _blocker = _h.Router.PumpOneBatchForTestAsync(CancellationToken.None);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        // Complete the cancellable waiters through the registration under test.
        await _waitCts.CancelAsync().ConfigureAwait(false);

        // Release the blocker (its pipe read fails) and signal every remaining
        // waiter so none is left parked.
        await _h.ServerWriter.CompleteAsync().ConfigureAwait(false);

        try
        {
            await Task.WhenAll(_parked).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        try
        {
            await _blocker.ConfigureAwait(false);
        }
        catch (SshException)
        {
        }

        _waitCts.Dispose();
        _h.Dispose();
    }

    [Benchmark]
    public void ParkWaiters()
    {
        for (int i = 0; i < WaiterCount; i++)
        {
            // The async method runs synchronously up to its await: the wait
            // handle, capture closure, delegate, and cancellation registration
            // all allocate on this thread before it parks.
            _parked.Add(_h.Router.WaitForStateChangeAsync(_channel, canProceed: null, _tokens[i]));
        }
    }
}
