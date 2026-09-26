using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Regression tests for read-timeout scoping: the read-deadline timer
/// callback in <c>PacketQueue.ReadTimeoutScope</c> can call
/// <see cref="CancellationTokenSource.Cancel"/> on a CTS that was already
/// disposed by a concurrently-finishing wait, throwing
/// <see cref="ObjectDisposedException"/> on a threadpool thread (unhandled →
/// process crash). The C reference (<c>_libssh2_packet_require</c>,
/// packet.c:1480-1533) polls single-threaded with no timer, so this is a
/// managed-only lifecycle hazard; the fix must make a late timer callback a
/// no-op.
/// </summary>
public class ReadTimeoutScopeTests
{
    [Fact]
    public async Task TimerCallback_AfterScopeDisposed_DoesNotThrow()
    {
        // A manual TimeProvider lets us fire the deadline timer callback
        // AFTER the scope has been disposed — the exact race where the
        // callback was already dispatched to the threadpool when Dispose ran
        // (ITimer.Dispose prevents future fires but not in-flight callbacks).
        var provider = new ManualTimerProvider();
        var pipe = new Pipe();
        var q = new PacketQueue(new PacketReader(pipe.Reader))
        {
            TimeProvider = provider,
            ReadTimeout = TimeSpan.FromMinutes(5),
        };

        using var cts = new CancellationTokenSource();
        Task<RawPacket> wait = q.WaitForTypeAsync(PacketType.KexInit, cts.Token).AsTask();

        // The scope (and its deadline timer) is created before the first read
        // awaits; wait for it so the scope definitely exists.
        ManualTimer timer = await provider.WaitForTimerAsync(TimeSpan.FromSeconds(5));

        // Cancel the wait: the read unwinds and the using disposes the scope.
        await cts.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(() => wait);

        // Fire the deadline callback as if it had already been dispatched.
        // Pre-fix this throws ObjectDisposedException (Cancel on the disposed
        // CTS); post-fix it is a no-op.
        timer.Fire();

        await pipe.Writer.CompleteAsync();
    }

    [Fact]
    public async Task TimerCallback_NormalFire_CancelsTheWait()
    {
        // Sanity: the deadline callback still works when the scope is alive —
        // firing it must cancel the linked token and time out the wait with
        // SshException(Timeout) (parity packet.c:1520-1526).
        var provider = new ManualTimerProvider();
        var pipe = new Pipe();
        var q = new PacketQueue(new PacketReader(pipe.Reader))
        {
            TimeProvider = provider,
            ReadTimeout = TimeSpan.FromMinutes(5),
        };

        Task<RawPacket> wait = q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken).AsTask();
        ManualTimer timer = await provider.WaitForTimerAsync(TimeSpan.FromSeconds(5));

        timer.Fire();

        SshException? ex = await Assert.ThrowsAsync<SshException>(() => wait);
        Assert.Equal(SshErrorCode.Timeout, ex.ErrorCode);

        await pipe.Writer.CompleteAsync();
    }

    /// <summary>
    /// A <see cref="TimeProvider"/> whose timers are manual — the test fires
    /// their callbacks itself, deterministically.
    /// </summary>
    private sealed class ManualTimerProvider : TimeProvider
    {
        private readonly TaskCompletionSource<ManualTimer> _timerCreated =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(callback, state);
            _timerCreated.TrySetResult(timer);
            return timer;
        }

        public async Task<ManualTimer> WaitForTimerAsync(TimeSpan timeout)
        {
            Task completed = await Task.WhenAny(_timerCreated.Task, Task.Delay(timeout));
            Assert.Same(_timerCreated.Task, completed);
            return await _timerCreated.Task;
        }
    }

    /// <summary>
    /// An <see cref="ITimer"/> that never fires on its own; the test invokes
    /// <see cref="Fire"/> to run the callback. <see cref="Dispose"/> is a
    /// no-op so the callback can be fired after disposal — the in-flight
    /// callback scenario.
    /// </summary>
    private sealed class ManualTimer : ITimer
    {
        private readonly TimerCallback _callback;
        private readonly object? _state;

        public ManualTimer(TimerCallback callback, object? state)
        {
            _callback = callback;
            _state = state;
        }

        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => default;

        public void Fire() => _callback(_state);
    }
}
