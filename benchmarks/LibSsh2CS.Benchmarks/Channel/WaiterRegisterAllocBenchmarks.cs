using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Measures registration before suspension, with no wakeups in the measured region.</summary>
/// <remarks>Each iteration has fresh waiters. Completion and resource disposal occur in cleanup.
/// Independent routers let global requests reach their cancellation callback without lock contention.</remarks>
[MemoryDiagnoser]
[BenchmarkCategory("waiter")]
[InvocationCount(1)]
public class WaiterRegisterAllocBenchmarks
{
    private const int BatchSize = 64;
    private static readonly int[] s_replyTypes = [PacketType.ChannelSuccess];

    [Params("none", "cancellable")]
    public string TokenMode { get; set; } = "none";

    [Params("state", "reply", "global")]
    public string WaitKind { get; set; } = "state";

    private readonly ChannelBenchmarkHarness[] _harnesses = new ChannelBenchmarkHarness[BatchSize];
    private readonly SshChannel[] _channels = new SshChannel[BatchSize];
    private readonly Task[] _parked = new Task[BatchSize];
    private readonly Task[] _blockers = new Task[BatchSize];
    private readonly byte[][] _replies = new byte[BatchSize][];
    private CancellationTokenSource _cts = null!;

    [IterationSetup]
    public void Setup()
    {
        _cts = new CancellationTokenSource();
        for (int i = 0; i < BatchSize; i++)
        {
            ChannelBenchmarkHarness h = _harnesses[i] = new();
            SshChannel channel = _channels[i] = h.CreateChannel();
            byte[] payload = WaitKind == "global"
                ? ChannelBenchmarkHarness.BuildRequestSuccessPayload()
                : ChannelBenchmarkHarness.BuildChannelSuccessPayload(channel.LocalId);
            _replies[i] = ChannelBenchmarkHarness.BuildCleartextPacket(payload[0], payload);
            _blockers[i] = h.PumpOneBatchAsync(CancellationToken.None);
        }
    }

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public void ParkWaiters()
    {
        CancellationToken token = TokenMode == "cancellable" ? _cts.Token : CancellationToken.None;
        for (int i = 0; i < BatchSize; i++)
        {
            ChannelRouter router = _harnesses[i].Router;
            _parked[i] = WaitKind switch
            {
                "state" => router.WaitForStateChangeAsync(_channels[i], canProceed: null, token),
                "reply" => WaitForReplyAsync(router, _channels[i], token),
                _ => router.SendGlobalRequestAsync("keepalive@libssh2.org", ReadOnlyMemory<byte>.Empty, true, token),
            };
            if (_parked[i].IsCompleted)
            {
                throw new InvalidOperationException("Expected a parked waiter.");
            }
        }
    }

    private static async Task WaitForReplyAsync(ChannelRouter router, SshChannel channel, CancellationToken token)
    {
        using RawPacket reply = await router.WaitForReplyAsync(channel, s_replyTypes, token).ConfigureAwait(false);
    }

    [IterationCleanup]
    public void Cleanup()
    {
        for (int i = 0; i < BatchSize; i++)
        {
            ChannelBenchmarkHarness h = _harnesses[i];
            h.ServerWriter.WriteAsync(_replies[i]).GetAwaiter().GetResult();
            _blockers[i].GetAwaiter().GetResult();
            _parked[i].GetAwaiter().GetResult();
            h.Dispose();
            h.Queue.Reader.DisposeAsync().GetAwaiter().GetResult();
            h.ClientWriter.DisposeAsync().GetAwaiter().GetResult();
            h.ServerReader.DisposeAsync().GetAwaiter().GetResult();
        }
        _cts.Dispose();
    }
}
