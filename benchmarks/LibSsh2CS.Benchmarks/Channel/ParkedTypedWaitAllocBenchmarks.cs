using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Isolates allocations before a typed wait suspends, excluding producer and wakeup work.</summary>
[MemoryDiagnoser]
[InvocationCount(1)]
public class ParkedTypedWaitAllocBenchmarks
{
    private const int BatchSize = 64;
    private static readonly int[] s_types = [PacketType.ChannelSuccess];
    private static readonly byte[] s_reply = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelSuccess, [(byte)PacketType.ChannelSuccess]);

    [Params(false, true)]
    public bool UseTimeout { get; set; }

    [Params(false, true)]
    public bool SingleType { get; set; }

    [Params("none", "cancellable")]
    public string TokenMode { get; set; } = "none";

    private readonly ChannelBenchmarkHarness[] _harnesses = new ChannelBenchmarkHarness[BatchSize];
    private readonly ValueTask<RawPacket>[] _waits = new ValueTask<RawPacket>[BatchSize];
    private CancellationTokenSource _cts = null!;

    [IterationSetup]
    public void Setup()
    {
        _cts = new CancellationTokenSource();
        for (int i = 0; i < BatchSize; i++)
        {
            _harnesses[i] = new(readTimeout: UseTimeout ? TimeSpan.FromSeconds(60) : null);
        }
    }

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public void ParkWaits()
    {
        CancellationToken token = TokenMode == "cancellable" ? _cts.Token : CancellationToken.None;
        for (int i = 0; i < BatchSize; i++)
        {
            PacketQueue queue = _harnesses[i].Queue;
            _waits[i] = SingleType ? queue.WaitForTypeAsync(PacketType.ChannelSuccess, token) : queue.WaitForTypesAsync(s_types, token);
            if (_waits[i].IsCompleted)
            {
                throw new InvalidOperationException("Expected a suspended typed wait.");
            }
        }
    }

    [IterationCleanup]
    public void Cleanup()
    {
        for (int i = 0; i < BatchSize; i++)
        {
            ChannelBenchmarkHarness h = _harnesses[i];
            h.ServerWriter.WriteAsync(s_reply).GetAwaiter().GetResult();
            _waits[i].AsTask().GetAwaiter().GetResult().Dispose();
            h.Dispose();
            h.Queue.Reader.DisposeAsync().GetAwaiter().GetResult();
            h.ClientWriter.DisposeAsync().GetAwaiter().GetResult();
            h.ServerReader.DisposeAsync().GetAwaiter().GetResult();
        }
        _cts.Dispose();
    }
}
