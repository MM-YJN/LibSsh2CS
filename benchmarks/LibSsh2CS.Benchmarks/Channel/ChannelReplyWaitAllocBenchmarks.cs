using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Isolates typed channel replies, including genuinely suspended waits.</summary>
/// <remarks>Suspended cases include producer writes and continuation scheduling;
/// their allocations are not a thread-local measure of the waiter alone.</remarks>
[MemoryDiagnoser]
[InvocationCount(1)]
public class ChannelReplyWaitAllocBenchmarks
{
    // Amortize iteration overhead and warm tiered code before measuring small requests.
    private const int BatchSize = 1024;
    private static readonly int[] s_replyTypes = [PacketType.ChannelSuccess];

    [Params("stashed", "buffered", "suspended")]
    public string InputKind { get; set; } = "stashed";

    [Params(false, true)]
    public bool Cancellable { get; set; }

    private ChannelBenchmarkHarness _h = null!;
    private readonly SshChannel[] _channels = new SshChannel[BatchSize];
    private readonly byte[][] _replies = new byte[BatchSize][];
    private CancellationTokenSource _cts = null!;

    [IterationSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness();
        _cts = new CancellationTokenSource();
        for (int i = 0; i < BatchSize; i++)
        {
            _channels[i] = _h.CreateChannel();
            _replies[i] = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelSuccess,
                ChannelBenchmarkHarness.BuildChannelSuccessPayload(_channels[i].LocalId));
            if (InputKind != "suspended")
            {
                _h.ServerWriter.WriteAsync(_replies[i]).GetAwaiter().GetResult();
            }
        }
        if (InputKind == "stashed")
        {
            _h.PumpOneBatchAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
    }

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public async Task WaitForReplies()
    {
        CancellationToken token = Cancellable ? _cts.Token : CancellationToken.None;
        for (int i = 0; i < BatchSize; i++)
        {
            ValueTask<RawPacket> wait = AsValueTask(_h.Router.WaitForReplyAsync(_channels[i], s_replyTypes, token));
            if (InputKind == "suspended")
            {
                if (wait.IsCompleted)
                {
                    throw new InvalidOperationException("Expected a suspended reply wait.");
                }
                await _h.ServerWriter.WriteAsync(_replies[i], token).ConfigureAwait(false);
            }
            else if (!wait.IsCompletedSuccessfully)
            {
                throw new InvalidOperationException("Expected a synchronous reply wait.");
            }
            using RawPacket reply = await wait.ConfigureAwait(false);
            if (reply.Type != PacketType.ChannelSuccess)
            {
                throw new InvalidOperationException("Unexpected reply.");
            }
        }
    }

    // Normalize the benchmark's own state machine across the Task baseline and
    // ValueTask implementation, without allocating a Task through AsTask().
#pragma warning disable IDE0051 // The baseline and optimized library select different overloads.
    private static ValueTask<RawPacket> AsValueTask(Task<RawPacket> task) => new(task);
    private static ValueTask<RawPacket> AsValueTask(ValueTask<RawPacket> task) => task;
#pragma warning restore IDE0051

    [IterationCleanup]
    public void Cleanup()
    {
        _h.Dispose();
        _h.Queue.Reader.DisposeAsync().GetAwaiter().GetResult();
        _h.ClientWriter.DisposeAsync().GetAwaiter().GetResult();
        _h.ServerReader.DisposeAsync().GetAwaiter().GetResult();
        _cts.Dispose();
    }
}
