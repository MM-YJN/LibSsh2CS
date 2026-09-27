using System.Buffers.Binary;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Measures single/multiple-type waits against stashed or prebuffered packets.</summary>
/// <remarks>Compares deadline-enabled waits with disabled-deadline controls.</remarks>
[MemoryDiagnoser]
[BenchmarkCategory("typed-wait")]
[InvocationCount(1)]
public class TypedWaitAllocBenchmarks
{
    /// <summary><c>none</c> = CancellationToken.None; <c>cancellable</c> = live token.</summary>
    [Params("none", "cancellable")]
    public string TokenMode { get; set; } = "none";

    /// <summary>Whether the queue's read deadline (and thus the scope) is active.</summary>
    [Params(true, false)]
    public bool UseTimeout { get; set; }

    [Params(false, true)]
    public bool SingleType { get; set; }

    [Params("buffered", "stashed", "inline")]
    public string InputKind { get; set; } = "buffered";

    private static readonly int[] s_channelDataTypes = { PacketType.ChannelExtendedData, PacketType.ChannelData };

    private ChannelBenchmarkHarness _h = null!;
    private byte[] _wire = null!;
    private CancellationTokenSource _liveCts = null!;

    [IterationSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(
            pipeMegabytes: 4,
            readTimeout: UseTimeout ? TimeSpan.FromMinutes(10) : null);

        byte[] body = new byte[1 + 4 + 4 + 32];
        body[0] = (byte)PacketType.ChannelData;
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(1, 4), 0u);
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(5, 4), 32u);
        _wire = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelData, body);

        _liveCts = new CancellationTokenSource();
        for (int i = 0; i <= BatchSize; i++)
        {
            if (InputKind == "inline")
            {
                _h.ServerWriter.WriteAsync(s_ignore).GetAwaiter().GetResult();
            }
            _h.ServerWriter.WriteAsync(_wire).GetAwaiter().GetResult();
        }
        if (InputKind == "stashed")
        {
            _h.ServerWriter.WriteAsync(s_marker).GetAwaiter().GetResult();
#pragma warning disable IDE0008 // Keep identical benchmark source for Task and ValueTask baselines.
            var stash = _h.Queue.WaitForTypeAsync(PacketType.ChannelSuccess);
#pragma warning restore IDE0008
            if (!stash.IsCompletedSuccessfully)
            {
                throw new InvalidOperationException("Expected synchronous stashing.");
            }
            stash.GetAwaiter().GetResult().Dispose();
        }
#pragma warning disable IDE0008 // Keep identical benchmark source for Task and ValueTask baselines.
        var warmup = SingleType
            ? _h.Queue.WaitForTypeAsync(PacketType.ChannelData)
            : _h.Queue.WaitForTypesAsync(s_channelDataTypes);
#pragma warning restore IDE0008
        if (!warmup.IsCompletedSuccessfully)
        {
            throw new InvalidOperationException("Expected a synchronous typed wait.");
        }
        warmup.GetAwaiter().GetResult().Dispose();
    }

    [IterationCleanup]
    public void Cleanup()
    {
        _liveCts.Dispose();
        _h.Dispose();
        _h.Queue.Reader.DisposeAsync().GetAwaiter().GetResult();
        _h.ClientWriter.DisposeAsync().GetAwaiter().GetResult();
        _h.ServerReader.DisposeAsync().GetAwaiter().GetResult();
    }

    // Enough calls per iteration to stabilize tiered compilation and sub-microsecond stash timings.
    // The complete cleartext batch remains below the pipe's 4 MiB backpressure threshold.
    private const int BatchSize = 16384;
    private static readonly byte[] s_ignore = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.Ignore, [(byte)PacketType.Ignore]);
    private static readonly byte[] s_marker = ChannelBenchmarkHarness.BuildCleartextPacket(
        PacketType.ChannelSuccess, [(byte)PacketType.ChannelSuccess]);

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public async Task<int> WaitForOnePacket()
    {
        CancellationToken token = TokenMode == "cancellable" ? _liveCts.Token : CancellationToken.None;
        int length = 0;
        for (int i = 0; i < BatchSize; i++)
        {
            using RawPacket pkt = SingleType
                ? await _h.Queue.WaitForTypeAsync(PacketType.ChannelData, token).ConfigureAwait(false)
                : await _h.Queue.WaitForTypesAsync(s_channelDataTypes, token).ConfigureAwait(false);
            length += pkt.Payload.Length;
        }
        return length;
    }
}
