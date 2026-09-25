using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Benchmarks.Transport;
using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Isolates the inbound channel-data path: the router's pump (packet read,
/// payload extraction, routing into the channel FIFO) followed by
/// <see cref="SshChannel.ReadAsync"/> draining the data into the caller's
/// buffer.
/// </summary>
/// <remarks>
/// <para>
/// Each invocation writes one pre-framed cleartext <c>SSH_MSG_CHANNEL_DATA</c>
/// packet into the client's inbound pipe and then reads <see cref="DataSize"/>
/// bytes back. Feeding on the benchmark thread keeps the read path synchronous
/// and deterministic (the packet is always buffered, so pipe completions and
/// continuations stay on the benchmark thread), which is required for reliable
/// per-thread allocation attribution. The feed itself is constant and
/// allocation-light (a pooled pipe segment), so before/after deltas isolate the
/// receive path.
/// </para>
/// <para>
/// Allocation targets in this path: one payload array per packet
/// (<c>PacketReader.ExtractPayload</c>, the ownership-contract floor) plus the
/// second array that <c>SshChannel.DeliverDataPayload</c> allocates to copy the
/// data body out of that payload. The benchmark exists to quantify the second
/// copy (and to confirm the floor is unchanged after removing it): the
/// <c>32700</c> case currently allocates ~64 KB per packet, of which ~32 KB is
/// the removable copy.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("channel-read")]
public class ChannelReadAllocBenchmarks
{
    /// <summary>Bytes of channel data per packet.</summary>
    [Params(256, 4096, 32700)]
    public int DataSize { get; set; }

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;
    private byte[] _buffer = null!;
    private byte[] _wire = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 4);
        _channel = _h.CreateChannel();
        _buffer = new byte[DataSize];

        byte[] data = DataGenerator.Create(DataShape.Compressible, DataSize);
        _wire = ChannelBenchmarkHarness.BuildCleartextPacket(
            PacketType.ChannelData,
            ChannelBenchmarkHarness.BuildChannelDataPayload(_channel.LocalId, data));
    }

    [GlobalCleanup]
    public void Cleanup() => _h.Dispose();

    [Benchmark]
    public async Task<int> ReadChannelData()
    {
        await _h.ServerWriter.WriteAsync(_wire, CancellationToken.None).ConfigureAwait(false);
        await _h.ServerWriter.FlushAsync(CancellationToken.None).ConfigureAwait(false);

        int total = 0;
        while (total < _buffer.Length)
        {
            total += await _channel.ReadAsync(_buffer.AsMemory(total), CancellationToken.None)
                .ConfigureAwait(false);
        }

        return total;
    }
}
