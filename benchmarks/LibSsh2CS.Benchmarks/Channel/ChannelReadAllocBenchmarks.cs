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
/// <remarks>Payload arrays are owned by the channel; its FIFO retains slices without another data copy.
/// Input is fed on the benchmark thread before reading so the operation completes synchronously.</remarks>
[MemoryDiagnoser]
[BenchmarkCategory("channel-read")]
public class ChannelReadAllocBenchmarks
{
    /// <summary>Bytes of channel data per packet.</summary>
    [Params(256, 4096, 32700)]
    public int DataSize { get; set; }

    [Params("stdout", "stderr", "merge")]
    public string ReadKind { get; set; } = "stdout";

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;
    private byte[] _buffer = null!;
    private byte[] _wire = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 4);
        _channel = _h.CreateChannel();
        if (ReadKind == "merge")
        {
            _channel.SetExtendedDataModeAsync(SshExtendedDataMode.Merge).GetAwaiter().GetResult();
        }
        _buffer = new byte[DataSize];

        byte[] data = DataGenerator.Create(DataShape.Compressible, DataSize);
        byte[] payload = ChannelBenchmarkHarness.BuildChannelDataPayload(_channel.LocalId, data);
        if (ReadKind != "stdout")
        {
            byte[] extended = new byte[payload.Length + 4];
            payload.AsSpan(0, 5).CopyTo(extended);
            extended[0] = (byte)PacketType.ChannelExtendedData;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(5), 1);
            payload.AsSpan(5).CopyTo(extended.AsSpan(9));
            payload = extended;
        }
        _wire = ChannelBenchmarkHarness.BuildCleartextPacket(payload[0], payload);
        if (!ReadChannelData().IsCompletedSuccessfully)
        {
            throw new InvalidOperationException("Expected a synchronous channel read.");
        }
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
            total += ReadKind == "stderr"
                ? await _channel.ReadStderrAsync(_buffer.AsMemory(total)).ConfigureAwait(false)
                : await _channel.ReadAsync(_buffer.AsMemory(total)).ConfigureAwait(false);
        }

        return total;
    }
}
