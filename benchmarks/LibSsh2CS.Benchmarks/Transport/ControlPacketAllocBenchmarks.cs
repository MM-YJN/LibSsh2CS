using System.Buffers.Binary;
using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>Compares temporary payload arrays with direct control framing using a drained pipe.</summary>
[MemoryDiagnoser]
public class ControlPacketAllocBenchmarks
{
    [Params(PacketType.ChannelEof, PacketType.ChannelClose, PacketType.ChannelFailure,
        PacketType.RequestFailure, PacketType.NewKeys)]
    public int Type { get; set; }

    private Pipe _pipe = null!;
    private PacketWriter _writer = null!;
    private bool HasRecipient => Type is PacketType.ChannelEof or PacketType.ChannelClose or PacketType.ChannelFailure;

    [GlobalSetup]
    public void Setup()
    {
        _pipe = new Pipe();
        _writer = new PacketWriter(_pipe.Writer);
    }

    [Benchmark(Baseline = true)]
    public Task PayloadArray()
    {
        byte[] payload = new byte[HasRecipient ? 5 : 1];
        payload[0] = (byte)Type;
        if (HasRecipient)
        {
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), 42);
        }
        return DrainAsync(_writer.WritePacketAsync(Type, payload));
    }

    [Benchmark]
    public Task DirectFraming() => DrainAsync(HasRecipient
        ? _writer.WriteChannelControlPacketAsync(Type, 42)
        : _writer.WriteControlPacketAsync(Type));

    private async Task DrainAsync(Task write)
    {
        await write.ConfigureAwait(false);
        if (!_pipe.Reader.TryRead(out ReadResult result))
        {
            throw new InvalidOperationException("Expected a complete packet.");
        }
        _pipe.Reader.AdvanceTo(result.Buffer.End);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _writer.DisposeAsync().ConfigureAwait(false);
        await _pipe.Writer.CompleteAsync().ConfigureAwait(false);
        await _pipe.Reader.CompleteAsync().ConfigureAwait(false);
    }
}
