using BenchmarkDotNet.Attributes;

using LibSsh2CS.Benchmarks.Transport;
using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Buffered encrypted channel delivery, with compression and partial reads.</summary>
[MemoryDiagnoser]
[InvocationCount(1)]
public class BufferedChannelReadAllocBenchmarks
{
    private const int BatchSize = 64;

    [Params(256, 4096, 32700)]
    public int DataSize { get; set; }

    [Params("none", "zlib")]
    public string CompressionName { get; set; } = "none";

    [Params(false, true)]
    public bool PartialReads { get; set; }

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;
    private PacketWriter _server = null!;
    private byte[] _buffer = null!;

    [IterationSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 4);
        _channel = _h.CreateChannel();
        _buffer = new byte[DataSize];
        _server = new PacketWriter(_h.ServerWriter);
        (ICipher decrypt, IMac readMac) = TransportSetup.CreateCipherAndMac("aes256-gcm@openssh.com", null, false);
        (ICipher encrypt, IMac writeMac) = TransportSetup.CreateCipherAndMac("aes256-gcm@openssh.com", null, true);
        _h.Queue.Reader.SetInboundKeys(decrypt, readMac,
            TransportSetup.CreateCompression(CompressionName, false), false, true);
        _server.SetOutboundKeysAsync(encrypt, writeMac,
            TransportSetup.CreateCompression(CompressionName, true), false, true, CancellationToken.None)
            .GetAwaiter().GetResult();
        byte[] payload = ChannelBenchmarkHarness.BuildChannelDataPayload(_channel.LocalId,
            DataGenerator.Create(DataShape.Compressible, DataSize));
        _server.WritePacketAsync(PacketType.ChannelData, payload).GetAwaiter().GetResult();
        ReadOne().GetAwaiter().GetResult();
        for (int i = 0; i < BatchSize; i++)
        {
            _server.WritePacketAsync(PacketType.ChannelData, payload).GetAwaiter().GetResult();
        }
    }

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public async Task<int> ReadChannels()
    {
        int total = 0;
        for (int i = 0; i < BatchSize; i++)
        {
            total += await ReadOne().ConfigureAwait(false);
        }
        return total;
    }

    private async ValueTask<int> ReadOne()
    {
        int total = 0;
        while (total < DataSize)
        {
            int length = Math.Min(DataSize - total, PartialReads ? (DataSize + 3) / 4 : DataSize);
            total += await _channel.ReadAsync(_buffer.AsMemory(total, length)).ConfigureAwait(false);
        }
        return total;
    }

    [IterationCleanup]
    public void Cleanup()
    {
        _h.Dispose();
        _h.Queue.Reader.DisposeAsync().GetAwaiter().GetResult();
        _h.ClientWriter.DisposeAsync().GetAwaiter().GetResult();
        _server.DisposeAsync().GetAwaiter().GetResult();
    }
}
