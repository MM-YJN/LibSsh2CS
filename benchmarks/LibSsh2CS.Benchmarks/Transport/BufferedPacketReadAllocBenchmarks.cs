using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>Measures reads of already-buffered sequential encrypted packets.</summary>
/// <remarks>Encryption, pipe feeding, key installation, and scratch warmup are outside measurement.</remarks>
[MemoryDiagnoser]
[BenchmarkCategory("buffered-read")]
[InvocationCount(1)]
public class BufferedPacketReadAllocBenchmarks
{
    private const int BatchSize = 64;

    [Params(256, 4096, 32700)]
    public int PayloadSize { get; set; }

    [Params("ctr-std", "ctr-etm", "gcm", "chacha")]
    public string FramingMode { get; set; } = "gcm";

    [Params("none", "zlib")]
    public string CompressionName { get; set; } = "none";

    private Pipe _pipe = null!;
    private PacketReader _reader = null!;
    private PacketWriter _writer = null!;

    [IterationSetup]
    public void Setup()
    {
        _pipe = TransportSetup.CreatePipe(4);
        _reader = new PacketReader(_pipe.Reader);
        _writer = new PacketWriter(_pipe.Writer);
        (string cipher, string? mac) = FramingMode switch
        {
            "ctr-std" => ("aes256-ctr", "hmac-sha2-256"),
            "ctr-etm" => ("aes256-ctr", "hmac-sha2-256-etm@openssh.com"),
            "gcm" => ("aes256-gcm@openssh.com", null),
            _ => ("chacha20-poly1305@openssh.com", null),
        };
        (ICipher decrypt, IMac readMac) = TransportSetup.CreateCipherAndMac(cipher, mac, false);
        (ICipher encrypt, IMac writeMac) = TransportSetup.CreateCipherAndMac(cipher, mac, true);
        _reader.SetInboundKeys(decrypt, readMac,
            TransportSetup.CreateCompression(CompressionName, false), false, true);
        _writer.SetOutboundKeysAsync(encrypt, writeMac,
            TransportSetup.CreateCompression(CompressionName, true), false, true, CancellationToken.None)
            .GetAwaiter().GetResult();
        byte[] payload = DataGenerator.Create(DataShape.Compressible, PayloadSize);
        payload[0] = (byte)PacketType.ChannelData;
        for (int i = 0; i <= BatchSize; i++)
        {
            _writer.WritePacketAsync(PacketType.ChannelData, payload).GetAwaiter().GetResult();
        }

        // Consume one valid packet to warm reader scratch and verify synchronous completion.
#pragma warning disable IDE0008 // Keep identical benchmark source for Task and ValueTask baselines.
        var warmup = _reader.ReadPacketAsync();
#pragma warning restore IDE0008
        if (!warmup.IsCompletedSuccessfully || warmup.GetAwaiter().GetResult().Payload.Length != PayloadSize)
        {
            throw new InvalidOperationException("Expected a complete buffered packet.");
        }
    }

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public async Task<int> ReadPackets()
    {
        int length = 0;
        for (int i = 0; i < BatchSize; i++)
        {
            RawPacket packet = await _reader.ReadPacketAsync().ConfigureAwait(false);
            length += packet.Payload.Length;
        }
        return length;
    }

    [IterationCleanup]
    public void Cleanup()
    {
        _reader.DisposeAsync().GetAwaiter().GetResult();
        _writer.DisposeAsync().GetAwaiter().GetResult();
        _pipe.Reader.Complete();
        _pipe.Writer.Complete();
    }
}
