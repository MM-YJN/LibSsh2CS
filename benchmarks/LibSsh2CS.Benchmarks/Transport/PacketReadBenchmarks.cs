using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>
/// Isolates <see cref="PacketReader.ReadPacketAsync"/> — the per-packet
/// inbound framing path (length recovery, decrypt, MAC/AEAD verify,
/// decompression, padding strip). A background producer feeds the pipe with
/// packets encrypted under the same deterministic keys, so every framing
/// family is exercised with realistic ciphertext.
/// </summary>
/// <remarks>
/// The producer runs on a separate thread; BenchmarkDotNet measures allocations
/// on the benchmark thread, so the reader's per-packet allocations (the ones
/// the hot-path optimization targets) are attributed cleanly.
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("read")]
public class PacketReadBenchmarks
{
    /// <summary>Payload size in bytes (including the leading type byte).</summary>
    [Params(256, 4096, 32700)]
    public int PayloadSize { get; set; }

    /// <summary>
    /// Framing family: <c>ctr-std</c> (AES-CTR + separate HMAC), <c>ctr-etm</c>
    /// (encrypt-then-MAC), <c>gcm</c> (AES-GCM AEAD), <c>chacha</c>
    /// (ChaCha20-Poly1305 AEAD).
    /// </summary>
    [Params("ctr-std", "ctr-etm", "gcm", "chacha")]
    public string FramingMode { get; set; } = "ctr-std";

    /// <summary>Negotiated compression wire name.</summary>
    [Params("none", "zlib")]
    public string CompressionName { get; set; } = "none";

    private Pipe _pipe = null!;
    private PacketReader _reader = null!;
    private PacketWriter _producerWriter = null!;
    private CancellationTokenSource _cts = null!;
    private Task _producerTask = null!;
    private byte[] _payload = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _payload = DataGenerator.Create(DataShape.Compressible, PayloadSize);
        _payload[0] = (byte)PacketType.ChannelData;

        _pipe = TransportSetup.CreatePipe();

        (string cipherName, string? macName) = ResolveFraming(FramingMode);

        // Reader side (decrypt).
        (ICipher cipher, IMac mac) = TransportSetup.CreateCipherAndMac(cipherName, macName, encrypt: false);
        ICompression decompression = TransportSetup.CreateCompression(CompressionName, compress: false);
        _reader = new PacketReader(_pipe.Reader);
        _reader.SetInboundKeys(
            cipher, mac, decompression,
            strictKex: false, compressionActive: decompression.Compresses);

        // Producer side (encrypt), same deterministic keys and payload sequence.
        (ICipher producerCipher, IMac producerMac) = TransportSetup.CreateCipherAndMac(cipherName, macName, encrypt: true);
        ICompression compression = TransportSetup.CreateCompression(CompressionName, compress: true);
        _producerWriter = new PacketWriter(_pipe.Writer);
        await _producerWriter.SetOutboundKeysAsync(
            producerCipher, producerMac, compression,
            strictKex: false, compressionActive: compression.Compresses, CancellationToken.None)
            .ConfigureAwait(false);

        _cts = new CancellationTokenSource();
        _producerTask = Task.Run(() => ProduceAsync(_cts.Token));
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        try
        {
            await _producerTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        await _producerWriter.DisposeAsync().ConfigureAwait(false);
        await _pipe.Writer.CompleteAsync().ConfigureAwait(false);
        await _reader.DisposeAsync().ConfigureAwait(false);
        await _pipe.Reader.CompleteAsync().ConfigureAwait(false);
        _cts.Dispose();
    }

    [Benchmark]
    public async Task<int> ReadPacket()
    {
        RawPacket packet = await _reader.ReadPacketAsync(CancellationToken.None).ConfigureAwait(false);
        return packet.Payload.Length;
    }

    private async Task ProduceAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            await _producerWriter.WritePacketAsync(PacketType.ChannelData, _payload, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static (string CipherName, string? MacName) ResolveFraming(string mode) => mode switch
    {
        "ctr-std" => ("aes256-ctr", "hmac-sha2-256"),
        "ctr-etm" => ("aes256-ctr", "hmac-sha2-256-etm@openssh.com"),
        "gcm" => ("aes256-gcm@openssh.com", null),
        "chacha" => ("chacha20-poly1305@openssh.com", null),
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown framing mode"),
    };
}
