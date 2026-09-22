using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>
/// Isolates <see cref="PacketWriter.WritePacketAsync"/> — the per-packet
/// outbound framer. A background drain keeps the pipe from back-pressuring so
/// the measured region is framing + compression + MAC + encryption only.
/// </summary>
/// <remarks>
/// The writer's allocations (payload copy, frame buffer) are the ones the
/// hot-path optimization targets; the drain task's allocations run on another
/// thread and are therefore excluded from BenchmarkDotNet's per-thread
/// allocation measurement.
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("write")]
public class PacketWriteBenchmarks
{
    /// <summary>Payload size in bytes (including the leading type byte).</summary>
    [Params(256, 4096, 32700)]
    public int PayloadSize { get; set; }

    /// <summary>Negotiated cipher wire name.</summary>
    [Params("aes256-ctr", "chacha20-poly1305@openssh.com")]
    public string CipherName { get; set; } = "aes256-ctr";

    /// <summary>Negotiated compression wire name.</summary>
    [Params("none", "zlib")]
    public string CompressionName { get; set; } = "none";

    private Pipe _pipe = null!;
    private PacketWriter _writer = null!;
    private byte[] _payload = null!;
    private Task _drainTask = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _payload = DataGenerator.Create(DataShape.Compressible, PayloadSize);
        _payload[0] = (byte)PacketType.ChannelData;

        _pipe = TransportSetup.CreatePipe();
        _writer = new PacketWriter(_pipe.Writer);

        (ICipher cipher, IMac mac) = TransportSetup.CreateCipherAndMac(
            CipherName, macName: null, encrypt: true);
        ICompression compression = TransportSetup.CreateCompression(CompressionName, compress: true);
        await _writer.SetOutboundKeysAsync(
            cipher, mac, compression,
            strictKex: false, compressionActive: compression.Compresses, CancellationToken.None)
            .ConfigureAwait(false);

        _drainTask = Task.Run(() => DrainAsync(_pipe.Reader));
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _writer.DisposeAsync().ConfigureAwait(false);
        await _pipe.Writer.CompleteAsync().ConfigureAwait(false);
        await _drainTask.ConfigureAwait(false);
        await _pipe.Reader.CompleteAsync().ConfigureAwait(false);
    }

    [Benchmark]
    public Task WritePacket()
        => _writer.WritePacketAsync(PacketType.ChannelData, _payload, CancellationToken.None);

    private static async Task DrainAsync(PipeReader reader)
    {
        while (true)
        {
            ReadResult result = await reader.ReadAsync(CancellationToken.None).ConfigureAwait(false);
            reader.AdvanceTo(result.Buffer.End);
            if (result.IsCompleted)
            {
                return;
            }
        }
    }
}
