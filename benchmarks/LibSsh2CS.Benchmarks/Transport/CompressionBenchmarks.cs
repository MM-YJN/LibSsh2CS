using System.Buffers;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>
/// Isolates the per-packet buffers of <see cref="ZlibCompression"/>. The
/// compressor now appends into a caller-owned <see cref="IBufferWriter{Byte}"/>;
/// this benchmark reuses one pooled writer across iterations (the packet
/// layer's steady state) so the allocation figure reflects the codec work, not
/// a per-call output buffer.
/// </summary>
/// <remarks>
/// <para>
/// SSH compression keeps one persistent codec per direction, and the deflate
/// dictionary evolves with every packet. A decoder cannot be re-fed a packet
/// it has already consumed (distances resolve against the advanced window), so
/// <see cref="RoundTrip"/> advances the encoder and decoder in lockstep over
/// the same packet sequence — the real per-packet shape — and its allocation
/// figure covers both directions. <see cref="Compress"/> alone uses one
/// persistent encoder, matching the send path.
/// </para>
/// <para>
/// The receive-side allocation is also visible (inside the framing total) in
/// <see cref="PacketReadBenchmarks"/> with <c>zlib</c> selected.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("compression")]
public class CompressionBenchmarks
{
    /// <summary>Payload size in bytes.</summary>
    [Params(256, 4096, 32700)]
    public int PayloadSize { get; set; }

    /// <summary>Compressible vs incompressible input shape.</summary>
    [Params(DataShape.Compressible, DataShape.Incompressible)]
    public DataShape Shape { get; set; }

    private ZlibCompression _compressor = null!;
    private ZlibCompression _decompressor = null!;
    private byte[] _payload = null!;
    private PooledByteBufferWriter _writer = null!;
    private PooledByteBufferWriter _readWriter = null!;

    [GlobalSetup]
    public void Setup()
    {
        _payload = DataGenerator.Create(Shape, PayloadSize);
        _compressor = new ZlibCompression("zlib", useInAuth: true);
        _compressor.Init(compress: true);
        _decompressor = new ZlibCompression("zlib", useInAuth: true);
        _decompressor.Init(compress: false);
        _writer = new PooledByteBufferWriter(PayloadSize + 64);
        _readWriter = new PooledByteBufferWriter(PayloadSize + 64);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _compressor.Dispose();
        _decompressor.Dispose();
        _writer.Dispose();
        _readWriter.Dispose();
    }

    [Benchmark]
    public int Compress()
    {
        _writer.ResetWrittenCount();
        _compressor.Compress(_payload, _writer);
        return _writer.WrittenCount;
    }

    [Benchmark]
    public int RoundTrip()
    {
        _writer.ResetWrittenCount();
        _compressor.Compress(_payload, _writer);

        _readWriter.ResetWrittenCount();
        _decompressor.Decompress(_writer.WrittenSpan, _readWriter);
        return _readWriter.WrittenCount;
    }
}
