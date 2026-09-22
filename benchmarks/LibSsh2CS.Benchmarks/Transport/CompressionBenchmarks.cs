using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>
/// Isolates the per-packet buffers of <see cref="ZlibCompression"/>. Both
/// directions currently allocate an <c>ArrayBufferWriter</c> plus a
/// <c>ToArray</c> result on every call; the hot-path optimization replaces
/// those with pooled/caller-owned buffers.
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

    [GlobalSetup]
    public void Setup()
    {
        _payload = DataGenerator.Create(Shape, PayloadSize);
        _compressor = new ZlibCompression("zlib", useInAuth: true);
        _compressor.Init(compress: true);
        _decompressor = new ZlibCompression("zlib", useInAuth: true);
        _decompressor.Init(compress: false);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _compressor.Dispose();
        _decompressor.Dispose();
    }

    [Benchmark]
    public int Compress() => _compressor.Compress(_payload).Length;

    [Benchmark]
    public int RoundTrip()
    {
        byte[] compressed = _compressor.Compress(_payload);
        return _decompressor.Decompress(compressed).Length;
    }
}
