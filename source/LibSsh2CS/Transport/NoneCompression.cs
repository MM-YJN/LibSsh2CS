using System.Buffers;

namespace LibSsh2CS.Transport;

/// <summary>
/// The identity (no-op) compressor. Port of <c>comp_method_none</c>
/// (<c>comp.c:100</c>): payloads pass through unchanged.
/// </summary>
internal sealed class NoneCompression : ICompression
{
    public string Name => "none";
    public bool Compresses => false;
    public bool UseInAuth => false;

    public void Init(bool compress)
    {
        // Nothing to set up.
    }

    public void Compress(ReadOnlySpan<byte> src, IBufferWriter<byte> destination)
        => destination.Write(src);

    public void Decompress(ReadOnlySpan<byte> src, IBufferWriter<byte> destination)
        => destination.Write(src);

    public void Dispose()
    {
    }
}
