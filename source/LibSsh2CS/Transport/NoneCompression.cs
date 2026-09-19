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

    public byte[] Compress(ReadOnlySpan<byte> src) => src.ToArray();

    public byte[] Decompress(ReadOnlySpan<byte> src) => src.ToArray();

    public void Dispose()
    {
    }
}
