using System.IO.Compression;

namespace LibSsh2CS.Transport;

/// <summary>
/// The managed equivalent of libssh2's <c>struct _LIBSSH2_COMP_METHOD</c>
/// (<c>comp.c</c>): an SSH compression method. One instance handles every packet
/// in a single direction and keeps the deflate/inflate dictionary across packets
/// — mirroring libssh2's persistent <c>session-&gt;local.comp_abstract</c>
/// (<c>z_stream</c> initialized once in <c>comp_method_zlib_init</c>, reused per
/// packet with <c>Z_PARTIAL_FLUSH</c>).
/// </summary>
/// <remarks>
/// SSH "zlib" compression uses the <b>zlib data format (RFC 1950)</b> — a 2-byte
/// header, a raw deflate body, and an Adler-32 trailer. libssh2 requests this via
/// the plain <c>deflateInit</c>/<c>inflateInit</c> (<c>comp.c:156</c>), so the
/// .NET 11 match is <see cref="ZLibEncoder"/>/<see cref="ZLibDecoder"/>
/// (<b>not</b> <see cref="DeflateEncoder"/>, which emits headerless raw deflate
/// and would not interoperate).
/// </remarks>
internal interface ICompression : IDisposable
{
    /// <summary>The SSH algorithm name (<c>none</c>, <c>zlib</c>, <c>zlib@openssh.com</c>).</summary>
    string Name { get; }

    /// <summary>
    /// <c>comp_method-&gt;compress</c> — 1 if this method actually compresses
    /// (<c>zlib</c>), 0 for <c>none</c>.
    /// </summary>
    bool Compresses { get; }

    /// <summary>
    /// <c>comp_method-&gt;use_in_auth</c> — whether compression is active during
    /// the userauth phase. <c>zlib</c> compresses from the start (true);
    /// <c>zlib@openssh.com</c> delays compression until after auth (false).
    /// </summary>
    bool UseInAuth { get; }

    /// <summary>
    /// Sets up the (de)compression context for the given direction. Port of
    /// <c>comp_method-&gt;init(session, compr)</c>.
    /// </summary>
    /// <param name="compress"><c>true</c> for the sending (compressing) direction,
    /// <c>false</c> for the receiving (decompressing) direction.</param>
    void Init(bool compress);

    /// <summary>
    /// Compresses one packet's payload. Port of <c>comp_method-&gt;comp</c>
    /// (<c>comp_method_zlib_comp</c> with <c>Z_PARTIAL_FLUSH</c>). Dictionary state
    /// persists across calls on the same instance.
    /// </summary>
    byte[] Compress(ReadOnlySpan<byte> src);

    /// <summary>
    /// Decompresses one packet's payload. Port of <c>comp_method-&gt;decomp</c>
    /// (<c>comp_method_zlib_decomp</c>). Dictionary state persists across calls.
    /// </summary>
    byte[] Decompress(ReadOnlySpan<byte> src);
}
