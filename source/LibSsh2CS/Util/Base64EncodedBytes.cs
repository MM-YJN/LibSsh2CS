using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS.Util;

[ExcludeFromCodeCoverage]
internal readonly struct Base64EncodedBytes : ISpanFormattable, IUtf8SpanFormattable
{
    private readonly byte[] _bytes;

    internal byte[] Bytes => _bytes ?? Array.Empty<byte>();

    public Base64EncodedBytes(byte[] bytes)
    {
        _bytes = bytes;
    }

    public override string ToString() => Base64.EncodeToString(Bytes);

    public string ToString(string? format, IFormatProvider? formatProvider)
         => Base64.EncodeToString(Bytes);

    public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
        => Base64.TryEncodeToChars(Bytes, destination, out charsWritten);

    public bool TryFormat(Span<byte> utf8Destination, out int bytesWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
        => Base64.TryEncodeToUtf8(Bytes, utf8Destination, out bytesWritten);
}
