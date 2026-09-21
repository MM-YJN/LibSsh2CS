using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS.Util;

[ExcludeFromCodeCoverage]
internal readonly struct Base64EncodedBytes : ISpanFormattable, IUtf8SpanFormattable
{
    private readonly ReadOnlyMemory<byte> _bytes;

    internal ReadOnlyMemory<byte> Bytes => _bytes;

    public Base64EncodedBytes(ReadOnlyMemory<byte> bytes)
    {
        _bytes = bytes;
    }

    public override string ToString() => Base64.EncodeToString(Bytes.Span);

    public string ToString(string? format, IFormatProvider? formatProvider)
         => Base64.EncodeToString(Bytes.Span);

    public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
        => Base64.TryEncodeToChars(Bytes.Span, destination, out charsWritten);

    public bool TryFormat(Span<byte> utf8Destination, out int bytesWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
        => Base64.TryEncodeToUtf8(Bytes.Span, utf8Destination, out bytesWritten);
}
