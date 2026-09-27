using System.Buffers.Binary;
using System.Numerics;

namespace LibSsh2CS.Util;

/// <summary>
/// Big-endian integer read/write helpers. SSH wire format is network byte order
/// (big-endian) throughout (RFC 4251 §5).
/// </summary>
/// <remarks>
/// Wraps <see cref="BinaryPrimitives"/> for span-based big-endian conversion.
/// Replaces libssh2's <c>_libssh2_ntohu32</c> / <c>_libssh2_htonu32</c> family.
/// </remarks>
internal static class Endian
{
    /// <summary>
    /// Reads an SSH mpint (multi-precision integer) as a big-endian byte array.
    /// Per RFC 4251 §5, an mpint is a uint32 length prefix followed by the
    /// value bytes in big-endian two's-complement form (no leading zero bytes
    /// unless the high bit would otherwise be set).
    /// </summary>
    /// <remarks>
    /// Bounds-checked like the canonical <see cref="PacketWireReader.ReadMpint"/>
    /// path: a wire-declared length that exceeds the source buffer (or
    /// <see cref="int.MaxValue"/>) throws <see cref="SshException"/>
    /// (<see cref="SshErrorCode.OutOfBoundary"/>) instead of slicing out of
    /// bounds (parity fix).
    /// </remarks>
    /// <param name="source">The buffer starting at the mpint length prefix.</param>
    /// <param name="bytesConsumed">Receives the number of bytes consumed (length + 4).</param>
    /// <returns>The integer value as a big-endian byte array (no leading zeros).</returns>
    public static byte[] ReadMpint(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (source.Length < 4)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                "ReadMpint: buffer too short for the 4-byte length prefix");
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(source);
        if (length > int.MaxValue)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"ReadMpint: length {length} > int.MaxValue");
        }

        if (length > source.Length - 4)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"ReadMpint: length {length} > remaining {source.Length - 4}");
        }

        bytesConsumed = 4 + (int)length;
        return source.Slice(4, (int)length).ToArray();
    }

    /// <summary>
    /// Computes the encoded length of an SSH mpint given the value bytes
    /// (without a leading sign byte). Adds a leading zero byte if the high bit
    /// is set, per RFC 4251 §5.
    /// </summary>
    public static int GetMpintLength(byte[] valueBE)
    {
        ArgumentNullException.ThrowIfNull(valueBE);

        return GetMpintLength(valueBE.AsSpan());
    }

    internal static ReadOnlySpan<byte> NormalizeMpint(ReadOnlySpan<byte> valueBE)
    {
        // Preserve the existing representation: nonempty all-zero input retains one zero.
        int start = 0;
        while (start < valueBE.Length - 1 && valueBE[start] == 0)
        {
            start++;
        }
        return valueBE[start..];
    }

    internal static int GetMpintLength(ReadOnlySpan<byte> valueBE)
    {
        ReadOnlySpan<byte> value = NormalizeMpint(valueBE);
        return value.Length + (!value.IsEmpty && (value[0] & 0x80) != 0 ? 1 : 0);
    }

    /// <summary>
    /// Writes an SSH mpint (length-prefixed big-endian). Adds a leading zero
    /// byte if the high bit of the first value byte would be set.
    /// </summary>
    /// <param name="destination">The destination span (must hold the length prefix and encoded value).</param>
    /// <param name="valueBE">The integer value as a big-endian byte array.</param>
    /// <returns>The number of bytes written.</returns>
    public static int WriteMpint(Span<byte> destination, byte[] valueBE)
    {
        ArgumentNullException.ThrowIfNull(valueBE);
        return WriteMpint(destination, valueBE.AsSpan());
    }

    internal static int WriteMpint(Span<byte> destination, ReadOnlySpan<byte> valueBE)
    {
        ReadOnlySpan<byte> value = NormalizeMpint(valueBE);
        bool needsSignPrefix = !value.IsEmpty && (value[0] & 0x80) != 0;
        int encodedLength = value.Length + (needsSignPrefix ? 1 : 0);
        BinaryPrimitives.WriteInt32BigEndian(destination, encodedLength);
        int offset = 4;
        if (needsSignPrefix)
        {
            destination[offset++] = 0;
        }
        value.CopyTo(destination[offset..]);
        return 4 + encodedLength;
    }

    /// <summary>
    /// Converts a non-negative <see cref="BigInteger"/> to its minimal
    /// big-endian unsigned byte representation (no leading zeros, no sign
    /// byte, no length prefix). This is the form <see cref="GetMpintLength(byte[])"/>
    /// and <see cref="WriteMpint(Span{byte}, byte[])"/> expect: they add the conditional leading
    /// zero byte (when the high bit is set) and the 4-byte length prefix.
    /// Replaces libssh2's <c>_libssh2_bn_to_bin</c> output. The value 0
    /// returns an empty array (its mpint encoding is <c>00 00 00 00</c>).
    /// </summary>
    public static byte[] BigIntegerToBigEndianBytes(BigInteger value)
    {
        if (value.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value),
                "SSH mpints are non-negative.");
        }

        if (value.IsZero)
        {
            return [];
        }

        byte[] buf = new byte[value.GetByteCount(isUnsigned: true)];
        value.TryWriteBytes(buf, out int written, isUnsigned: true, isBigEndian: true);
        return written == buf.Length ? buf : buf.AsSpan(0, written).ToArray();
    }

    /// <summary>
    /// Parses a big-endian unsigned byte array (as produced by
    /// <see cref="BigIntegerToBigEndianBytes"/> or read raw from an SSH mpint
    /// body, including any leading 0x00 sign guard) into a
    /// <see cref="BigInteger"/>. Replaces libssh2's
    /// <c>_libssh2_bn_from_bin</c>. Leading zero bytes are insignificant.
    /// </summary>
    public static BigInteger BigIntegerFromBigEndian(ReadOnlySpan<byte> bigEndian)
        => bigEndian.IsEmpty ? BigInteger.Zero : new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true);
}
