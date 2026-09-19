using System.Buffers;
using System.Numerics;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.Util;

/// <summary>
/// Tests for the <see cref="Endian"/> BigInteger ↔ big-endian-byte helpers and
/// the round-trip through <see cref="Endian.WriteMpint"/> /
/// <see cref="Endian.GetMpintLength"/> (the mpint encode path used by the KEX
/// layer for <c>e</c> / <c>f</c> / <c>K</c>).
/// </summary>
public class EndianBigIntegerTests
{
    // ── BigIntegerToBigEndianBytes ─────────────────────────────────────

    [Theory]
    [InlineData(0, new byte[0])]
    [InlineData(1, new byte[] { 0x01 })]
    [InlineData(255, new byte[] { 0xFF })]
    [InlineData(256, new byte[] { 0x01, 0x00 })]
    [InlineData(0x80FF, new byte[] { 0x80, 0xFF })]
    [InlineData(0xFF00FF, new byte[] { 0xFF, 0x00, 0xFF })]
    public void ToBigEndianBytes_ProducesMinimalUnsignedBe(int value, byte[] expected)
    {
        Assert.Equal(expected, Endian.BigIntegerToBigEndianBytes((BigInteger)value));
    }

    [Fact]
    public void ToBigEndianBytes_ThrowsOnNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Endian.BigIntegerToBigEndianBytes((BigInteger)(-1)));
    }

    [Fact]
    public void ToBigEndianBytes_HandlesDhGroup14SizedValue()
    {
        // A 2048-bit value (group14 magnitude) — round-trips through parse.
        BigInteger big = BigInteger.Pow(2, 2047) + 1;
        byte[] be = Endian.BigIntegerToBigEndianBytes(big);
        Assert.Equal(256, be.Length);          // 2048 bits / 8
        Assert.Equal(0x80, be[0] & 0xF0);      // top byte has the 2^2047 bit set
        Assert.Equal(big, Endian.BigIntegerFromBigEndian(be));
    }

    // ── BigIntegerFromBigEndian ────────────────────────────────────────

    [Fact]
    public void FromBigEndian_EmptySpan_IsZero()
    {
        Assert.Equal(BigInteger.Zero, Endian.BigIntegerFromBigEndian([]));
    }

    [Fact]
    public void FromBigEndian_LeadingZerosAreInsignificant()
    {
        // 0x00 0x00 0x01 == 1 (leading zeros from a prior mpint sign guard)
        Assert.Equal((BigInteger)1, Endian.BigIntegerFromBigEndian([0x00, 0x00, 0x01]));
    }

    // ── mpint round-trip (encode via WriteMpint, decode via parse) ─────

    [Fact]
    public void MpintRoundTrip_HighBitValue_GetsLeadingZero()
    {
        BigInteger value = 0x80FF;
        byte[] be = Endian.BigIntegerToBigEndianBytes(value);

        // High bit set → mpint body must carry a leading 0x00.
        int len = Endian.GetMpintLength(be);
        Assert.Equal(3, len);   // 0x00 0x80 0xFF

        byte[] buf = new byte[4 + len];
        int written = Endian.WriteMpint(buf, be);
        Assert.Equal(7, written);
        Assert.Equal([0, 0, 0, 3, 0x00, 0x80, 0xFF], buf);

        // Decode back via the wire reader path.
        var r = new PacketWireReader(new ReadOnlySequence<byte>(buf));
        Assert.Equal(value, r.ReadMpintAsBigInteger());
    }

    [Fact]
    public void MpintRoundTrip_PlainValue_NoLeadingZero()
    {
        BigInteger value = 0x0100;
        byte[] be = Endian.BigIntegerToBigEndianBytes(value);

        int len = Endian.GetMpintLength(be);
        Assert.Equal(2, len);

        byte[] buf = new byte[4 + len];
        Endian.WriteMpint(buf, be);
        Assert.Equal([0, 0, 0, 2, 0x01, 0x00], buf);
    }

    [Fact]
    public void MpintRoundTrip_ZeroValue_EmptyBody()
    {
        BigInteger value = BigInteger.Zero;
        byte[] be = Endian.BigIntegerToBigEndianBytes(value);
        Assert.Empty(be);

        int len = Endian.GetMpintLength(be);
        Assert.Equal(0, len);

        byte[] buf = new byte[4];
        int written = Endian.WriteMpint(buf, be);
        Assert.Equal(4, written);   // just the length prefix: 00 00 00 00
        Assert.Equal([0, 0, 0, 0], buf);
    }

    // ── ReadMpint (guarded decode, parity with PacketWireReader.ReadMpint) ──

    [Fact]
    public void ReadMpint_ValidBody_ReturnsBytesAndConsumed()
    {
        byte[] body = Endian.ReadMpint([0, 0, 0, 3, 0x01, 0x80, 0xFF], out int bytesConsumed);

        Assert.Equal([0x01, 0x80, 0xFF], body);
        Assert.Equal(7, bytesConsumed);
    }

    [Fact]
    public void ReadMpint_ZeroLength_ReturnsEmptyBody()
    {
        byte[] body = Endian.ReadMpint([0, 0, 0, 0], out int bytesConsumed);

        Assert.Empty(body);
        Assert.Equal(4, bytesConsumed);
    }

    [Fact]
    public void ReadMpint_LengthExceedsRemaining_ThrowsOutOfBoundary()
    {
        // Declared length 5 with only 2 value bytes present — must not slice
        // out of bounds.
        SshException ex = Assert.Throws<SshException>(
            () => Endian.ReadMpint([0, 0, 0, 5, 0x01, 0x02], out _));

        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadMpint_LengthBeyondIntMax_ThrowsOutOfBoundary()
    {
        // 0xFFFFFFFF > int.MaxValue — must not wrap negative and slice.
        SshException ex = Assert.Throws<SshException>(
            () => Endian.ReadMpint([0xFF, 0xFF, 0xFF, 0xFF], out _));

        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadMpint_BufferShorterThanLengthPrefix_ThrowsOutOfBoundary()
    {
        SshException ex = Assert.Throws<SshException>(
            () => Endian.ReadMpint([0, 0], out _));

        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }
}
