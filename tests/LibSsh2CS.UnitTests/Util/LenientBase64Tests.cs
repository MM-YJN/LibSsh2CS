using System.Buffers.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.Util;

/// <summary>
/// Tests for the libssh2-exact lenient base64 decoder
/// (<c>misc.c:396-424</c>): non-alphabet bytes are skipped, unpadded tails
/// decode, and the only failure is a lone leftover sextet.
/// </summary>
public class LenientBase64Tests
{
    [Fact]
    public void Decode_CanonicalInput_MatchesBcl()
    {
        byte[] src = System.Text.Encoding.ASCII.GetBytes("QUJDRA==");   // "ABCD"
        byte[] expected = System.Convert.FromBase64String("QUJDRA==");

        Assert.Equal(expected, Decode(src));
        Assert.Equal(expected, Decode("QUJDRA=="));
    }

    [Theory]
    [InlineData("QQ", "A")]            // unpadded 1-byte tail
    [InlineData("QUI", "AB")]          // unpadded 2-byte tail
    [InlineData("QUJD", "ABC")]        // no padding at all
    [InlineData("QUJD=", "ABC")]       // '=' skipped as junk
    [InlineData("QUJD====", "ABC")]    // extra padding skipped
    [InlineData("QU=JD", "ABC")]       // mid-stream '=' skipped
    [InlineData("QU JD\nRA", "ABCD")]  // whitespace skipped
    [InlineData("QU!JD", "ABC")]       // junk skipped
    [InlineData("QUJDRA==", "ABCD")]   // canonical still works
    public void Decode_LenientCases(string b64, string expectedText)
    {
        byte[] expected = System.Text.Encoding.ASCII.GetBytes(expectedText);

        Assert.Equal(expected, Decode(b64));
        Assert.Equal(expected, Decode(System.Text.Encoding.ASCII.GetBytes(b64)));
    }

    [Theory]
    [InlineData("Q")]        // one sextet — partial octet
    [InlineData("Q Q Q Q Q")]  // five sextets — still a lone leftover (5 % 4 == 1)
    public void Decode_LoneLeftoverSextet_ThrowsInval(string b64)
    {
        SshException ex = Assert.Throws<SshException>(() => Decode(b64));

        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
        Assert.Contains("Invalid base64", ex.Message);
    }

    [Fact]
    public void Decode_EmptyInput_ReturnsEmpty()
    {
        Assert.Empty(Decode(""));
        Assert.Empty(Decode(ReadOnlySpan<byte>.Empty));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 3)]
    [InlineData(4, 3)]
    [InlineData(5, 4)]
    [InlineData(int.MaxValue, 1_610_612_736)]
    public void GetMaxDecodedLength_ReturnsCeilingCapacity(int encodedLength, int expected)
    {
        Assert.Equal(expected, LenientBase64.GetMaxDecodedLength(encodedLength));
    }

    [Fact]
    public void GetMaxDecodedLength_NegativeLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => LenientBase64.GetMaxDecodedLength(-1));
    }

    [Fact]
    public void Decode_SpanOverload_WritesIntoDestination()
    {
        byte[] destination = new byte[16];
        int written = LenientBase64.Decode("QUJDRA=="u8, destination);

        Assert.Equal(4, written);
        Assert.Equal("ABCD"u8.ToArray(), destination.AsSpan(0, written).ToArray());
    }

    [Fact]
    public void Decode_SpanOverload_DestinationOfMaximumLength_NeverOverruns()
    {
        // Pins the documented contract: GetMaxDecodedLength includes the staged
        // byte for every possible partial trailing group. Any write beyond this
        // exact maximum destination capacity fails this test.
        for (int length = 0; length <= 400; length++)
        {
            byte[] src = new byte[length];
            Array.Fill(src, (byte)'A');
            byte[] destination = new byte[LenientBase64.GetMaxDecodedLength(length)];

            try
            {
                int written = LenientBase64.Decode(src, destination);
                Assert.InRange(written, 0, destination.Length);
            }
            catch (SshException ex)
            {
                // The decoder's only failure: a lone leftover sextet
                // (n ≡ 1 mod 4) throws Inval — after writing in-bounds.
                Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
            }
        }
    }

    /// <summary>
    /// Defect characterization for decode-buffer sizing: a destination sized with the
    /// BCL strict decoder's floor bound <c>Base64.GetMaxDecodedLength</c>
    /// (3·⌊L/4⌋) is genuinely too small for the lenient decoder's partial-tail
    /// writes — the overrun is deterministic (the array-backed span bounds
    /// check fires). This documents why callers must use
    /// <c>LenientBase64.GetMaxDecodedLength</c>, and pins the floor-bound failure
    /// mode so any future call site that reintroduces the floor bound is visibly
    /// wrong.
    /// </summary>
    [Theory]
    [InlineData(342)]   // n = 342 ≡ 2 (mod 4): last write at index 256, floor bound 255
    [InlineData(343)]   // n = 343 ≡ 3 (mod 4): last write at index 257, floor bound 255
    [InlineData(1366)]  // n = 1366 ≡ 2 (mod 4): last write at index 1024, floor bound 1023
    [InlineData(1367)]  // n = 1367 ≡ 3 (mod 4): last write at index 1025, floor bound 1023
    public void Decode_SpanOverload_StrictFloorBoundDestination_Overruns(int length)
    {
        byte[] src = new byte[length];
        Array.Fill(src, (byte)'A');

        byte[] floorBoundDestination = new byte[Base64.GetMaxDecodedLength(length)];

        Assert.Throws<IndexOutOfRangeException>(() => LenientBase64.Decode(src, floorBoundDestination));
    }

    private static byte[] Decode(ReadOnlySpan<char> src)
    {
        byte[] output = new byte[LenientBase64.GetMaxDecodedLength(src.Length)];
        int length = LenientBase64.Decode(src, output);
        return output.AsSpan(0, length).ToArray();
    }

    private static byte[] Decode(ReadOnlySpan<byte> src)
    {
        byte[] output = new byte[LenientBase64.GetMaxDecodedLength(src.Length)];
        int length = LenientBase64.Decode(src, output);
        return output.AsSpan(0, length).ToArray();
    }
}
