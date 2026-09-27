using System.Security.Cryptography;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.Transport;

public class MpintHashTests
{
    [Theory]
    [InlineData("", "00000000")]
    [InlineData("00", "0000000100")]
    [InlineData("000000", "0000000100")]
    [InlineData("7F", "000000017F")]
    [InlineData("80", "000000020080")]
    [InlineData("000080", "000000020080")]
    [InlineData("000100", "000000020100")]
    public void ExchangeHash_PreservesMpintEncodingAndRawServerValue(string input, string encoded)
    {
        byte[] value = Convert.FromHexString(input);
        byte[] wire = Convert.FromHexString(encoded);
        byte[] destination = new byte[wire.Length];
        Assert.Equal(wire.Length - 4, Endian.GetMpintLength(value.AsSpan()));
        Assert.Equal(wire.Length, Endian.WriteMpint(destination, value.AsSpan()));
        Assert.Equal(wire, destination);

        // Five empty SSH strings, the explicitly encoded client mpint, an intentionally
        // nonminimal server mpint, and the shared secret 128 with its sign guard.
        byte[] expectedTranscript = new byte[20].Concat(wire)
            .Concat(Convert.FromHexString("0000000400000080"))
            .Concat(Convert.FromHexString("000000020080")).ToArray();
        byte[] hash = KeyExchange.ComputeExchangeHash(KexAlgorithm.DhGroup14Sha256,
            [], [], default, default, default, value, new byte[] { 0, 0, 0, 0x80 }, 128);
        Assert.Equal(SHA256.HashData(expectedTranscript), hash);
    }

    [Fact]
    public void ExchangeHash_ZeroSecret_HasEmptyMpintBody()
    {
        // Curve25519 hashes seven empty strings followed by the empty zero mpint.
        byte[] hash = KeyExchange.ComputeExchangeHash(KexAlgorithm.Curve25519Sha256,
            [], [], default, default, default, default, default, 0);
        Assert.Equal(SHA256.HashData(new byte[32]), hash);
    }
}
