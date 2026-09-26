using System.Security.Cryptography;

namespace LibSsh2CS.UnitTests;

public class BcryptAllocationRegressionTests
{
    // SHA-256 of derived outputs captured from the pre-refactor managed implementation
    // Revision: bc2f8477277b2bb6ee15098b7199818bcaf1a9ec.
    // (password="password", salt="salt", rounds=4). Independent OpenSSH encrypted-key
    // fixtures in PemParserTests continue to validate interoperability.
    [Theory]
    [InlineData(1, "245843ABEF9E72E7EFAC30138A994BF6301E7E1D7D7042A33D42E863D2638811")]
    [InlineData(31, "B61E09611C1823EF805DE28DCB4E83F438FEA0FF3DAEEFAD5C00A6827BAFC3A2")]
    [InlineData(32, "F42D337DEDCB15D9171942078FFDF9B1B78EDB888F30741521456B79CF7E8885")]
    [InlineData(33, "48E7F793070EECA89E0F4E618D28AE224292F52D9EA11A3C82F97F4E1A9769F6")]
    [InlineData(48, "F317E0BCEA770D84AFBBFAD2DC2F934A3140583408A92F8C9D249A7CEBD6C057")]
    [InlineData(64, "FDC937883F3606A1288A52221DA3185CF607BB6E3A8BB38733461503250ADAAA")]
    [InlineData(65, "64A742ED2CBA7AF46B8DFDBFCE91401D6BF21B48DF82A66030965B46EC0FDB46")]
    [InlineData(1024, "C23CBB94D2CDA4A2673A0800C6B68B7BB83D124F3048990415A960B03D2EF6A0")]
    public void Derive_OutputBlockBoundaries_MatchesBaseline(int length, string expectedHash)
    {
        byte[] result = BcryptPbkdf.Derive("password"u8, "salt"u8, 4, length);
        Assert.Equal(length, result.Length);
        Assert.Equal(expectedHash, Convert.ToHexString(SHA256.HashData(result)));
    }

    [Fact]
    public async Task Derive_ConcurrentAndRepeatedCalls_HaveIndependentState()
    {
        byte[] expected = BcryptPbkdf.Derive("password"u8, "salt"u8, 4, 48);
        Task<byte[]>[] calls = Enumerable.Range(0, 4)
            .Select(_ => Task.Run(() => BcryptPbkdf.Derive("password"u8, "salt"u8, 4, 48)))
            .ToArray();
        byte[][] results = await Task.WhenAll(calls);
        foreach (byte[] result in results)
        {
            Assert.Equal(expected, result);
            Assert.NotSame(expected, result);
        }
        Array.Clear(results[0]);
        Assert.Equal(expected, results[1]);
        Assert.NotEqual(expected, BcryptPbkdf.Derive("different"u8, "salt"u8, 4, 48));
        Assert.Equal(expected, BcryptPbkdf.Derive("password"u8, "salt"u8, 4, 48));
    }
}
