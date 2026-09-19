using System.Globalization;
using System.Numerics;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// DH group14 (RFC 3526 §3 modp2048) tests. RFC 3526 ships no KAT, so the
/// strength here is a two-party self-convergence (mirrors the X25519 §6.1 DH
/// test style) plus generator/known-exponent checks and private-exponent range
/// assertions matching OpenSSL's BN_rand sampling.
/// </summary>
public class DhGroup14Tests
{
    private static readonly BigInteger s_prime = BigInteger.Parse(
        "0" +
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    [Fact]
    public void SharedSecret_RejectsInvalidPeerBoundaries()
    {
        var dh = new DhGroup14(new BigInteger(3));
        foreach (BigInteger value in new BigInteger[] { -1, 0, 1, s_prime - 1, s_prime, s_prime + 1 })
        {
            SshException ex = Assert.Throws<SshException>(() => dh.ComputeSharedSecret(value));
            Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
        }

        Assert.Equal(new BigInteger(8), dh.ComputeSharedSecret(2));
        Assert.Equal(s_prime - 8, dh.ComputeSharedSecret(s_prime - 2));
    }

    [Fact]
    public void PublicKey_PrivateExponentOne_IsGenerator()
    {
        // e = g^1 mod p = 2 (g = 2 per RFC 3526 §3).
        Assert.Equal(new BigInteger(2), new DhGroup14(BigInteger.One).PublicKey);
    }

    [Fact]
    public void PublicKey_PrivateExponentTwo_IsFour()
    {
        Assert.Equal(new BigInteger(4), new DhGroup14(new BigInteger(2)).PublicKey);
    }

    [Fact]
    public void PublicKey_PrivateExponentThree_IsEight()
    {
        Assert.Equal(new BigInteger(8), new DhGroup14(new BigInteger(3)).PublicKey);
    }

    [Fact]
    public void DiffieHellman_TwoParties_ConvergeOnSharedSecret()
    {
        // Alice and Bob each draw a fresh private exponent, exchange public
        // values, and must arrive at the same K = g^(ab) mod p. This is the core
        // DH correctness property the KEX handshake depends on.
        var alice = new DhGroup14();
        var bob = new DhGroup14();

        BigInteger ka = alice.ComputeSharedSecret(bob.PublicKey);
        BigInteger kb = bob.ComputeSharedSecret(alice.PublicKey);

        Assert.Equal(ka, kb);
        Assert.True(ka.Sign > 0, "shared secret must be non-zero");
        Assert.False(ka.IsOne, "shared secret must not be 1");
    }

    [Fact]
    public void DiffieHellman_RepeatedExchanges_AllConverge()
    {
        // Run several independent handshakes to catch any randomized-path bug
        // (e.g. a bad limb in the private-exponent sampling).
        for (int i = 0; i < 16; i++)
        {
            var a = new DhGroup14();
            var b = new DhGroup14();
            Assert.Equal(a.ComputeSharedSecret(b.PublicKey), b.ComputeSharedSecret(a.PublicKey));
        }
    }

    [Fact]
    public void GeneratePrivateValue_Is2047BitsTopSetAndOdd()
    {
        // Mirrors OpenSSL BNrand(bits=2047, top=0, bottom=-1): bit 2046 set,
        // bit 2047 clear, and odd (LSB set). Sample many times.
        for (int i = 0; i < 32; i++)
        {
            BigInteger x = DhGroup14.GeneratePrivateValue();

            Assert.False(x.Sign <= 0, "private exponent must be positive");
            Assert.True((x >> 2046).IsOne, "bit 2046 (top) must be set");
            Assert.True(((x >> 2047) & BigInteger.One).IsZero, "bit 2047 must be clear (strictly < 2^2047)");
            Assert.False(x.IsEven, "private exponent must be odd (bottom bit set)");
        }
    }

    [Fact]
    public void GeneratePrivateValue_IsLessThanPrime()
    {
        // 2047-bit number is always < the 2048-bit prime, but assert it so the
        // invariant is pinned.
        BigInteger two2047 = BigInteger.One << 2047;
        for (int i = 0; i < 8; i++)
        {
            BigInteger x = DhGroup14.GeneratePrivateValue();
            Assert.True(x < two2047, "private exponent must be < 2^2047");
        }
    }

    /// <summary>
    /// Known-answer test: <c>e = 2^x mod p</c> for a fixed private exponent,
    /// precomputed against the RFC 3526 §3 modp2048 prime with an independent
    /// (Python <c>pow</c>) implementation. This is the regression guard for the
    /// negative-prime parse bug — <c>BigInteger.Parse(hexString,
    /// NumberStyles.HexNumber)</c> interpreted the high-bit-set prime
    /// (<c>0xFF…</c>) as two's-complement negative, silently corrupting every
    /// <see cref="BigInteger.ModPow"/> result. The two-party convergence test
    /// above was blind to it (both parties shared the same wrong prime).
    /// </summary>
    [Fact]
    public void PublicKey_KnownAnswer_MatchesReferenceImplementation()
    {
        var x = BigInteger.Parse(
            "0" +
            "4000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000001",
            NumberStyles.HexNumber,
            CultureInfo.InvariantCulture);

        var expected = BigInteger.Parse(
            "0" +
            "4087DB254DDC0FCD61EDC93AF60E8770719F431ACE56745432806671F22B5433" +
            "1C41941CAE072B15B5C4070502A370B506BABBF5F28341D003C763E8B7B1F687" +
            "5847F4BCBC57608E2C3C70F21027BC2E5D50CBCF877C11109FA357FC3BE5D48F" +
            "CCF34A55B160C05A10ECB9E23BFA95A72B345FC518F01846D1B228CF36143E95" +
            "698AA2BFD1B621940BA9E15915EB1321C9B2BF690A8CB7BB011335511A61EBE9" +
            "7BDFAE32D5D5CE2CD43C6E6FD8B27DE1A691E0D987928A10CB5D669233A48A9E" +
            "68E4765398B01BB6E0F9F8EFD04A1C990AECBDBFE6A47324E9A7944E38D46E48" +
            "04556AD54059242C769CF3FB74C52DF39605EA5F0116B923F18FBF1B8BB09B63",
            NumberStyles.HexNumber,
            CultureInfo.InvariantCulture);

        Assert.Equal(expected, new DhGroup14(x).PublicKey);
    }
}
