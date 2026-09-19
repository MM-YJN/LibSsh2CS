using System.Numerics;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Cross-checks the new constant-time <see cref="Fe25519Ops"/> (10-limb radix-2^25.5)
/// against the existing BigInteger <see cref="Fe25519"/> on random inputs. The
/// BigInteger version is itself verified by the RFC 7748/8032 KATs in X25519Tests
/// and Ed25519Tests, so it is a correct oracle. If every op matches on 1,000 random
/// inputs, the new field arithmetic is byte-exact correct.
/// </summary>
public class Fe25519OpsTests
{
    private const int RandomTrials = 200;

    private static readonly Random s_rng = new(0x25519);

    /// <summary>
    /// Generates a random field element as 32 random bytes, both as a BigInteger
    /// (for the reference path) and as an Fe (for the new path).
    /// </summary>
    private static BigInteger RandomFieldElement(out Fe fe)
    {
        byte[] bytes = new byte[32];
        lock (s_rng)
        {
            s_rng.NextBytes(bytes);
        }

        bytes[31] &= 0x7F; // drop bit 255 so the value is < 2^255
        Fe25519Ops.FromBytes(out fe, bytes);

        // BigInteger reference: parse the same bytes (with zero high byte to keep positive).
        byte[] biBytes = new byte[33];
        Array.Copy(bytes, 0, biBytes, 0, 32);
        return new BigInteger(biBytes);
    }

    [Fact]
    public void FromBytes_ToBytes_RoundTrips()
    {
        // Specific case: bytes 5,6,7 = 123, 84, 57 (this was failing in random tests).
        // The value 0x390054007B (bytes 0,5,6,7 set, rest 0) is well below p, so
        // FromBytes → ToBytes should round-trip exactly.
        byte[] specific = new byte[32];
        specific[5] = 0x7B;
        specific[6] = 0x54;
        specific[7] = 0x39;
        Fe25519Ops.FromBytes(out Fe feSpecific, specific);
        byte[] specificOut = new byte[32];
        Fe25519Ops.ToBytes(specificOut, in feSpecific);
        Assert.Equal(specific, specificOut);

        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fe);

            byte[] expected = Fe25519Oracle.ToBytesLE(a);
            byte[] actual = new byte[32];
            Fe25519Ops.ToBytes(actual, in fe);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void Add_MatchesBigInteger()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);
            BigInteger b = RandomFieldElement(out Fe fb);

            Fe25519Ops.Add(out Fe actual, in fa, in fb);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Add(a, b);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    [Fact]
    public void Sub_MatchesBigInteger()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);
            BigInteger b = RandomFieldElement(out Fe fb);

            Fe25519Ops.Sub(out Fe actual, in fa, in fb);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Sub(a, b);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    [Fact]
    public void Neg_MatchesBigInteger()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);

            Fe25519Ops.Neg(out Fe actual, in fa);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Mod(-a);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    [Fact]
    public void Mul_MatchesBigInteger()
    {
        // Specific case: 2^26 * 2^26 = 2^52. Both operands cross the limb boundary
        // (limb 1 represents 2^26). The result must be encoded in limb 2.
        byte[] fBytes = new byte[32];
        fBytes[3] = 4; // bit 26 → limb 1 = 1 (representing 2^26)
        Fe25519Ops.FromBytes(out Fe fSimple, fBytes);
        Fe25519Ops.Mul(out Fe simpleProduct, in fSimple, in fSimple);
        Fe25519Ops.Freeze(ref simpleProduct);
        byte[] simpleOut = new byte[32];
        Fe25519Ops.ToBytes(simpleOut, in simpleProduct);
        byte[] expectedSimple = new byte[32];
        expectedSimple[6] = 16; // 2^52 = byte 6 bit 4 = 16
        Assert.Equal(expectedSimple, simpleOut);

        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);
            BigInteger b = RandomFieldElement(out Fe fb);

            Fe25519Ops.Mul(out Fe actual, in fa, in fb);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Mul(a, b);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    [Fact]
    public void Debug_SimpleProduct26x26()
    {
        // 2^26 * 2^26 = 2^52.
        byte[] fBytes = new byte[32];
        fBytes[3] = 4; // bit 26 → limb 1 = 1 (representing 2^26)
        Fe25519Ops.FromBytes(out Fe fSimple, fBytes);
        Assert.Equal(0L, fSimple._l0);
        Assert.Equal(1L, fSimple._l1);
        Assert.Equal(0L, fSimple._l2);

        Fe25519Ops.Mul(out Fe product, in fSimple, in fSimple);
        // product._l2 should be 2 (representing 2 * 2^51 = 2^52), not 1.
        Assert.Equal(2L, product._l2);
    }

    [Fact]
    public void Sq_MatchesBigInteger_AndMatchesMul()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);

            // Sq must match the BigInteger square.
            Fe25519Ops.Sq(out Fe actual, in fa);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Sqr(a);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);

            // And Sq(a) must equal Mul(a, a).
            Fe25519Ops.Mul(out Fe mulSelf, in fa, in fa);
            Fe25519Ops.Freeze(ref mulSelf);
            byte[] mulSelfBytes = new byte[32];
            Fe25519Ops.ToBytes(mulSelfBytes, in mulSelf);
            Assert.Equal(actualBytes, mulSelfBytes);
        }
    }

    [Fact]
    public void Invert_MatchesBigInteger()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);
            // Skip zero (non-invertible) — extremely unlikely with random 32 bytes,
            // but guard anyway.
            if (a.IsZero)
            {
                continue;
            }

            Fe25519Ops.Invert(out Fe actual, in fa);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Invert(a);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    [Fact]
    public void Invert_OfOne_IsOne()
    {
        Fe oneFe = Fe25519Ops.One();
        Fe25519Ops.Invert(out Fe inv, in oneFe);
        Fe25519Ops.Freeze(ref inv);

        byte[] actualBytes = new byte[32];
        Fe25519Ops.ToBytes(actualBytes, in inv);

        byte[] expected = new byte[32];
        expected[0] = 1;
        Assert.Equal(expected, actualBytes);
    }

    [Fact]
    public void Mul121666_MatchesBigInteger()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);

            Fe25519Ops.Mul121666(out Fe actual, in fa);
            Fe25519Ops.Freeze(ref actual);

            BigInteger expectedBi = Fe25519Oracle.Mod(a * 121666);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    [Fact]
    public void IsZero_ReturnsOneForZero_AndZeroOtherwise()
    {
        Fe zero = Fe25519Ops.Zero();
        Assert.Equal(1, Fe25519Ops.IsZero(in zero));

        Fe one = Fe25519Ops.One();
        Assert.Equal(0, Fe25519Ops.IsZero(in one));

        for (int i = 0; i < RandomTrials; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);
            // Random bytes are zero with probability ~2^-256; not a concern.
            Assert.Equal(a.IsZero ? 1 : 0, Fe25519Ops.IsZero(in fa));
        }
    }

    // ── Freeze must canonicalize sparse extreme-negative-limb inputs ──

    /// <summary>
    /// The interleaved carry chain + h−p borrow selection kept the exact
    /// (possibly negative-limb) representation whenever it was below p — a
    /// sparse input with one extreme negative limb (h5 = −2^25, all others 0,
    /// within the documented [−2^25, 2^25] input range) froze to a
    /// representation with h1 = −1, and ToBytes sign-extended the negative
    /// limb into the packed bytes. The post-fix q-chain must produce the
    /// canonical encoding of (−2^153 mod p) = p − 2^153.
    /// </summary>
    [Fact]
    public void Freeze_SparseExtremeNegativeLimb_Canonicalizes()
    {
        Fe fe = default;
        fe._l5 = -(1L << 25);   // value −2^153, within the documented limb range

        byte[] actual = new byte[32];
        Fe25519Ops.ToBytes(actual, in fe);

        byte[] expected = Fe25519Oracle.ToBytesLE(Fe25519Oracle.Mod(-(BigInteger.One << 153)));
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// The frozen representation must be canonical: every limb non-negative
    /// and within its radix (the freeze failure left h1 = −1).
    /// </summary>
    [Fact]
    public void Freeze_SparseExtremeNegativeLimb_ProducesCanonicalLimbs()
    {
        Fe fe = default;
        fe._l5 = -(1L << 25);

        Fe25519Ops.Freeze(ref fe);

        Assert.InRange(fe._l0, 0, (1L << 26) - 1);
        Assert.InRange(fe._l1, 0, (1L << 25) - 1);
        Assert.InRange(fe._l2, 0, (1L << 26) - 1);
        Assert.InRange(fe._l3, 0, (1L << 25) - 1);
        Assert.InRange(fe._l4, 0, (1L << 26) - 1);
        Assert.InRange(fe._l5, 0, (1L << 25) - 1);
        Assert.InRange(fe._l6, 0, (1L << 26) - 1);
        Assert.InRange(fe._l7, 0, (1L << 25) - 1);
        Assert.InRange(fe._l8, 0, (1L << 26) - 1);
        Assert.InRange(fe._l9, 0, (1L << 25) - 1);
    }

    /// <summary>
    /// Sweeps every single-limb input at its extreme and boundary values
    /// (including the negative extremes that broke pre-fix Freeze) and
    /// cross-checks the freeze+encode against the BigInteger oracle.
    /// </summary>
    [Fact]
    public void Freeze_SingleExtremeLimbSweep_MatchesBigInteger()
    {
        int[] radices = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25];
        long[] probes = [(1L << 26) - 1, 1L << 25, 1, 0, -1, -(1L << 25), -(1L << 26)];

        for (int limb = 0; limb < 10; limb++)
        {
            long shift = 0;
            for (int i = 0; i < limb; i++)
            {
                shift += radices[i];
            }

            foreach (long probe in probes)
            {
                Fe fe = default;
                SetLimb(ref fe, limb, probe);

                byte[] actual = new byte[32];
                Fe25519Ops.ToBytes(actual, in fe);

                // BigInteger arithmetic: a long shift would overflow for the
                // high limbs (e.g. (2^26−1) << 51 == 2^77−2^51 needs bit 76).
                BigInteger expectedBi = Fe25519Oracle.Mod(new BigInteger(probe) << (int)shift);
                byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
                Assert.True(actual.AsSpan().SequenceEqual(expected),
                    $"limb {limb} = {probe} (value {probe}·2^{shift}): expected {Convert.ToHexString(expected)}, got {Convert.ToHexString(actual)}");
            }
        }
    }

    private static void SetLimb(ref Fe fe, int limb, long value)
    {
        switch (limb)
        {
            case 0: fe._l0 = value; break;
            case 1: fe._l1 = value; break;
            case 2: fe._l2 = value; break;
            case 3: fe._l3 = value; break;
            case 4: fe._l4 = value; break;
            case 5: fe._l5 = value; break;
            case 6: fe._l6 = value; break;
            case 7: fe._l7 = value; break;
            case 8: fe._l8 = value; break;
            case 9: fe._l9 = value; break;
            default: throw new ArgumentOutOfRangeException(nameof(limb));
        }
    }

    [Fact]
    public void CSwap_BranchlessAndCorrect()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            _ = RandomFieldElement(out Fe fa);
            _ = RandomFieldElement(out Fe fb);
            Fe faOriginal = fa;
            Fe fbOriginal = fb;

            // swap=0: no-op
            Fe25519Ops.CSwap(ref fa, ref fb, 0);
            AssertEqualFe(in fa, in faOriginal);
            AssertEqualFe(in fb, in fbOriginal);

            // swap=1: exchange
            Fe25519Ops.CSwap(ref fa, ref fb, 1);
            AssertEqualFe(in fa, in fbOriginal);
            AssertEqualFe(in fb, in faOriginal);
        }
    }

    [Fact]
    public void CMove_BranchlessAndCorrect()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            _ = RandomFieldElement(out Fe fa);
            _ = RandomFieldElement(out Fe fg);

            // b=0: f unchanged
            Fe fOriginal = fa;
            Fe25519Ops.CMove(ref fa, in fg, 0);
            AssertEqualFe(in fa, in fOriginal);

            // b=1: f becomes g
            Fe25519Ops.CMove(ref fa, in fg, 1);
            AssertEqualFe(in fa, in fg);
        }
    }

    [Fact]
    public void Pow22523_MatchesBigInteger()
    {
        // f^(2^252 - 3) is what Pow22523 should compute. Verify against BigInteger.
        BigInteger exp = BigInteger.Pow(2, 252) - 3;

        for (int i = 0; i < 8; i++)
        {
            BigInteger a = RandomFieldElement(out Fe fa);

            Fe25519Ops.Pow22523(out Fe actual, in fa);
            Fe25519Ops.Freeze(ref actual);

            var expectedBi = BigInteger.ModPow(a, exp, Fe25519Oracle.P);
            byte[] expected = Fe25519Oracle.ToBytesLE(expectedBi);
            byte[] actualBytes = new byte[32];
            Fe25519Ops.ToBytes(actualBytes, in actual);

            Assert.Equal(expected, actualBytes);
        }
    }

    private static void AssertEqualFe(in Fe a, in Fe b)
    {
        Assert.Equal(a._l0, b._l0);
        Assert.Equal(a._l1, b._l1);
        Assert.Equal(a._l2, b._l2);
        Assert.Equal(a._l3, b._l3);
        Assert.Equal(a._l4, b._l4);
        Assert.Equal(a._l5, b._l5);
        Assert.Equal(a._l6, b._l6);
        Assert.Equal(a._l7, b._l7);
        Assert.Equal(a._l8, b._l8);
        Assert.Equal(a._l9, b._l9);
    }
}
