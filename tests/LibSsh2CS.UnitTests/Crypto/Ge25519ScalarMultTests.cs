using System.Numerics;
using System.Security.Cryptography;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Cross-checks <see cref="Ge25519ScalarMult"/> against the BigInteger point-multiplication
/// oracle and the RFC 8032 §7.1 known-answer vectors. The BigInteger oracle is itself
/// validated by the existing Ed25519Tests / Ed25519SignTests.
/// </summary>
public class Ge25519ScalarMultTests
{
    private const int RandomTrials = 50;

    private static readonly Random s_rng = new(0x5CA1);

    // The Ed25519 base point B (y = 4/5, x positive).
    private static readonly byte[] s_basePointBytes =
        Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666");

    // ════════════════════════════════════════════════════════════════════════
    // BigInteger point oracle — same shape as in Ge25519OpsTests. Will be
    // removed in H.6 when Ed25519.cs is rewritten.
    // ════════════════════════════════════════════════════════════════════════

    private readonly struct BigPoint
    {
        public BigInteger X { get; }
        public BigInteger Y { get; }
        public BigInteger Z { get; }
        public BigInteger T { get; }

        public BigPoint(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
        {
            X = x;
            Y = y;
            Z = z;
            T = t;
        }
    }

    private static readonly BigInteger s_p = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger s_d = ModP(-121665 * BigInteger.ModPow(121666, s_p - 2, s_p));

    private static BigInteger ModP(BigInteger v)
    {
        BigInteger r = v % s_p;
        return r.Sign < 0 ? r + s_p : r;
    }

    private static BigPoint BigBasePoint()
    {
        BigInteger gy = ModP(4 * BigInteger.ModPow(5, s_p - 2, s_p));
        BigInteger? x = RecoverX(gy, 0);
        if (x is null)
        {
            throw new InvalidOperationException("base point has no valid x");
        }

        BigInteger xv = x.Value;
        return new BigPoint(xv, gy, BigInteger.One, ModP(xv * gy));
    }

    private static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y.Sign < 0 || y >= s_p)
        {
            return null;
        }

        BigInteger x2 = ModP((y * y - 1) * BigInteger.ModPow(ModP(s_d * y * y + 1), s_p - 2, s_p));
        if (x2.IsZero)
        {
            return sign == 0 ? BigInteger.Zero : null;
        }

        BigInteger x;
        x = BigInteger.ModPow(x2, (s_p + 3) / 8, s_p);
        if (!ModP(x * x - x2).IsZero)
        {
            x = ModP(x * BigInteger.ModPow(2, (s_p - 1) / 4, s_p));
            if (!ModP(x * x - x2).IsZero)
            {
                return null;
            }
        }

        if ((int)(x & BigInteger.One) != sign)
        {
            x = s_p - x;
        }

        return x;
    }

    private static BigPoint BigAdd(BigPoint pp, BigPoint q)
    {
        BigInteger a = ModP(pp.Y - pp.X) * ModP(q.Y - q.X);
        BigInteger b = ModP(pp.Y + pp.X) * ModP(q.Y + q.X);
        BigInteger c = ModP(ModP(pp.T * q.T) * 2 * s_d);
        BigInteger d = 2 * pp.Z * q.Z;
        BigInteger e = b - a;
        BigInteger f = d - c;
        BigInteger g = d + c;
        BigInteger h = b + a;
        return new BigPoint(ModP(e * f), ModP(g * h), ModP(f * g), ModP(e * h));
    }

    private static BigPoint BigMul(BigInteger s, BigPoint p)
    {
        BigPoint q = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        while (s.Sign > 0)
        {
            if ((s & BigInteger.One) != BigInteger.Zero)
            {
                q = BigAdd(q, p);
            }

            p = BigAdd(p, p);
            s >>= 1;
        }

        return q;
    }

    private static byte[] BigEncode(BigPoint p)
    {
        var zInv = BigInteger.ModPow(p.Z, s_p - 2, s_p);
        BigInteger x = ModP(p.X * zInv);
        BigInteger y = ModP(p.Y * zInv);
        byte[] buf = new byte[33];
        _ = y.TryWriteBytes(buf, out _);
        Array.Resize(ref buf, 32);
        if (!x.IsEven)
        {
            buf[31] |= 0b1000_0000;
        }

        return buf;
    }

    private static byte[] RandomScalar()
    {
        byte[] bytes = new byte[32];
        lock (s_rng)
        {
            s_rng.NextBytes(bytes);
        }

        bytes[31] &= 0x7F; // a[31] <= 127 (scalarmult precondition)
        return bytes;
    }

    private static byte[] GeP3ToBytes(in GeP3 p)
    {
        byte[] s = new byte[32];
        Ge25519Ops.P3ToBytes(s, in p);
        return s;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Base — fixed-base scalar mult.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Base_OfOne_YieldsBasePoint()
    {
        // a = 1 → B. (Scalar representation: byte 0 = 1, rest zero. a[31] = 0 ≤ 127.)
        byte[] one = new byte[32];
        one[0] = 1;

        Ge25519ScalarMult.Base(out GeP3 h, one);
        Assert.Equal(s_basePointBytes, GeP3ToBytes(in h));
    }

    [Fact]
    public void Base_OfZero_YieldsIdentity()
    {
        Ge25519ScalarMult.Base(out GeP3 h, new byte[32]);

        // Identity encoding is 0x01 followed by 31 zeros.
        byte[] identityBytes = new byte[32] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        Assert.Equal(identityBytes, GeP3ToBytes(in h));
    }

    [Fact]
    public void Base_OfTwo_EqualsDoubleOfBasePoint()
    {
        // a = 2 → 2B. Cross-check: build 2B via Ge25519Ops doubling of B.
        byte[] two = new byte[32];
        two[0] = 2;

        Ge25519ScalarMult.Base(out GeP3 h, two);

        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3Dbl(out GeP1P1 r, in b);
        Ge25519Ops.P1P1ToP3(out GeP3 dbl, in r);
        Assert.Equal(GeP3ToBytes(in dbl), GeP3ToBytes(in h));
    }

    [Fact]
    public void Base_OfLMinus1_Equals_NegatedBasePoint()
    {
        // a = L-1. [L-1]B = -B (since [L]B = identity). -B has the same y as B
        // but the opposite sign of x, so its encoding has the high bit set.
        BigInteger l = BigInteger.Pow(2, 252)
            + BigInteger.Parse("27742317777372353535851937790883648493");
        BigInteger lMinus1 = l - 1;
        byte[] aBytes = new byte[33];
        _ = lMinus1.TryWriteBytes(aBytes, out int _);
        Array.Resize(ref aBytes, 32);

        Ge25519ScalarMult.Base(out GeP3 h, aBytes);
        byte[] encoded = GeP3ToBytes(in h);

        // Expected: base point encoding with the high bit of byte 31 set.
        byte[] expected = (byte[])s_basePointBytes.Clone();
        expected[31] |= 0b1000_0000;
        Assert.Equal(expected, encoded);
    }

    [Fact]
    public void Base_OfL_YieldsIdentity()
    {
        // a = L. [L]B = identity (B is in the prime-order subgroup).
        BigInteger l = BigInteger.Pow(2, 252)
            + BigInteger.Parse("27742317777372353535851937790883648493");
        byte[] aBytes = new byte[33];
        _ = l.TryWriteBytes(aBytes, out int _);
        Array.Resize(ref aBytes, 32);

        Ge25519ScalarMult.Base(out GeP3 h, aBytes);
        byte[] identityBytes = new byte[32] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        Assert.Equal(identityBytes, GeP3ToBytes(in h));
    }

    [Fact]
    public void Base_OfRandomScalars_MatchesBigIntegerOracle()
    {
        BigPoint b = BigBasePoint();
        for (int i = 0; i < RandomTrials; i++)
        {
            byte[] aBytes = RandomScalar();
            BigInteger a = BigFromBytes32(aBytes);

            Ge25519ScalarMult.Base(out GeP3 h, aBytes);
            BigPoint expected = BigMul(a, b);
            Assert.Equal(BigEncode(expected), GeP3ToBytes(in h));
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Base — RFC 8032 §7.1 known-answer. Reconstructing the documented public
    // key from the documented seed proves the table + ladder are correct.
    // ════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")]
    [InlineData(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")]
    [InlineData(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")]
    public void Base_Rfc8032_Test1To3_PublicKeyFromSeed_MatchesDocumented(
        string seedHex, string expectedPkHex)
    {
        // RFC 8032 §5.1.5 step 2: a = clamp(SHA-512(seed)[0..32]).
        byte[] seed = Convert.FromHexString(seedHex);
        byte[] h = SHA512.HashData(seed);
        byte[] scalarBytes = h.AsSpan(0, 32).ToArray();
        scalarBytes[0] &= 0b1111_1000;
        scalarBytes[31] &= 0b0111_1111;
        scalarBytes[31] |= 0b0100_0000;

        Ge25519ScalarMult.Base(out GeP3 a, scalarBytes);
        byte[] actualPk = GeP3ToBytes(in a);

        Assert.Equal(Convert.FromHexString(expectedPkHex), actualPk);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Base — table consistency invariant: [8]B == sum(table[0][0..7]).
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Base_Table8B_Equals_SumOfTable0Row()
    {
        // table[0][j-1] = j * B for j in 1..8. Summing all 8 entries via MAdd gives
        // (1+2+3+4+5+6+7+8) * B = 36 * B.
        // Cross-check: Base(36) must equal the running sum.
        Assert.Equal(0, Ge25519Ops.FromBytes(out _, s_basePointBytes));

        Ge25519Ops.P3Zero(out GeP3 sum);
        for (int j = 0; j < 8; j++)
        {
            GePrecomp entry = GeBasepointTable.Table[0, j];
            Ge25519Ops.MAdd(out GeP1P1 r, in sum, in entry);
            Ge25519Ops.P1P1ToP3(out sum, in r);
        }

        byte[] sumEncoded = GeP3ToBytes(in sum);

        // 36 * B via Base.
        byte[] scalar36 = new byte[32];
        scalar36[0] = 36;
        Ge25519ScalarMult.Base(out GeP3 thirtySixB, scalar36);
        Assert.Equal(GeP3ToBytes(in thirtySixB), sumEncoded);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ScalarMult — variable-base.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void ScalarMult_OfOne_YieldsInputPoint()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        byte[] one = new byte[32];
        one[0] = 1;

        Ge25519ScalarMult.ScalarMult(out GeP3 h, one, in b);
        Assert.Equal(s_basePointBytes, GeP3ToBytes(in h));
    }

    [Fact]
    public void ScalarMult_OfZero_YieldsIdentity()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));

        Ge25519ScalarMult.ScalarMult(out GeP3 h, new byte[32], in b);
        byte[] identityBytes = new byte[32] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        Assert.Equal(identityBytes, GeP3ToBytes(in h));
    }

    [Fact]
    public void ScalarMult_OfTwo_EqualsDoubleOfInput()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        byte[] two = new byte[32];
        two[0] = 2;

        Ge25519ScalarMult.ScalarMult(out GeP3 h, two, in b);

        // Cross-check: 2B via doubling.
        Ge25519Ops.P3Dbl(out GeP1P1 r, in b);
        Ge25519Ops.P1P1ToP3(out GeP3 dbl, in r);
        Assert.Equal(GeP3ToBytes(in dbl), GeP3ToBytes(in h));
    }

    [Fact]
    public void ScalarMult_OfRandomScalarsAndPoints_MatchesBigIntegerOracle()
    {
        BigPoint bBig = BigBasePoint();
        for (int i = 0; i < RandomTrials; i++)
        {
            byte[] aBytes = RandomScalar();
            BigInteger a = BigFromBytes32(aBytes);

            // Pick a random point by random-scalar-multiplying B.
            byte[] pScalar = RandomScalar();
            Ge25519ScalarMult.Base(out GeP3 pGe, pScalar);
            BigInteger pScalarBi = BigFromBytes32(pScalar);
            BigPoint pBig = BigMul(pScalarBi, bBig);

            Ge25519ScalarMult.ScalarMult(out GeP3 h, aBytes, in pGe);
            BigPoint expected = BigMul(a, pBig);
            Assert.Equal(BigEncode(expected), GeP3ToBytes(in h));
        }
    }

    [Fact]
    public void ScalarMult_OfLMinus1_OfBasePoint_Equals_NegatedBasePoint()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        BigInteger l = BigInteger.Pow(2, 252)
            + BigInteger.Parse("27742317777372353535851937790883648493");
        BigInteger lMinus1 = l - 1;
        byte[] aBytes = new byte[33];
        _ = lMinus1.TryWriteBytes(aBytes, out int _);
        Array.Resize(ref aBytes, 32);

        Ge25519ScalarMult.ScalarMult(out GeP3 h, aBytes, in b);
        byte[] encoded = GeP3ToBytes(in h);
        byte[] expected = (byte[])s_basePointBytes.Clone();
        expected[31] |= 0b1000_0000;
        Assert.Equal(expected, encoded);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Arg validation.
    // ════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void Base_WrongScalarLength_Throws(int len)
    {
        byte[] a = new byte[len];
        Assert.Throws<ArgumentException>(() => Ge25519ScalarMult.Base(out _, a));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void ScalarMult_WrongScalarLength_Throws(int len)
    {
        byte[] a = new byte[len];
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Assert.Throws<ArgumentException>(() => Ge25519ScalarMult.ScalarMult(out _, a, in b));
    }

    private static BigInteger BigFromBytes32(byte[] bytes)
    {
        byte[] biBytes = new byte[33];
        Buffer.BlockCopy(bytes, 0, biBytes, 0, 32);
        return new BigInteger(biBytes);
    }
}
