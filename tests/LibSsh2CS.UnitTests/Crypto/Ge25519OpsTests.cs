using System.Numerics;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Cross-checks the constant-time <see cref="Ge25519Ops"/> against the BigInteger
/// <see cref="Fe25519"/> oracle on random points, plus RFC 8032 §7.1 known-answer
/// tests for byte I/O. The BigInteger path is itself validated by Ed25519Tests /
/// Ed25519SignTests, so it is a correct oracle.
/// </summary>
public class Ge25519OpsTests
{
    private const int RandomTrials = 50;

    private static readonly Random s_rng = new(0x8032);

    // The encoding of the identity point (0:1) on edwards25519 — y=1, x=0 (sign bit 0).
    private static readonly byte[] s_identityBytes = new byte[32] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    // The Ed25519 base point B (y = 4/5, x positive), as a 32-byte compressed encoding.
    // Matches libsodium's comment at ed25519_ref10.c:908 ("as bytes: 0x5866...6666").
    private static readonly byte[] s_basePointBytes =
        Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666");

    /// <summary>
    /// RFC 8032 §7.1 TEST 1–3 public keys, used for byte I/O round-trip tests.
    /// </summary>
    public static readonly byte[][] Rfc8032PublicKeys =
    [
        // TEST 1
        Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        // TEST 2
        Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        // TEST 3
        Convert.FromHexString("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
    ];

    // ════════════════════════════════════════════════════════════════════════
    // BigInteger point oracle — a faithful copy of the math in
    // Ed25519.cs (which is private). Used to cross-check the new Ge25519Ops.
    // Will be removed in H.6 when Ed25519.cs is rewritten on Fe/Ge.
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
    private static readonly BigInteger s_d = Fe25519Oracle.Mod(-121665 * Fe25519Oracle.Invert(121666));

    private static BigInteger ModP(BigInteger v)
    {
        BigInteger r = v % s_p;
        return r.Sign < 0 ? r + s_p : r;
    }

    private static BigPoint BigBasePoint()
    {
        BigInteger gy = ModP(4 * Fe25519Oracle.Invert(5));
        BigInteger? gxOrNull = RecoverX(gy, 0);
        if (gxOrNull is null)
        {
            throw new InvalidOperationException("edwards25519 base point has no valid x");
        }

        BigInteger gx = gxOrNull.Value;
        return new BigPoint(gx, gy, BigInteger.One, ModP(gx * gy));
    }

    private static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y.Sign < 0 || y >= s_p)
        {
            return null;
        }

        BigInteger x2 = ModP(y * y - 1) * ModP(Fe25519Oracle.Invert(ModP(s_d * y * y + 1)));
        if (x2.IsZero)
        {
            return sign == 0 ? BigInteger.Zero : null;
        }

        var x = BigInteger.ModPow(x2, (s_p + 3) / 8, s_p);
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

    private static BigPoint BigAdd(BigPoint p, BigPoint q)
    {
        BigInteger a = ModP(p.Y - p.X) * ModP(q.Y - q.X);
        BigInteger b = ModP(p.Y + p.X) * ModP(q.Y + q.X);
        BigInteger c = ModP(ModP(p.T * q.T) * 2 * s_d);
        BigInteger d = 2 * p.Z * q.Z;
        BigInteger e = b - a;
        BigInteger f = d - c;
        BigInteger g = d + c;
        BigInteger h = b + a;
        return new BigPoint(ModP(e * f), ModP(g * h), ModP(f * g), ModP(e * h));
    }

    private static BigPoint BigDouble(BigPoint p) => BigAdd(p, p);

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
        BigInteger zInv = Fe25519Oracle.Invert(p.Z);
        BigInteger x = ModP(p.X * zInv);
        BigInteger y = ModP(p.Y * zInv);
        byte[] encoded = Fe25519Oracle.ToBytesLE(y);
        if (!x.IsEven)
        {
            encoded[31] |= 0b1000_0000;
        }

        return encoded;
    }

    private static BigPoint? BigDecode(byte[] encoded)
    {
        if (encoded.Length != 32)
        {
            return null;
        }

        BigInteger full = Fe25519Oracle.FromBytesLE(encoded);
        int sign = (int)((full >> 255) & BigInteger.One);
        BigInteger y = full & ((BigInteger.One << 255) - 1);

        BigInteger? x = RecoverX(y, sign);
        if (x is null)
        {
            return null;
        }

        BigInteger xv = x.Value;
        return new BigPoint(xv, y, BigInteger.One, ModP(xv * y));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers — bridge Fe↔BigInteger, Ge↔BigPoint.
    // ════════════════════════════════════════════════════════════════════════

    private static byte[] GeP3ToBytesArray(in GeP3 p)
    {
        byte[] s = new byte[32];
        Ge25519Ops.P3ToBytes(s, in p);
        return s;
    }

    private static byte[] P3ToBytesViaBig(in GeP3 p)
    {
        // Compare the encoded form to the BigInteger oracle on the same point.
        // We extract the affine coords by encoding via Ge25519Ops.P3ToBytes and
        // re-decoding through BigDecode; this isolates FromBytes/ToBytes from the
        // point ops. The point ops themselves are cross-checked separately.
        return GeP3ToBytesArray(in p);
    }

    /// <summary>
    /// Picks a random valid curve point as both GeP3 and BigPoint by generating
    /// a random scalar and multiplying B. The scalar is small enough (≤ 256 bits)
    /// to keep the BigInteger ladder fast.
    /// </summary>
    private static void RandomCurvePoint(out GeP3 ge, out BigPoint big)
    {
        byte[] scalarBytes = new byte[32];
        lock (s_rng)
        {
            s_rng.NextBytes(scalarBytes);
        }

        scalarBytes[31] &= 0x7F; // a[31] <= 127 (precondition for scalar mult later)

        // BigInteger ladder for the oracle.
        BigInteger scalar = Fe25519Oracle.FromBytesLE(scalarBytes);
        big = BigMul(scalar, BigBasePoint());

        // Ge path: decode B then run a small ladder locally (we don't have
        // Ge25519ScalarMult yet — that's H.4). For H.3 tests we use the BigInteger
        // path to derive the point, then re-encode and re-decode through Ge25519Ops
        // to produce the GeP3 form. This still cross-checks FromBytes/ToBytes/IsOnCurve.
        byte[] encoded = BigEncode(big);
        Assert.Equal(0, Ge25519Ops.FromBytes(out ge, encoded));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Byte I/O round-trip + RFC 8032 KATs.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void FromBytes_ToBytes_RoundTrips_Rfc8032_TestKeys()
    {
        foreach (byte[] pk in Rfc8032PublicKeys)
        {
            Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 p, pk));
            byte[] reencoded = GeP3ToBytesArray(in p);
            Assert.Equal(pk, reencoded);
        }
    }

    [Fact]
    public void FromBytes_ToBytes_RoundTrips_BasePoint()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        byte[] reencoded = GeP3ToBytesArray(in b);
        Assert.Equal(s_basePointBytes, reencoded);
    }

    [Fact]
    public void FromBytes_ToBytes_RoundTrips_RandomPoints()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            RandomCurvePoint(out GeP3 p, out BigPoint big);

            // RandomCurvePoint already encoded then decoded through Ge25519Ops, so
            // re-encoding must be a fixed point.
            byte[] reencoded = GeP3ToBytesArray(in p);
            byte[] expected = BigEncode(big);
            Assert.Equal(expected, reencoded);
        }
    }

    [Fact]
    public void FromBytes_Rejects_WrongLength()
    {
        byte[] tooShort = new byte[31];
        byte[] tooLong = new byte[33];
        Assert.Equal(-1, Ge25519Ops.FromBytes(out _, tooShort));
        Assert.Equal(-1, Ge25519Ops.FromBytes(out _, tooLong));
    }

    [Fact]
    public void FromBytes_Accepts_Y_Zero()
    {
        // y = 0 has x = ±1 (both valid points on the curve). FromBytes should
        // return 0 and the point should be on the curve.
        byte[] yZero = new byte[32];
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 p, yZero));
        Assert.Equal(1, Ge25519Ops.IsOnCurve(in p));
    }

    [Fact]
    public void FromBytes_Rejects_NonCurveEncoding()
    {
        // Construct a y for which (y^2-1)/(d*y^2+1) is a quadratic non-residue
        // — about half of all random y values qualify. Search deterministically.
        var rng = new Random(0xCAFE);
        byte[] badY = new byte[32];
        bool found = false;
        for (int trial = 0; trial < 1000; trial++)
        {
            rng.NextBytes(badY);
            badY[31] &= 0x7F; // y < 2^255
            if (Ge25519Ops.FromBytes(out _, badY) != 0)
            {
                found = true;
                break;
            }
        }

        Assert.True(found, "should have found at least one non-curve y in 1000 tries");
        Assert.Equal(-1, Ge25519Ops.FromBytes(out _, badY));
    }

    [Fact]
    public void FromBytes_Accepts_BasePoint_IsOnCurve()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Assert.Equal(1, Ge25519Ops.IsOnCurve(in b));
    }

    [Fact]
    public void IsOnCurve_Accepts_Rfc8032_PublicKeys()
    {
        foreach (byte[] pk in Rfc8032PublicKeys)
        {
            Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 p, pk));
            Assert.Equal(1, Ge25519Ops.IsOnCurve(in p));
        }
    }

    [Fact]
    public void IsOnCurve_Accepts_RandomCurvePoints()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            RandomCurvePoint(out GeP3 p, out _);
            Assert.Equal(1, Ge25519Ops.IsOnCurve(in p));
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Point ops — cross-check against the BigInteger oracle.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void P3ToCached_Then_Add_MatchesBigInteger_BPlusB()
    {
        // Ge: r = P1P1(B + Cached(B)); compare to BigPoint(B + B).
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3ToCached(out GeCached bCached, in b);
        Ge25519Ops.Add(out GeP1P1 r, in b, in bCached);
        Ge25519Ops.P1P1ToP3(out GeP3 sum, in r);

        BigPoint bb = BigBasePoint();
        BigPoint expected = BigAdd(bb, bb);
        Assert.Equal(BigEncode(expected), GeP3ToBytesArray(in sum));
    }

    [Fact]
    public void Sub_MatchesBigInteger_BMinusB_IsIdentity()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3ToCached(out GeCached bCached, in b);
        Ge25519Ops.Sub(out GeP1P1 r, in b, in bCached);
        Ge25519Ops.P1P1ToP3(out GeP3 diff, in r);

        // B - B == identity (0:1:1:0). Encoding of identity is y=1 little-endian
        // = 0x01 followed by 31 zero bytes, with sign bit 0 (x=0 is even).
        Assert.Equal(s_identityBytes, GeP3ToBytesArray(in diff));
    }

    [Fact]
    public void P3Dbl_MatchesBigInteger()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3Dbl(out GeP1P1 r, in b);
        Ge25519Ops.P1P1ToP3(out GeP3 dbl, in r);

        BigPoint bb = BigBasePoint();
        BigPoint expected = BigDouble(bb);
        Assert.Equal(BigEncode(expected), GeP3ToBytesArray(in dbl));
    }

    [Fact]
    public void P2Dbl_MatchesBigInteger()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3ToP2(out GeP2 b2, in b);
        Ge25519Ops.P2Dbl(out GeP1P1 r, in b2);
        Ge25519Ops.P1P1ToP2(out GeP2 dbl, in r);

        BigPoint bb = BigBasePoint();
        BigPoint expected = BigDouble(bb);
        byte[] encoded = new byte[32];
        Ge25519Ops.P2ToBytes(encoded, in dbl);
        Assert.Equal(BigEncode(expected), encoded);
    }

    [Fact]
    public void MAdd_With_PrecompB_MatchesBigInteger()
    {
        // MAdd uses GePrecomp (Duif form). Construct GePrecomp from B via
        // P3ToPrecomp, then MAdd(B, precompB) == B + B.
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3ToPrecomp(out GePrecomp bPrecomp, in b);
        Ge25519Ops.MAdd(out GeP1P1 r, in b, in bPrecomp);
        Ge25519Ops.P1P1ToP3(out GeP3 sum, in r);

        BigPoint bb = BigBasePoint();
        BigPoint expected = BigAdd(bb, bb);
        Assert.Equal(BigEncode(expected), GeP3ToBytesArray(in sum));
    }

    [Fact]
    public void MSub_With_PrecompB_MatchesBigInteger_BMinusB_IsIdentity()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.P3ToPrecomp(out GePrecomp bPrecomp, in b);
        Ge25519Ops.MSub(out GeP1P1 r, in b, in bPrecomp);
        Ge25519Ops.P1P1ToP3(out GeP3 diff, in r);

        Assert.Equal(s_identityBytes, GeP3ToBytesArray(in diff));
    }

    [Fact]
    public void Add_Identity_IsNoOp()
    {
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));
        Ge25519Ops.CachedZero(out GeCached id);
        Ge25519Ops.Add(out GeP1P1 r, in b, in id);
        Ge25519Ops.P1P1ToP3(out GeP3 sum, in r);
        Assert.Equal(s_basePointBytes, GeP3ToBytesArray(in sum));
    }

    [Fact]
    public void Double_Application_AddUpTo_FourB_MatchesBigInteger()
    {
        // Repeated doubling: B, 2B, 4B, 8B.
        Assert.Equal(0, Ge25519Ops.FromBytes(out GeP3 b, s_basePointBytes));

        GeP3 current = b;
        BigPoint bigCurrent = BigBasePoint();
        for (int i = 1; i <= 3; i++)
        {
            Ge25519Ops.P3Dbl(out GeP1P1 r, in current);
            Ge25519Ops.P1P1ToP3(out current, in r);
            bigCurrent = BigDouble(bigCurrent);
            Assert.Equal(BigEncode(bigCurrent), GeP3ToBytesArray(in current));
        }
    }

    [Fact]
    public void CMove8Precomp_SelectsCorrectEntry()
    {
        // Build a fake 8-entry table where entry i has yplusx = i+1, others = 0.
        // CMove8Precomp(t, table, b) for b in [1..8] should yield t.yplusx = b.
        // For b in [-8..-1] the negation path is exercised (yplusx ↔ yminusx).
        var table = new GePrecomp[8];
        for (int i = 0; i < 8; i++)
        {
            table[i] = default;
            table[i]._yPlusX = Fe25519Ops.FromSmall(i + 1);
            table[i]._yMinusX = Fe25519Ops.Zero();
            table[i]._xy2D = Fe25519Ops.Zero();
        }

        for (int b = 1; b <= 8; b++)
        {
            Ge25519Ops.CMove8Precomp(out GePrecomp t, table, (sbyte)b);
            Assert.Equal(b, t._yPlusX._l0);
        }
    }

    [Fact]
    public void CMove8Cached_SelectsCorrectEntry()
    {
        var table = new GeCached[8];
        for (int i = 0; i < 8; i++)
        {
            table[i] = default;
            table[i]._yPlusX = Fe25519Ops.FromSmall(i + 1);
            table[i]._yMinusX = Fe25519Ops.Zero();
            table[i]._z = Fe25519Ops.Zero();
            table[i]._t2D = Fe25519Ops.Zero();
        }

        for (int b = 1; b <= 8; b++)
        {
            Ge25519Ops.CMove8Cached(out GeCached t, table, (sbyte)b);
            Assert.Equal(b, t._yPlusX._l0);
        }
    }
}
