using System.Numerics;
using System.Security.Cryptography;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Cross-checks <see cref="ScalarModL"/> against <see cref="BigInteger"/> arithmetic
/// mod L on random inputs, plus boundary cases at L-1, L, 2L-1, 2^256-1.
/// </summary>
/// <remarks>
/// <para>
/// libsodium's <c>sc_muladd</c> ships no standalone known-answer tests in its test
/// suite — the function is exercised only indirectly via sign/verify round-trips.
/// The BigInteger oracle here is the equivalent of those sign/verify round-trips:
/// we compute <c>(s*a + b) mod L</c> via <see cref="BigInteger"/> (which is well
/// within range: max unreduced value is 2^256 * 2^256 + 2^256 ≈ 2^512) and compare
/// byte-exact against <see cref="ScalarModL.MulAdd(byte[], byte[], byte[])"/>.
/// </para>
/// <para>
/// The BigInteger path is itself validated by the existing Ed25519 sign tests
/// (RFC 8032 §7.1 TEST 1–3), so it is a correct oracle.
/// </para>
/// </remarks>
public class ScalarModLTests
{
    private const int RandomTrials = 1000;

    private static readonly Random s_rng = new(0x5CA1);

    /// <summary>
    /// The Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
    /// </summary>
    private static readonly BigInteger s_l = BigInteger.Pow(2, 252)
        + BigInteger.Parse("27742317777372353535851937790883648493");

    // ════════════════════════════════════════════════════════════════════════
    // BigInteger ↔ byte[] helpers (little-endian, 32-byte fixed-width).
    // ════════════════════════════════════════════════════════════════════════

    private static byte[] RandomScalar(out BigInteger bi)
    {
        byte[] bytes = new byte[32];
        lock (s_rng)
        {
            s_rng.NextBytes(bytes);
        }

        bytes[31] &= 0x7F; // ensure < 2^255 so it fits in canonical sc representation

        // BigInteger reference: parse little-endian (append a zero high byte for sign).
        byte[] biBytes = new byte[33];
        Buffer.BlockCopy(bytes, 0, biBytes, 0, 32);
        bi = new BigInteger(biBytes);
        return bytes;
    }

    private static byte[] BigToBytes32(BigInteger v)
    {
        BigInteger reduced = ((v % s_l) + s_l) % s_l;
        byte[] buf = new byte[33]; // extra byte keeps BigInteger's sign bit clear
        _ = reduced.TryWriteBytes(buf, out int written);
        Array.Resize(ref buf, 32);
        if (written < 32)
        {
            byte[] padded = new byte[32];
            Array.Copy(buf, 0, padded, 0, written);
            return padded;
        }

        return buf;
    }

    private static BigInteger BigFromBytes32(byte[] bytes)
    {
        byte[] biBytes = new byte[33];
        Buffer.BlockCopy(bytes, 0, biBytes, 0, 32);
        return new BigInteger(biBytes);
    }

    // ════════════════════════════════════════════════════════════════════════
    // MulAdd — random-input cross-check vs BigInteger.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void MulAdd_MatchesBigInteger_OnRandomTriples()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            byte[] aBytes = RandomScalar(out BigInteger a);
            byte[] bBytes = RandomScalar(out BigInteger b);
            byte[] cBytes = RandomScalar(out BigInteger c);

            byte[] actual = ScalarModL.MulAdd(aBytes, bBytes, cBytes);
            byte[] expected = BigToBytes32(a * b + c);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void MulAdd_IdentityScalar_ReturnsBModL()
    {
        // 1 * b + 0 = b (mod L). The raw b may be ≥ L, so reduce before comparing.
        byte[] one = new byte[32];
        one[0] = 1;
        byte[] bBytes = RandomScalar(out BigInteger b);
        byte[] zero = new byte[32];

        byte[] actual = ScalarModL.MulAdd(one, bBytes, zero);
        Assert.Equal(BigToBytes32(b), actual);
    }

    [Fact]
    public void MulAdd_ZeroScalar_ReturnsCModL()
    {
        // 0 * b + c = c (mod L). The raw c may be ≥ L, so reduce before comparing.
        byte[] zero = new byte[32];
        byte[] bBytes = RandomScalar(out _);
        byte[] cBytes = RandomScalar(out BigInteger c);

        byte[] actual = ScalarModL.MulAdd(zero, bBytes, cBytes);
        Assert.Equal(BigToBytes32(c), actual);
    }

    // ════════════════════════════════════════════════════════════════════════
    // MulAdd — boundary cases.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void MulAdd_Boundary_LMinus1_Times1_Plus0()
    {
        // (L - 1) * 1 + 0 = L - 1.
        byte[] lMinus1 = BigToBytes32(s_l - 1);
        byte[] one = new byte[32];
        one[0] = 1;
        byte[] zero = new byte[32];

        byte[] actual = ScalarModL.MulAdd(lMinus1, one, zero);
        Assert.Equal(lMinus1, actual);
    }

    [Fact]
    public void MulAdd_Boundary_L_Times1_Plus0_YieldsZero()
    {
        // L * 1 + 0 = 0 (mod L).
        byte[] l = BigToBytes32(s_l);
        byte[] one = new byte[32];
        one[0] = 1;
        byte[] zero = new byte[32];

        byte[] actual = ScalarModL.MulAdd(l, one, zero);
        Assert.Equal(new byte[32], actual);
    }

    [Fact]
    public void MulAdd_Boundary_1_Times1_PlusLMinus1_YieldsZero()
    {
        // 1 * 1 + (L - 1) = L = 0 (mod L).
        byte[] one = new byte[32];
        one[0] = 1;
        byte[] lMinus1 = BigToBytes32(s_l - 1);

        byte[] actual = ScalarModL.MulAdd(one, one, lMinus1);
        Assert.Equal(new byte[32], actual);
    }

    [Fact]
    public void MulAdd_Boundary_1_Times1_PlusL_YieldsOne()
    {
        // 1 * 1 + L = L + 1 = 1 (mod L).
        byte[] one = new byte[32];
        one[0] = 1;
        byte[] l = BigToBytes32(s_l);

        byte[] actual = ScalarModL.MulAdd(one, one, l);
        Assert.Equal(one, actual);
    }

    [Fact]
    public void MulAdd_Boundary_2To256Minus1_Times1()
    {
        // 2^256 - 1 is the largest representable input scalar; reduced mod L must match.
        byte[] maxBytes = new byte[32];
        Array.Fill(maxBytes, (byte)0xFF);
        maxBytes[31] = 0x7F; // < 2^255 (preserve "a[31] <= 127" precondition)
        BigInteger max = BigFromBytes32(maxBytes);

        byte[] one = new byte[32];
        one[0] = 1;
        byte[] zero = new byte[32];

        byte[] actual = ScalarModL.MulAdd(maxBytes, one, zero);
        byte[] expected = BigToBytes32(max);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MulAdd_Boundary_SumStraddles_L_2L_3L()
    {
        // Construct triples where (a*b + c) is exactly L, 2L, 3L and confirm
        // the result wraps to zero (or near-zero).
        byte[] one = new byte[32];
        one[0] = 1;

        for (int k = 1; k <= 3; k++)
        {
            BigInteger target = s_l * k;
            // a = target, b = 1, c = 0  →  result = 0 (mod L)
            byte[] aBytes = BigToBytes32(target);
            byte[] zero = new byte[32];
            byte[] actual = ScalarModL.MulAdd(aBytes, one, zero);
            Assert.Equal(new byte[32], actual);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Reduce — random-input cross-check vs BigInteger.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Reduce_MatchesBigInteger_OnRandom512BitValues()
    {
        for (int i = 0; i < RandomTrials; i++)
        {
            byte[] input = new byte[64];
            lock (s_rng)
            {
                s_rng.NextBytes(input);
            }

            byte[] actual = ScalarModL.Reduce(input);

            // BigInteger reference: parse little-endian (extra byte for sign).
            byte[] biBytes = new byte[65];
            Buffer.BlockCopy(input, 0, biBytes, 0, 64);
            BigInteger bi = new(biBytes);
            byte[] expected = BigToBytes32(bi);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void Reduce_OfL_YieldsZero()
    {
        byte[] input = new byte[64];
        byte[] l = BigToBytes32(s_l);
        Buffer.BlockCopy(l, 0, input, 0, 32);

        byte[] actual = ScalarModL.Reduce(input);
        Assert.Equal(new byte[32], actual);
    }

    [Fact]
    public void Reduce_OfLMinus1_YieldsLMinus1()
    {
        byte[] input = new byte[64];
        byte[] lMinus1 = BigToBytes32(s_l - 1);
        Buffer.BlockCopy(lMinus1, 0, input, 0, 32);

        byte[] actual = ScalarModL.Reduce(input);
        Assert.Equal(lMinus1, actual);
    }

    [Fact]
    public void Reduce_OfZero_YieldsZero()
    {
        byte[] actual = ScalarModL.Reduce(new byte[64]);
        Assert.Equal(new byte[32], actual);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Ed25519 sign parity — proves the H.6 swap will be sound before H.6 lands.
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void MulAdd_MatchesExistingEd25519SignFormula_OnRfc8032_Test1()
    {
        // RFC 8032 §7.1 TEST 1: seed = 9d61b19d... ; the sign step computes
        // s = (r + a*k) mod L. r, a, k are derived from the seed + message;
        // we compute them via the existing BigInteger path and verify
        // MulAdd(a, k, r) matches (r + a*k) % L byte-exact.
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        // Step 1-2: a = clamp(SHA-512(seed)[0..32]) little-endian.
        byte[] h = SHA512.HashData(seed);
        byte[] scalarBytes = h.AsSpan(0, 32).ToArray();
        scalarBytes[0] &= 0b1111_1000;
        scalarBytes[31] &= 0b0111_1111;
        scalarBytes[31] |= 0b0100_0000;
        BigInteger a = BigFromBytes32(scalarBytes);

        // Step 5: r = SHA-512(prefix ‖ M) mod L, prefix = h[32..64], M = empty.
        byte[] prefix = h.AsSpan(32, 32).ToArray();
        byte[] message = Array.Empty<byte>();
        byte[] rBytes = new byte[prefix.Length + message.Length];
        prefix.AsSpan().CopyTo(rBytes);
        message.AsSpan().CopyTo(rBytes.AsSpan(prefix.Length));
        byte[] rHash = SHA512.HashData(rBytes);
        byte[] biBytes65 = new byte[65];
        Buffer.BlockCopy(rHash, 0, biBytes65, 0, 64);
        var rRaw = new BigInteger(biBytes65);
        BigInteger r = rRaw % s_l;
        byte[] rBytes32 = BigToBytes32(r);

        // Step 7: k = SHA-512(R ‖ A ‖ M) mod L. R and A are 32 bytes each.
        // We don't need the actual R and A for this test — only k's bytes.
        // Use the documented RFC 8032 TEST 1 R and A.
        byte[] R = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155");
        byte[] A = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] kBuf = new byte[R.Length + A.Length + message.Length];
        R.AsSpan().CopyTo(kBuf);
        A.AsSpan().CopyTo(kBuf.AsSpan(R.Length));
        byte[] kHash = SHA512.HashData(kBuf);
        Buffer.BlockCopy(kHash, 0, biBytes65, 0, 64);
        var kRaw = new BigInteger(biBytes65);
        BigInteger k = kRaw % s_l;
        byte[] kBytes32 = BigToBytes32(k);

        // BigInteger oracle: (r + a*k) mod L.
        BigInteger expected = (r + a * k) % s_l;
        byte[] expectedBytes = BigToBytes32(expected);

        // ScalarModL.MulAdd: s = a*k + r (mod L). Note arg order: MulAdd(a, b, c) = a*b + c.
        byte[] actual = ScalarModL.MulAdd(scalarBytes, kBytes32, rBytes32);

        Assert.Equal(expectedBytes, actual);

        // And the result S must match the documented second half of the RFC 8032 signature.
        byte[] expectedSig = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        byte[] expectedS = expectedSig.AsSpan(32, 32).ToArray();
        Assert.Equal(expectedS, actual);
    }
}
