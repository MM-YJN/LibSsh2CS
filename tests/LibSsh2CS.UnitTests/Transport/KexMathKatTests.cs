using System.Numerics;
using System.Security.Cryptography;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Golden KATs for the increment-7 KEX math: <see cref="KeyExchange.ComputeExchangeHash"/>
/// and <see cref="KeyExchange.DeriveKey"/>, driven by the captured
/// <c>Fixtures/kex/&lt;method&gt;/</c> oracles (5 KEX methods, one live
/// libssh2→OpenSSH handshake each). These are the parity-critical tests — they
/// pin the field order, the string-vs-mpint encoding, the hash-per-curve
/// selection, and the RFC 4253 §7.2 key-derivation loop against the reference.
/// </summary>
public class KexMathKatTests
{
    // The 5 in-scope KEX methods, as (method-dir, KexAlgorithm) pairs. The dir
    // name carries the hyphens; KexFixtureLoader applies the MSBuild rewrite.
    public static TheoryData<string> Methods => new()
    {
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
    };

    [Theory]
    [MemberData(nameof(Methods))]
    public void ComputeExchangeHash_MatchesCapturedOracle(string methodDir)
    {
        KexFixture fx = KexFixtureLoader.Load(methodDir);
        KexAlgorithm alg = KexMethods.Lookup(fx.Kex);
        BigInteger k = Endian.BigIntegerFromBigEndian(fx.SharedSecret);

        byte[] h = KeyExchange.ComputeExchangeHash(
            alg,
            fx.ClientBanner,
            fx.ServerBanner,
            fx.ClientKexInit,
            fx.ServerKexInit,
            fx.HostKey,
            fx.ClientEphemeral,
            fx.ServerEphemeral,
            k);

        Assert.Equal(fx.ExchangeHash, h);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void DeriveKey_AllSixKeys_MatchCapturedOracle(string methodDir)
    {
        KexFixture fx = KexFixtureLoader.Load(methodDir);
        KexAlgorithm alg = KexMethods.Lookup(fx.Kex);
        BigInteger k = Endian.BigIntegerFromBigEndian(fx.SharedSecret);

        // First kex: session_id == H (per kex.c:808-821).
        byte[] sessionId = fx.ExchangeHash;
        byte[] h = fx.ExchangeHash;

        foreach (char letter in "ABCDEF")
        {
            byte[] expected = Convert.FromHexString(fx.DerivedKeys[letter.ToString()]);
            byte[] got = KeyExchange.DeriveKey(alg, k, h, sessionId, letter, expected.Length);
            Assert.Equal(expected, got);
        }
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void HashDigestLength_MatchesCapturedHashSize(string methodDir)
    {
        KexFixture fx = KexFixtureLoader.Load(methodDir);
        KexAlgorithm alg = KexMethods.Lookup(fx.Kex);

        Assert.Equal(fx.ExchangeHash.Length, KeyExchange.HashDigestLength(alg));
    }

    [Fact]
    public void DeriveKey_ThreeBlocks_AccumulatesAllPriorBlocks()
    {
        // Regression: per the C macro
        // (kex.c:73-120), block n hashes ALL prior blocks (K1‖K2‖…). The
        // previous implementation re-hashed only the LAST digest and threw
        // ArgumentOutOfRangeException at the third block. 96 bytes = 3
        // SHA-256 blocks — not reachable from the in-scope key lengths (max
        // 64 bytes), but the math must still be right.
        KexAlgorithm alg = KexAlgorithm.Curve25519Sha256;   // SHA-256 (32-byte digest)
        BigInteger k = 12345;
        byte[] h = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] sessionId = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();

        // Reference computation with the same mpint encoding the KDF uses.
        byte[] kMpint = new byte[4 + Endian.GetMpintLength(Endian.BigIntegerToBigEndianBytes(k))];
        Endian.WriteMpint(kMpint, Endian.BigIntegerToBigEndianBytes(k));

        byte[] K1 = SHA256.HashData([.. kMpint, .. h, (byte)'A', .. sessionId]);
        byte[] K2 = SHA256.HashData([.. kMpint, .. h, .. K1]);
        byte[] K3 = SHA256.HashData([.. kMpint, .. h, .. K1, .. K2]);
        byte[] expected = [.. K1, .. K2, .. K3];

        byte[] got = KeyExchange.DeriveKey(alg, k, h, sessionId, 'A', 96);

        Assert.Equal(expected, got);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void EFieldEncoding_MatchesAlgorithm(string methodDir)
    {
        // DH encodes e/f as mpint; ECDH/curve25519 as string. The fixture's
        // e_field_encoding records what the capture observed.
        KexFixture fx = KexFixtureLoader.Load(methodDir);
        KexAlgorithm alg = KexMethods.Lookup(fx.Kex);
        bool isDh = alg == KexAlgorithm.DhGroup14Sha256;

        Assert.Equal(isDh ? "mpint" : "string", fx.EFieldEncoding);
    }
}
