using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for the Phase 1 increment-4 MAC adapters: registry, metadata parity with
/// <c>mac.c</c>, and HMAC correctness cross-checked against the BCL HMAC over the
/// SSH MAC input (<c>BE32(seqno) ‖ packet</c>).
/// </summary>
public class MacAdapterTests
{
    private static readonly byte[] s_key = RandomBytes(64, 123);
    private static readonly byte[] s_data = RandomBytes(100, 7);

    // ── Registry ──────────────────────────────────────────────────────

    [Fact]
    public void DefaultPreferences_HasInScopeAlgorithms_InPreferenceOrder()
    {
        // Order mirrors mac_methods[] (mac.c:455).
        string[] expected =
        [
            "hmac-sha2-256",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1",
            "hmac-sha1-etm@openssh.com",
        ];

        Assert.Equal(expected, MacMethods.DefaultPreferences);
    }

    [Theory]
    [InlineData("hmac-sha2-256", 32, false)]
    [InlineData("hmac-sha2-256-etm@openssh.com", 32, true)]
    [InlineData("hmac-sha2-512", 64, false)]
    [InlineData("hmac-sha2-512-etm@openssh.com", 64, true)]
    [InlineData("hmac-sha1", 20, false)]
    [InlineData("hmac-sha1-etm@openssh.com", 20, true)]
    public void Metadata_MatchesLibssh2(string name, int macLen, bool isEtm)
    {
        using IMac mac = MacMethods.Create(name)!;
        Assert.Equal(name, mac.Name);
        Assert.Equal(macLen, mac.MacLen);
        Assert.Equal(isEtm, mac.IsEtm);
    }

    [Fact]
    public void Create_UnknownName_ReturnsNull()
    {
        Assert.Null(MacMethods.Create("hmac-md5"));
    }

    // ── HMAC correctness vs BCL ───────────────────────────────────────

    [Theory]
    [InlineData("hmac-sha1", "SHA1")]
    [InlineData("hmac-sha2-256", "SHA256")]
    [InlineData("hmac-sha2-512", "SHA512")]
    public void Compute_MatchesBclHmacOverSeqnoAndData(string name, string hashName)
    {
        const uint Seqno = 0x11223344u;
        using IMac mac = MacMethods.Create(name)!;
        mac.Init(s_key);

        byte[] actual = new byte[mac.MacLen];
        mac.Compute(Seqno, s_data, actual);

        byte[] expected = ComputeBclHmac(hashName, s_key, Seqno, s_data);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Verify_CorrectMac_ReturnsTrue()
    {
        using IMac mac = MacMethods.Create("hmac-sha2-256")!;
        mac.Init(s_key);

        byte[] tag = new byte[mac.MacLen];
        mac.Compute(1, s_data, tag);

        Assert.True(mac.Verify(1, s_data, tag));
    }

    [Fact]
    public void Verify_WrongMac_ReturnsFalse()
    {
        using IMac mac = MacMethods.Create("hmac-sha2-256")!;
        mac.Init(s_key);

        byte[] tag = new byte[mac.MacLen];
        mac.Compute(1, s_data, tag);
        tag[0] ^= 0xff;

        Assert.False(mac.Verify(1, s_data, tag));
    }

    [Fact]
    public void Verify_DifferentSeqno_ReturnsFalse()
    {
        using IMac mac = MacMethods.Create("hmac-sha1")!;
        mac.Init(s_key);

        byte[] tag = new byte[mac.MacLen];
        mac.Compute(1, s_data, tag);

        // Same data, different seqno → different MAC.
        Assert.False(mac.Verify(2, s_data, tag));
    }

    [Fact]
    public void Compute_PersistsAcrossCalls_ReusingKeyedContext()
    {
        // Reusing the same instance across packets must keep producing correct MACs.
        using IMac mac = MacMethods.Create("hmac-sha2-256")!;
        mac.Init(s_key);

        byte[] tag1 = new byte[mac.MacLen];
        byte[] tag2 = new byte[mac.MacLen];
        mac.Compute(1, s_data, tag1);
        mac.Compute(2, s_data, tag2);

        Assert.Equal(ComputeBclHmac("SHA256", s_key, 1, s_data), tag1);
        Assert.Equal(ComputeBclHmac("SHA256", s_key, 2, s_data), tag2);
    }

    // ── Noop MAC ──────────────────────────────────────────────────────

    [Fact]
    public void NoopMac_ProducesNothingAndAlwaysVerifies()
    {
        using IMac mac = MacMethods.Noop;
        Assert.Equal(0, mac.MacLen);
        Assert.False(mac.IsEtm);

        mac.Init([]);
        Span<byte> tag = stackalloc byte[1];
        mac.Compute(0, s_data, tag);
        Assert.Equal((byte)0, tag[0]);

        Assert.True(mac.Verify(0, s_data, []));
    }

    // ── Helpers ───────────────────────────────────────────────────────

    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "HMAC-SHA1 is an in-scope SSH MAC (hmac-sha1); this test cross-checks it against the BCL.")]
    private static byte[] ComputeBclHmac(string hashName, byte[] key, uint seqno, byte[] data)
    {
        using HMAC hmac = hashName switch
        {
            "SHA1" => new HMACSHA1(),
            "SHA256" => new HMACSHA256(),
            "SHA512" => new HMACSHA512(),
            _ => throw new ArgumentException($"Unknown hash {hashName}", nameof(hashName)),
        };
        hmac.Key = key;
        byte[] input = new byte[4 + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(0, 4), seqno);
        Buffer.BlockCopy(data, 0, input, 4, data.Length);
        return hmac.ComputeHash(input);
    }

    private static byte[] RandomBytes(int n, int seed)
    {
        byte[] b = new byte[n];
        new Random(seed).NextBytes(b);
        return b;
    }
}
