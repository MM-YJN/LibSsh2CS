using LibSsh2CS.Crypto;
using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for the Phase 1 increment-4 cipher adapters: registry lookup, per-cipher
/// metadata parity with <c>libssh2_priv.h</c>/<c>crypt.c</c>, and round-trip /
/// chaining behaviour across all four framing families (AES-CBC, AES-CTR,
/// AES-GCM, ChaCha20-Poly1305).
/// </summary>
public class CipherAdapterTests
{
    // ── Registry ──────────────────────────────────────────────────────

    [Fact]
    public void DefaultPreferences_HasInScopeAlgorithms_InPreferenceOrder()
    {
        // Order mirrors _libssh2_crypt_methods[] (crypt.c:508) — including the
        // rijndael-cbc@lysator.liu.se position between aes256-cbc and
        // aes192-cbc (crypt.c:519-523).
        string[] expected =
        [
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
            "aes256-cbc",
            "rijndael-cbc@lysator.liu.se",
            "aes192-cbc",
            "aes128-cbc",
        ];

        Assert.Equal(expected, CipherMethods.DefaultPreferences);
    }

    [Theory]
    [InlineData("chacha20-poly1305@openssh.com")]
    [InlineData("aes256-gcm@openssh.com")]
    [InlineData("aes128-gcm@openssh.com")]
    [InlineData("aes256-ctr")]
    [InlineData("aes192-ctr")]
    [InlineData("aes128-ctr")]
    [InlineData("aes256-cbc")]
    [InlineData("aes192-cbc")]
    [InlineData("aes128-cbc")]
    [InlineData("rijndael-cbc@lysator.liu.se")]
    public void Create_KnownName_ReturnsInstance(string name)
    {
        ICipher cipher = CipherMethods.Create(name)!;
        Assert.NotNull(cipher);
        Assert.Equal(ResolveExpectedName(name), cipher.Name);
        cipher.Dispose();
    }

    [Fact]
    public void Create_UnknownName_ReturnsNull()
    {
        Assert.Null(CipherMethods.Create("aes256-ocb"));
    }

    // ── Metadata parity with crypt.c struct initializers ──────────────

    [Theory]
    [InlineData("aes128-ctr", 16, 16, 16, 0, 0)]
    [InlineData("aes192-ctr", 16, 16, 24, 0, 0)]
    [InlineData("aes256-ctr", 16, 16, 32, 0, 0)]
    [InlineData("aes128-cbc", 16, 16, 16, 0, 0)]
    [InlineData("aes192-cbc", 16, 16, 24, 0, 0)]
    [InlineData("aes256-cbc", 16, 16, 32, 0, 0)]
    [InlineData("aes128-gcm@openssh.com", 16, 12, 16, 16, 3)] // IntegratedMac(1) | PktLenAad(2)
    [InlineData("aes256-gcm@openssh.com", 16, 12, 32, 16, 3)]
    [InlineData("chacha20-poly1305@openssh.com", 8, 0, 64, 16, 4)] // RequiresFullPacket(4)
    public void Metadata_MatchesLibssh2(string name, int blockSize, int ivLen, int keyLen, int authTagLen, int flags)
    {
        using ICipher cipher = CipherMethods.Create(name)!;
        Assert.Equal(blockSize, cipher.BlockSize);
        Assert.Equal(ivLen, cipher.IvLen);
        Assert.Equal(keyLen, cipher.KeyLen);
        Assert.Equal(authTagLen, cipher.AuthTagLen);
        Assert.Equal((CipherFlags)flags, cipher.Flags);
    }

    [Theory]
    [InlineData("aes128-ctr", false)]
    [InlineData("aes256-cbc", false)]
    [InlineData("aes128-gcm@openssh.com", true)]
    [InlineData("aes256-gcm@openssh.com", true)]
    [InlineData("chacha20-poly1305@openssh.com", true)]
    public void IsAead_ClassifiesCorrectly(string name, bool expected)
    {
        using ICipher cipher = CipherMethods.Create(name)!;
        Assert.Equal(expected, CipherMethods.IsAead(cipher));
    }

    // ── AES-CBC: round-trip + chaining persistence ────────────────────

    [Fact]
    public void AesCbc_RoundTrips_MultipleBlocks()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        Random r = new(42);
        r.NextBytes(key);
        r.NextBytes(iv);

        byte[] plain = new byte[64];
        r.NextBytes(plain);

        using var enc = new AesCbcCipher(32);
        using var dec = new AesCbcCipher(32);
        enc.Init(key, iv, encrypt: true);
        dec.Init(key, iv, encrypt: false);

        byte[] cipher1 = (byte[])plain.Clone();
        enc.Crypt(cipher1);

        Assert.NotEqual(plain, cipher1);

        byte[] restored = (byte[])cipher1.Clone();
        dec.Crypt(restored);
        Assert.Equal(plain, restored);
    }

    [Fact]
    public void AesCbc_ChainingPersistsAcrossPackets()
    {
        // Encrypting p1‖p2 as one call must equal encrypting p1 then p2 in two
        // calls on the same instance — proof that the CBC IV carry persists.
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Random r = new(7);
        r.NextBytes(key);
        r.NextBytes(iv);

        byte[] p1 = new byte[32];
        byte[] p2 = new byte[16];
        r.NextBytes(p1);
        r.NextBytes(p2);

        byte[] oneShot = Concat(p1, p2);
        using (var c = new AesCbcCipher(16))
        {
            c.Init(key, iv, encrypt: true);
            c.Crypt(oneShot);
        }

        byte[] sequential;
        using (var c = new AesCbcCipher(16))
        {
            c.Init(key, iv, encrypt: true);
            c.Crypt(p1);
            c.Crypt(p2);
            sequential = Concat(p1, p2);
        }

        Assert.Equal(oneShot, sequential);
    }

    [Fact]
    public void AesCbc_RejectsNonBlockMultiple()
    {
        using var c = new AesCbcCipher(16);
        c.Init(new byte[16], new byte[16], encrypt: true);
        Assert.Throws<SshException>(() => c.Crypt(new byte[17]));
    }

    [Fact]
    public void AesCbc_CryptAead_Throws()
    {
        using var c = new AesCbcCipher(16);
        c.Init(new byte[16], new byte[16], encrypt: true);
        Assert.Throws<NotSupportedException>(() => c.CryptAead(0, new byte[16], new byte[16], 0, 0, true));
    }

    [Fact]
    public void AesCbc_Init_RejectsBadSizes()
    {
        using var c = new AesCbcCipher(32);
        Assert.Throws<SshException>(() => c.Init(new byte[16], new byte[16], true));
        Assert.Throws<SshException>(() => c.Init(new byte[32], new byte[15], true));
    }

    // ── AES-CTR: round-trip + counter persistence ─────────────────────

    [Fact]
    public void AesCtr_RoundTrips_AsymmetricToEncrypt()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        Random r = new(1);
        r.NextBytes(key);
        r.NextBytes(iv);

        byte[] plain = new byte[48];
        r.NextBytes(plain);

        using var enc = new AesCtrCipher(32);
        using var dec = new AesCtrCipher(32);
        enc.Init(key, iv, true);
        dec.Init(key, iv, false);

        byte[] cipher1 = (byte[])plain.Clone();
        enc.Crypt(cipher1);

        byte[] restored = (byte[])cipher1.Clone();
        dec.Crypt(restored);
        Assert.Equal(plain, restored);
    }

    [Fact]
    public void AesCtr_CounterPersistsAcrossPackets()
    {
        // One-shot p1‖p2 keystream must match sequential p1 then p2 — proof the
        // counter carries across calls.
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Random r = new(99);
        r.NextBytes(key);
        r.NextBytes(iv);

        byte[] p1 = new byte[16];
        byte[] p2 = new byte[32];
        r.NextBytes(p1);
        r.NextBytes(p2);

        byte[] oneShot = Concat(p1, p2);
        using (var c = new AesCtrCipher(16))
        {
            c.Init(key, iv, true);
            c.Crypt(oneShot);
        }

        byte[] sequential;
        using (var c = new AesCtrCipher(16))
        {
            c.Init(key, iv, true);
            c.Crypt(p1);
            c.Crypt(p2);
            sequential = Concat(p1, p2);
        }

        Assert.Equal(oneShot, sequential);
    }

    [Fact]
    public void AesCtr_TryGetLength_ReturnsFalse()
    {
        using var c = new AesCtrCipher(16);
        Assert.False(c.TryGetLength(0, new byte[16], out _));
    }

    // ── AES-GCM: AEAD round-trip + invocation counter + length-as-AAD ──

    [Fact]
    public void AesGcm_RoundTrips_Payload()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        Random r = new(5);
        r.NextBytes(key);
        r.NextBytes(iv);

        const int AadLen = 4;
        const int PayloadLen = 28;
        byte[] src = new byte[AadLen + PayloadLen];
        r.NextBytes(src);

        using var enc = new AesGcmCipher(32);
        using var dec = new AesGcmCipher(32);
        enc.Init(key, iv, true);
        dec.Init(key, iv, false);

        byte[] ciphertext = new byte[AadLen + PayloadLen + 16];
        enc.CryptAead(0, ciphertext, src, PayloadLen, AadLen, encrypt: true);

        // Length is plaintext AAD — TryGetLength reads it directly.
        Assert.True(enc.TryGetLength(0, ciphertext, out uint len));
        Assert.Equal(len, BigEndianU32(src, 0));

        byte[] restored = new byte[AadLen + PayloadLen];
        dec.CryptAead(0, restored, ciphertext, PayloadLen, AadLen, encrypt: false);
        Assert.Equal(src, restored);
    }

    [Fact]
    public void AesGcm_InvocationCounter_AdvancesPerPacket()
    {
        // Same plaintext encrypted twice on one instance must differ (nonce changes).
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        Random r = new(11);
        r.NextBytes(key);
        r.NextBytes(iv);

        byte[] src = new byte[4 + 16];
        r.NextBytes(src);

        using var enc = new AesGcmCipher(16);
        enc.Init(key, iv, true);

        byte[] c1 = new byte[4 + 16 + 16];
        byte[] c2 = new byte[4 + 16 + 16];
        enc.CryptAead(0, c1, src, 16, 4, true);
        enc.CryptAead(1, c2, src, 16, 4, true);

        // The AAD prefix (length) is plaintext and identical, but the encrypted
        // payload and tag must differ because the nonce advanced.
        Assert.NotEqual(c1.AsSpan(4).ToArray(), c2.AsSpan(4).ToArray());
    }

    [Fact]
    public void AesGcm_DecryptTamperedTag_ThrowsDecrypt()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        Random r = new(3);
        r.NextBytes(key);
        r.NextBytes(iv);

        byte[] src = new byte[4 + 12];
        r.NextBytes(src);

        using var enc = new AesGcmCipher(32);
        using var dec = new AesGcmCipher(32);
        enc.Init(key, iv, true);
        dec.Init(key, iv, false);

        byte[] ciphertext = new byte[4 + 12 + 16];
        enc.CryptAead(0, ciphertext, src, 12, 4, true);
        ciphertext[^1] ^= 0x01;

        SshException ex = Assert.Throws<SshException>(
            () => dec.CryptAead(0, new byte[4 + 12], ciphertext, 12, 4, false));
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    [Fact]
    public void AesGcm_Crypt_ThrowsAndTryGetLengthHandlesShortInput()
    {
        using var c = new AesGcmCipher(16);
        c.Init(new byte[16], new byte[12], true);
        Assert.Throws<NotSupportedException>(() => c.Crypt(new byte[16]));
        Assert.False(c.TryGetLength(0, new byte[3], out _));
    }

    // ── ChaCha20-Poly1305: adapter delegates to the shipped AEAD ──────

    [Fact]
    public void ChaChaPoly_RoundTripsThroughAdapter()
    {
        byte[] key = new byte[ChaChaPolySsh.KeySize];
        Random r = new(8);
        r.NextBytes(key);

        byte[] src = new byte[4 + 20];
        src[3] = 20;
        r.NextBytes(src.AsSpan(4));

        using var enc = new ChaChaPolyCipher();
        using var dec = new ChaChaPolyCipher();
        enc.Init(key, [], true);
        dec.Init(key, [], false);

        byte[] ciphertext = new byte[4 + 20 + 16];
        enc.CryptAead(42, ciphertext, src, 20, 4, true);

        Assert.True(enc.TryGetLength(42, ciphertext, out uint len));
        Assert.Equal(20u, len);

        byte[] restored = new byte[4 + 20];
        dec.CryptAead(42, restored, ciphertext, 20, 4, false);
        Assert.Equal(src, restored);
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private static string ResolveExpectedName(string requested)
        => requested == "rijndael-cbc@lysator.liu.se" ? "aes256-cbc" : requested;

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    private static uint BigEndianU32(byte[] data, int offset)
        => ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16)
           | ((uint)data[offset + 2] << 8) | data[offset + 3];
}
