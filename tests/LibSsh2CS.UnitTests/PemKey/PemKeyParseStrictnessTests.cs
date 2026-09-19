using System.Buffers.Binary;
using System.Text;

namespace LibSsh2CS.UnitTests.PemKey;

/// <summary>
/// Regression tests for key-file parse
/// strictness and KDF-iteration caps.
/// <list type="bullet">
/// <item>Ed25519 private blob: the comment read is REQUIRED (the C
/// fails hard at openssl.c:2281-2286 "Unable to read comment"); the pre-fix
/// port swallowed the truncation and accepted comment-less blobs.</item>
/// <item>RSA private blob: the comment is never read (the C requires
/// it, openssl.c:1524 "RSA no comment"); truncated blobs were accepted.</item>
/// <item>bcrypt <c>rounds</c> and PBKDF2 <c>iterations</c> are
/// attacker-controlled counts the C passes through uncapped (parity), so the
/// caps are a DOCUMENTED DIVERGENCE: reject above a bound before deriving.</item>
/// <item><c>DerIntegerToLong</c> silently wrapped &gt;8-byte DER
/// INTEGERs (the C's <c>ASN1_INTEGER_get</c> fails for them); the gate is
/// now a rejection.</item>
/// </list>
/// </summary>
public class PemKeyParseStrictnessTests
{
    // ── Ed25519 comment is a required structural read ───────────────

    [Fact]
    public void Parse_Ed25519_NoComment_Throws()
    {
        // Blob: check1 | check2 | keytype | pub(32) | priv(64) — NO comment and
        // no padding tail. Pre-fix the swallowed comment-read failure left an
        // empty tail, which trivially passes the 1,2,3,… padding check, and the
        // key was accepted (the C fails hard: openssl.c:2281-2286).
        OpenSshKey key = BuildEd25519OpenSshKey(commentBytes: null);

        SshException ex = Assert.Throws<SshException>(() => SshPemKey.Parse(key));
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void Parse_Ed25519_TruncatedComment_Throws()
    {
        // Comment declares 4 bytes but only 2 remain — a truncated comment is
        // a hard failure (openssl.c:2281-2286), not "absent".
        OpenSshKey key = BuildEd25519OpenSshKey(commentBytes: new byte[] { 0x41, 0x42 }, truncated: true);

        SshException ex = Assert.Throws<SshException>(() => SshPemKey.Parse(key));
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void Parse_Ed25519_ValidComment_StillAccepted()
    {
        // Sanity: a well-formed comment keeps the key parseable.
        OpenSshKey key = BuildEd25519OpenSshKey(commentBytes: Encoding.UTF8.GetBytes("user@host"));

        var pemKey = SshPemKey.Parse(key);
        Assert.Equal(SshKeyType.Ed25519, pemKey.KeyType);
    }

    // ── RSA comment is a required structural read ───────────────────

    [Fact]
    public void Parse_Rsa_TruncatedComment_Throws()
    {
        // Blob: n, e, d, coeff, p, q, then a comment declaring 8 bytes with
        // none remaining. Pre-fix the comment was never read, so the truncated
        // blob was silently accepted (the C requires it: openssl.c:1524
        // "RSA no comment").
        OpenSshKey key = BuildRsaOpenSshKey(commentBytes: null);

        SshException ex = Assert.Throws<SshException>(() => SshPemKey.Parse(key));
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void Parse_Rsa_ValidComment_StillAccepted()
    {
        OpenSshKey key = BuildRsaOpenSshKey(commentBytes: Encoding.UTF8.GetBytes("user@host"));

        var pemKey = SshPemKey.Parse(key);
        Assert.Equal(SshKeyType.Rsa, pemKey.KeyType);
    }

    // ── KDF iteration caps (documented divergence — the C is uncapped)

    [Fact]
    public async Task ParseOpenSsh_BcryptRoundsAboveCap_ThrowsDecryptWithoutDeriving()
    {
        // rounds = 0x7FFFFFFF: pre-fix the derive loop ran ~2.1×10⁹ bcrypt
        // rounds (effectively forever — the bounded wait turns that into a
        // failure); post-fix the cap rejects the file before any derivation.
        byte[] pem = BuildOpenSshKeyV1Pem(rounds: 0x7FFF_FFFF);

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await Task.Run(() => SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "pw"))
                .WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));

        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    [Fact]
    public async Task ParsePkcs8_Pbkdf2IterationsAboveCap_ThrowsFileWithoutDeriving()
    {
        // 200M iterations: pre-fix the PBKDF2 derive ran for tens of seconds
        // (the bounded wait turns that into a failure); post-fix the cap
        // rejects the file before any derivation.
        byte[] pem = BuildEncryptedPkcs8Pem(iterations: 200_000_000, integerBytes: 4);

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await Task.Run(() => SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "pw"))
                .WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));

        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
    }

    // ── DER INTEGER content longer than 8 bytes is rejected ─────────

    [Fact]
    public void ParsePkcs8_OverLongIterationsInteger_ThrowsFile()
    {
        // A 9-byte INTEGER (00 00 00 00 00 00 00 00 01): pre-fix the unchecked
        // shift-accumulate wrapped it to 1 (after the sign-byte strip), passing
        // the iterations gate and failing later with a decrypt error
        // (KeyfileAuthFailed). OpenSSL's ASN1_INTEGER_get rejects content
        // longer than sizeof(long) — the file must fail with the C's FILE
        // error up front.
        byte[] pem = BuildEncryptedPkcs8Pem(iterations: 1, integerBytes: 9,
            overLongInteger: true);

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "pw"));
        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static OpenSshKey BuildEd25519OpenSshKey(byte[]? commentBytes, bool truncated = false)
    {
        using var ms = new MemoryStream();
        WriteUInt32(ms, 0x0102_0304);            // check1
        WriteUInt32(ms, 0x0102_0304);            // check2
        WriteSshString(ms, "ssh-ed25519"u8.ToArray());
        WriteSshString(ms, Enumerable.Repeat((byte)0x11, 32).ToArray());   // pub
        WriteSshString(ms, Enumerable.Repeat((byte)0x22, 64).ToArray());   // priv
        if (commentBytes is not null)
        {
            // truncated: declare more than we supply; else declare exactly.
            WriteUInt32(ms, truncated ? (uint)(commentBytes.Length + 2) : (uint)commentBytes.Length);
            ms.Write(commentBytes);
        }

        return new OpenSshKey("none", "none", [], ms.ToArray(), string.Empty);
    }

    private static OpenSshKey BuildRsaOpenSshKey(byte[]? commentBytes)
    {
        using var ms = new MemoryStream();
        WriteUInt32(ms, 0x0102_0304);            // check1
        WriteUInt32(ms, 0x0102_0304);            // check2
        WriteSshString(ms, "ssh-rsa"u8.ToArray());
        WriteSshString(ms, Enumerable.Repeat((byte)0x01, 16).ToArray());   // n
        WriteSshString(ms, [0x01, 0x00, 0x01]);                            // e
        WriteSshString(ms, Enumerable.Repeat((byte)0x02, 16).ToArray());   // d
        WriteSshString(ms, Enumerable.Repeat((byte)0x03, 16).ToArray());   // coeff
        WriteSshString(ms, Enumerable.Repeat((byte)0x04, 16).ToArray());   // p
        WriteSshString(ms, Enumerable.Repeat((byte)0x05, 16).ToArray());   // q
        if (commentBytes is not null)
        {
            WriteUInt32(ms, (uint)commentBytes.Length);
            ms.Write(commentBytes);
        }

        return new OpenSshKey("none", "none", [], ms.ToArray(), string.Empty);
    }

    /// <summary>
    /// Builds a full <c>openssh-key-v1</c> PEM whose bcrypt KDF options carry
    /// the given <paramref name="rounds"/>. The encrypted payload is 16 bytes
    /// (a valid AES-CTR block multiple) — the rounds cap must reject the file
    /// before any derivation touches it.
    /// </summary>
    private static byte[] BuildOpenSshKeyV1Pem(uint rounds)
    {
        using var blob = new MemoryStream();
        blob.Write("openssh-key-v1\0"u8);
        WriteSshString(blob, "aes256-ctr"u8.ToArray());
        WriteSshString(blob, "bcrypt"u8.ToArray());

        using (var kdfOptions = new MemoryStream())
        {
            WriteSshString(kdfOptions, Enumerable.Repeat((byte)0x5A, 16).ToArray());   // salt
            Span<byte> r = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(r, rounds);
            kdfOptions.Write(r);
            WriteSshString(blob, kdfOptions.ToArray());
        }

        WriteUInt32(blob, 1);   // nkeys
        using (var pub = new MemoryStream())
        {
            WriteSshString(pub, "ssh-ed25519"u8.ToArray());
            WriteSshString(pub, Enumerable.Repeat((byte)0x33, 32).ToArray());
            WriteSshString(blob, pub.ToArray());
        }

        WriteSshString(blob, new byte[16]);   // encrypted private blob (zeros)

        return WrapPem(blob.ToArray(), "OPENSSH PRIVATE KEY");
    }

    /// <summary>
    /// Builds an <c>ENCRYPTED PRIVATE KEY</c> (PKCS#8 PBES2/PBKDF2) PEM with
    /// the given PBKDF2 iteration count. <paramref name="integerBytes"/>
    /// controls the DER INTEGER content length; when
    /// <paramref name="overLongInteger"/> is set the content is 9 bytes
    /// (00 × 8 ‖ 01 — a positive value the old wrap-decoder collapsed to 1).
    /// </summary>
    private static byte[] BuildEncryptedPkcs8Pem(
        long iterations, int integerBytes, bool overLongInteger = false)
    {
        byte[] iterationsInteger;
        if (overLongInteger)
        {
            // 9 bytes: 01 00 00 00 00 00 00 00 01 — no leading sign byte (so
            // ReadInteger does not strip it). Pre-fix the 64-bit
            // shift-accumulate shifted the top byte out on the 9th step,
            // wrapping the value to 1 and passing the iterations gate.
            iterationsInteger = new byte[integerBytes];
            iterationsInteger[0] = 0x01;
            iterationsInteger[^1] = 0x01;
        }
        else
        {
            iterationsInteger = new byte[integerBytes];
            for (int i = 0; i < integerBytes; i++)
            {
                iterationsInteger[integerBytes - 1 - i] = (byte)(iterations >> (8 * i));
            }
        }

        byte[] salt = Enumerable.Repeat((byte)0x44, 8).ToArray();
        byte[] iv = Enumerable.Repeat((byte)0x55, 16).ToArray();
        byte[] encrypted = new byte[16];   // must be a full CBC block

        // PBKDF2-params: SEQUENCE { OCTET STRING salt, INTEGER iterations }
        byte[] pbkdf2Params = DerSequence([.. DerOctetString(salt), .. DerInteger(iterationsInteger)]);
        // keyDerivationFunc: SEQUENCE { OID PBKDF2, PBKDF2-params }
        byte[] kdf = DerSequence([.. DerOid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C), .. pbkdf2Params]);
        // encryptionScheme: SEQUENCE { OID aes128-CBC, OCTET STRING iv }
        byte[] enc = DerSequence([.. DerOid(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02), .. DerOctetString(iv)]);
        // PBES2-params: SEQUENCE { keyDerivationFunc, encryptionScheme }
        byte[] pbes2Params = DerSequence([.. kdf, .. enc]);
        // AlgorithmIdentifier: SEQUENCE { OID PBES2, PBES2-params }
        byte[] algId = DerSequence([.. DerOid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D), .. pbes2Params]);
        // EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        byte[] body = DerSequence([.. algId, .. DerOctetString(encrypted)]);

        return WrapPem(body, "ENCRYPTED PRIVATE KEY");
    }

    private static byte[] WrapPem(byte[] der, string label)
    {
        string b64 = Convert.ToBase64String(der);
        return Encoding.ASCII.GetBytes(
            $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n");
    }

    private static byte[] DerSequence(byte[] content) => DerElement(0x30, content);
    private static byte[] DerOctetString(byte[] content) => DerElement(0x04, content);
    private static byte[] DerInteger(byte[] content) => DerElement(0x02, content);

    private static byte[] DerElement(byte tag, byte[] content)
    {
        byte[] result = new byte[1 + 1 + content.Length];
        result[0] = tag;
        result[1] = (byte)content.Length;   // short form; contents here are < 128 B
        Buffer.BlockCopy(content, 0, result, 2, content.Length);
        return result;
    }

    private static byte[] DerOid(params byte[] content) => DerElement(0x06, content);

    private static void WriteUInt32(Stream ms, uint value)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
        ms.Write(tmp);
    }

    private static void WriteSshString(Stream ms, byte[] bytes)
    {
        WriteUInt32(ms, (uint)bytes.Length);
        ms.Write(bytes);
    }
}
