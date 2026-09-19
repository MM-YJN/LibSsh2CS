using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.UserAuth;

/// <summary>
/// SshSign sign-dispatcher tests. Verifies that <see cref="SshSign.Sign"/>
/// produces a valid SSH signature blob for RSA, ECDSA (when fixtures exist),
/// and Ed25519 keys, by re-parsing the blob and verifying the signature with the
/// corresponding BCL or in-port verifier.
/// </summary>
/// <remarks>
/// These tests are the sign-side counterpart to the verify-side
/// <c>HostKeyVerifierTests</c>. Together they prove the sign → verify round-trip
/// for every key type.
/// </remarks>
public class SshSignTests
{
    /// <summary>
    /// Signs a test message with an Ed25519 key, parses the SSH sig blob
    /// ([string "ssh-ed25519"][string 64-byte sig]), and verifies the signature
    /// via <see cref="Crypto.Ed25519.Verify"/>. Proves the blob format and the
    /// sign path are correct.
    /// </summary>
    [Fact]
    public void Sign_Ed25519_ProducesVerifiableSignatureBlob()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (SshEd25519PemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "test data for ssh-ed25519 signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "ssh-ed25519");

        // Parse the SSH sig blob: [string "ssh-ed25519"][string 64-byte sig]
        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("ssh-ed25519", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);
        Assert.Equal(64, rawSig.Length);

        // Verify the signature against the public key.
        bool valid = Ed25519.Verify(pemKey.PublicKey, data, rawSig);
        Assert.True(valid);
    }

    /// <summary>
    /// Signs a test message with an RSA key using <c>rsa-sha2-256</c>, parses the
    /// SSH sig blob, and verifies the raw RSA signature via BCL
    /// <see cref="RSA.VerifyHash"/>. Proves the RSA sign path + blob format.
    /// </summary>
    [Fact]
    public void Sign_RsaSha2_256_ProducesVerifiableSignatureBlob()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("rsa_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (RsaPemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "test data for rsa-sha2-256 signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "rsa-sha2-256");

        // Parse: [string "rsa-sha2-256"][string rawSig]
        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("rsa-sha2-256", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);
        // RSA signature length = key size in bytes (256 for RSA-2048). The SSH
        // modulus may carry a 0x00 sign guard (257 bytes) but the signature is
        // always exactly the key size.
        Assert.Equal(256, rawSig.Length);

        // Verify: hash the data with SHA-256, then RSA.VerifyHash with PKCS#1.
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = pemKey.Modulus,
            Exponent = pemKey.PublicExponent,
        });
        byte[] digest = SHA256.HashData(data);
        bool valid = rsa.VerifyHash(digest, rawSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(valid);
    }

    /// <summary>
    /// Signs with <c>ssh-rsa</c> (SHA-1) and verifies via BCL RSA.VerifyHash with
    /// SHA-1. Proves the SHA-1 fallback path.
    /// </summary>
    [Fact]
    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "SHA-1 is the algorithm under test (ssh-rsa); cross-checks SshSign.Sign against the BCL RSA verifier with SHA-1.")]
    public void Sign_SshRsa_Sha1_ProducesVerifiableSignatureBlob()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("rsa_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (RsaPemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "test data for ssh-rsa (sha1) signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "ssh-rsa");

        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("ssh-rsa", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = pemKey.Modulus,
            Exponent = pemKey.PublicExponent,
        });
        byte[] digest = SHA1.HashData(data);
        bool valid = rsa.VerifyHash(digest, rawSig, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        Assert.True(valid);
    }

    /// <summary>
    /// Signs with <c>rsa-sha2-512</c> and verifies via BCL RSA.VerifyHash with
    /// SHA-512. Proves the SHA-512 path.
    /// </summary>
    [Fact]
    public void Sign_RsaSha2_512_ProducesVerifiableSignatureBlob()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("rsa_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (RsaPemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "test data for rsa-sha2-512 signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "rsa-sha2-512");

        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("rsa-sha2-512", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = pemKey.Modulus,
            Exponent = pemKey.PublicExponent,
        });
        byte[] digest = SHA512.HashData(data);
        bool valid = rsa.VerifyHash(digest, rawSig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        Assert.True(valid);
    }

    /// <summary>
    /// A tampered message must NOT verify against the signature.
    /// </summary>
    [Fact]
    public void Sign_TamperedMessage_SignatureDoesNotVerify()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (SshEd25519PemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "original message"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "ssh-ed25519");

        _ = ReadSshString(sigBlob, out int offset);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

        byte[] tampered = "tampered message"u8.ToArray();
        bool valid = Ed25519.Verify(pemKey.PublicKey, tampered, rawSig);
        Assert.False(valid);
    }

    /// <summary>
    /// An unsupported algorithm name for a key type throws PublicKeyProtocol.
    /// </summary>
    [Fact]
    public void Sign_UnsupportedAlgo_Throws()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = SshPemKey.Parse(openSshKey);

        Assert.Throws<SshException>(() =>
            SshSign.Sign(pemKey, "data"u8.ToArray(), "ssh-rsa"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // ECDSA (ecdsa-sha2-nistp256/384/521). These tests pin two parity bugs
    // surfaced by the ECDSA client-auth integration tests
    // (DockerAuthTests.Auth_EcdsaP*_PublicKey_Succeeds):
    //
    //  (1) D-length normalization: the SSH mpint Exponent may carry a 0x00
    //      sign guard (coordSize+1 bytes) or be shorter than coordSize.
    //      OpenSSL's BN_bin2bn + EC_KEY_set_private_key tolerate both
    //      (BIGNUM is arbitrary-precision); the BCL's ECDsa.ImportParameters
    //      requires D to be exactly coordSize. SignEcdsa must normalize.
    //      Pre-fix the P384 key (Exponent=49 bytes) threw
    //      CryptographicException on ImportParameters.
    //
    //  (2) r/s bignum2 sign guard: ReadDerInteger must RETAIN the 0x00 sign
    //      guard in the SSH wire r/s when the value's high bit is set, matching
    //      libssh2's write_bn (openssl.c:222-237) and OpenSSH's
    //      sshbuf_put_bignum2. Pre-fix the guard was stripped, producing shorter
    //      r/s that OpenSSH misparsed as negative under the bignum2 signed
    //      convention, failing signature verification.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Signs a test message with the ECDSA-P256 key and verifies the signature
    /// via BCL <see cref="ECDsa.VerifyData(byte[], byte[], HashAlgorithmName,
    /// DSASignatureFormat)"/>. Proves the ECDSA-P256 sign path produces a
    /// cryptographically valid signature in the SSH wire form.
    /// </summary>
    [Fact]
    public void Sign_EcdsaP256_ProducesVerifiableSignatureBlob()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p256_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (SshEcdsaPemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "test data for ecdsa-sha2-nistp256 signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "ecdsa-sha2-nistp256");

        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("ecdsa-sha2-nistp256", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

        // rawSig is [string r][string s].
        int rsOff = 0;
        byte[] r = ReadSshBytes(rawSig, ref rsOff);
        byte[] s = ReadSshBytes(rawSig, ref rsOff);

        Assert.True(VerifyEcdsa(pemKey, data, r, s, HashAlgorithmName.SHA256, 32),
            "ECDSA-P256 signature must verify against the public key");
    }

    /// <summary>
    /// Signs a test message with the ECDSA-P384 key and verifies via BCL with
    /// SHA-384. <b>Regression test for bug (1):</b> the P384 fixture's private
    /// scalar (<c>Exponent</c>) is 49 bytes — a 0x00 sign guard prefixing 48
    /// real bytes because the scalar's high bit is set. Pre-fix
    /// <see cref="SshSign.SignEcdsa"/> passed <c>key.Exponent</c> directly to
    /// <see cref="ECDsa.ImportParameters"/>, which threw
    /// <c>CryptographicException</c> ("D must be the same length as Q.X and
    /// Q.Y"). The fix normalizes D to <c>coordSize</c> via
    /// <c>StripLeadingZeros</c> + <c>LeftPadToLength</c>, mirroring OpenSSL's
    /// <c>BN_bin2bn</c> semantics. This test asserts the sign call no longer
    /// throws AND produces a verifiable signature.
    /// </summary>
    [Fact]
    public void Sign_EcdsaP384_NormalizesExponentGuardAndVerifies()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p384_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (SshEcdsaPemKey)SshPemKey.Parse(openSshKey);

        // The regression: assert the fixture actually exercises the guard path
        // (Exponent longer than coordSize=48). If a future ssh-keygen regenerates
        // the fixture with a guard-less scalar, this assertion flags that the
        // regression coverage is lost — regenerate with a key whose scalar high
        // bit is set, or pick a different fixture.
        Assert.Equal(49, pemKey.Exponent.Length);
        Assert.Equal(0x00, pemKey.Exponent[0]);

        byte[] data = "test data for ecdsa-sha2-nistp384 signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "ecdsa-sha2-nistp384");

        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("ecdsa-sha2-nistp384", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

        int rsOff = 0;
        byte[] r = ReadSshBytes(rawSig, ref rsOff);
        byte[] s = ReadSshBytes(rawSig, ref rsOff);

        Assert.True(VerifyEcdsa(pemKey, data, r, s, HashAlgorithmName.SHA384, 48),
            "ECDSA-P384 signature must verify after Exponent guard normalization");
    }

    /// <summary>
    /// Signs a test message with the ECDSA-P521 key and verifies via BCL with
    /// SHA-512. P-521 is the largest in-scope ECDSA curve (coordSize=66); its
    /// DER signature SEQUENCE length exceeds 127 bytes, exercising the
    /// long-form length branch in <see cref="SshSign.ParseEcdsaDerSig"/>
    /// (<c>lenByte & 0x80 != 0</c> → one extra length byte).
    /// </summary>
    [Fact]
    public void Sign_EcdsaP521_ProducesVerifiableSignatureBlob()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p521_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (SshEcdsaPemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "test data for ecdsa-sha2-nistp521 signing"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(pemKey, data, "ecdsa-sha2-nistp521");

        string algo = ReadSshString(sigBlob, out int offset);
        Assert.Equal("ecdsa-sha2-nistp521", algo);
        byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

        int rsOff = 0;
        byte[] r = ReadSshBytes(rawSig, ref rsOff);
        byte[] s = ReadSshBytes(rawSig, ref rsOff);

        Assert.True(VerifyEcdsa(pemKey, data, r, s, HashAlgorithmName.SHA512, 66),
            "ECDSA-P521 signature must verify against the public key");
    }

    /// <summary>
    /// <b>Regression test for bug (2):</b> the SSH wire r/s values produced by
    /// <see cref="SshSign.SignEcdsa"/> must follow the <c>bignum2</c> convention
    /// from libssh2's <c>write_bn</c> (<c>openssl.c:222-237</c>) and OpenSSH's
    /// <c>sshbuf_put_bignum2</c>: a 0x00 sign guard is present iff the value's
    /// high bit is set, so the byte length is <c>coordSize</c> (no guard, high
    /// bit clear) or <c>coordSize+1</c> (guard, high bit set). Pre-fix
    /// <see cref="SshSign.ReadDerInteger"/> stripped the guard unconditionally,
    /// producing <c>coordSize</c>-length r/s with the high bit set — which
    /// OpenSSH misparses as negative under the signed bignum2 convention,
    /// failing server-side verification.
    ///
    /// ECDSA signatures are randomized, so across a handful of sign calls at
    /// least one r or s will have its high bit set (probability ~0.5 per value
    /// per call). This test signs repeatedly (up to 20×) until it observes a
    /// high-bit-set value, then asserts that value carries the 0x00 guard
    /// (length <c>coordSize+1</c>, first byte 0x00). If no high-bit-set value
    /// appears in 20 tries, the test asserts that at least the length invariant
    /// held for every observed value (length is coordSize or coordSize+1) —
    /// which would still catch the pre-fix bug (which produced coordSize-1 for
    /// guarded values).
    /// </summary>
    [Fact]
    public void Sign_Ecdsa_RetainsBignum2SignGuardWhenHighBitSet()
    {
        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p256_plain_key");
        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);
        var pemKey = (SshEcdsaPemKey)SshPemKey.Parse(openSshKey);

        byte[] data = "bignum2 guard regression"u8.ToArray();
        const int coordSize = 32;
        bool observedGuarded = false;

        for (int i = 0; i < 20; i++)
        {
            // Vary the data each iteration so ECDSA yields different r/s.
            byte[] msg = data.Concat([(byte)i]).ToArray();
            byte[] sigBlob = SshSign.Sign(pemKey, msg, "ecdsa-sha2-nistp256");

            _ = ReadSshString(sigBlob, out int offset);
            byte[] rawSig = ReadSshBytes(sigBlob, ref offset);

            int rsOff = 0;
            byte[] r = ReadSshBytes(rawSig, ref rsOff);
            byte[] s = ReadSshBytes(rawSig, ref rsOff);

            // Length invariant: every value is coordSize (no guard) or
            // coordSize+1 (guard present). The pre-fix bug produced
            // coordSize-1 (= stripped guard from a coordSize DER INTEGER),
            // which violates this.
            Assert.True(r.Length is coordSize or (coordSize + 1),
                $"r length {r.Length} not in {{{coordSize}, {coordSize + 1}}}");
            Assert.True(s.Length is coordSize or (coordSize + 1),
                $"s length {s.Length} not in {{{coordSize}, {coordSize + 1}}}");

            CheckBignum2Guard(r, coordSize, ref observedGuarded);
            CheckBignum2Guard(s, coordSize, ref observedGuarded);

            if (observedGuarded)
            {
                break;
            }
        }

        Assert.True(observedGuarded,
            "Did not observe a high-bit-set r/s in 20 sign calls; " +
            "either the test is unlucky or the sign path is dropping the guard. " +
            "Re-run; if it consistently fails, investigate SignEcdsa's r/s encoding.");
    }

    /// <summary>
    /// Asserts that a wire r/s value obeys the bignum2 sign-guard convention:
    /// if the value's high bit is set (the first content byte has bit 7 on),
    /// there MUST be a leading 0x00 guard (length coordSize+1, byte[0]==0x00);
    /// otherwise there MUST NOT be a guard (length coordSize, byte[0]!=0x00).
    /// Sets <paramref name="observedGuarded"/> true when a guarded value is
    /// seen, so the caller can stop iterating once it has exercised the
    /// guard path.
    /// </summary>
    private static void CheckBignum2Guard(byte[] value, int coordSize, ref bool observedGuarded)
    {
        if (value.Length == coordSize + 1)
        {
            // Guard present: first byte must be 0x00, second byte high bit set.
            Assert.Equal(0x00, value[0]);
            Assert.True((value[1] & 0x80) != 0,
                "bignum2 guard present but high bit of value is clear (unnecessary guard)");
            observedGuarded = true;
        }
        else
        {
            // No guard: length == coordSize. If the high bit is set here, the
            // guard was wrongly stripped (the pre-fix bug). The length-invariant
            // assertion in the caller already catches coordSize-1; this
            // catches the coordSize-with-high-bit case that would be
            // misparsed as negative.
            Assert.True((value[0] & 0x80) == 0,
                $"bignum2 value length {value.Length} (no guard) but high bit set — " +
                "guard was stripped (pre-fix bug); value would be misparsed as negative");
        }
    }

    /// <summary>
    /// Re-encodes the SSH wire r/s back into a DER SEQUENCE and verifies the
    /// signature against the ECDSA public key using BCL
    /// <see cref="ECDsa.VerifyData(byte[], byte[], HashAlgorithmName,
    /// DSASignatureFormat)"/>. The DER re-encode mirrors
    /// <c>HostKeyVerifier.EncodeEcdsaDerSig</c> so the verify path is the same
    /// one OpenSSH's server-side verifier uses.
    /// </summary>
    private static bool VerifyEcdsa(
        SshEcdsaPemKey key, byte[] data, byte[] r, byte[] s, HashAlgorithmName hash, int coordSize)
    {
        // Reconstruct the ECPoint from the SEC1 uncompressed point (0x04 ‖ X ‖ Y).
        if (key.Point.Length != 1 + (2 * coordSize) || key.Point[0] != 0x04)
        {
            return false;
        }

        var q = new ECPoint
        {
            X = key.Point.AsSpan(1, coordSize).ToArray(),
            Y = key.Point.AsSpan(1 + coordSize, coordSize).ToArray(),
        };

        byte[] der = EncodeEcdsaDerSig(r, s);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(new ECParameters { Curve = key.Curve, Q = q });
        return ecdsa.VerifyData(data, der, hash, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Encodes r and s as a DER <c>SEQUENCE { INTEGER r, INTEGER s }</c>
    /// (Rfc3279DerSequence), matching the format BCL's
    /// <see cref="ECDsa.VerifyData(byte[], byte[], HashAlgorithmName,
    /// DSASignatureFormat)"/> expects when passed
    /// <see cref="DSASignatureFormat.Rfc3279DerSequence"/>. Mirrors
    /// <c>HostKeyVerifier.EncodeEcdsaDerSig</c>.
    /// </summary>
    private static byte[] EncodeEcdsaDerSig(byte[] r, byte[] s)
    {
        byte[] rDer = EncodeDerInteger(r);
        byte[] sDer = EncodeDerInteger(s);
        int seqLen = rDer.Length + sDer.Length;
        byte[] lenBytes = seqLen <= 0x7F
            ? new byte[] { (byte)seqLen }
            : new byte[] { 0x81, (byte)seqLen };
        byte[] sig = new byte[1 + lenBytes.Length + seqLen];
        sig[0] = 0x30;
        lenBytes.CopyTo(sig, 1);
        int offset = 1 + lenBytes.Length;
        rDer.CopyTo(sig, offset);
        sDer.CopyTo(sig, offset + rDer.Length);
        return sig;
    }

    /// <summary>
    /// Encodes a positive unsigned big-endian integer as a DER INTEGER
    /// (tag 0x02). Strips insignificant leading zeros, then prepends a 0x00
    /// sign guard if the value's high bit is set (DER INTEGER is two's
    /// complement). Mirrors <c>HostKeyVerifier.EncodeDerInteger</c>.
    /// </summary>
    private static byte[] EncodeDerInteger(byte[] unsignedBE)
    {
        int start = 0;
        while (start < unsignedBE.Length - 1 && unsignedBE[start] == 0)
        {
            start++;
        }

        int contentLen = unsignedBE.Length - start;
        bool prependZero = (unsignedBE[start] & 0x80) != 0;
        int len = contentLen + (prependZero ? 1 : 0);
        byte[] der = new byte[2 + len];
        der[0] = 0x02;
        der[1] = (byte)len;
        int offset = 2;
        if (prependZero)
        {
            der[offset] = 0;
            offset++;
        }

        unsignedBE.AsSpan(start, contentLen).CopyTo(der.AsSpan(offset));
        return der;
    }

    // ── SSH wire helpers (minimal, for sig blob parsing) ─────────────────────

    private static string ReadSshString(byte[] buf, out int offset)
    {
        int len = (int)BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(0, 4));
        string s = System.Text.Encoding.UTF8.GetString(buf, 4, len);
        offset = 4 + len;
        return s;
    }

    private static byte[] ReadSshBytes(byte[] buf, ref int offset)
    {
        int len = (int)BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        offset += 4;
        byte[] result = new byte[len];
        Buffer.BlockCopy(buf, offset, result, 0, len);
        offset += len;
        return result;
    }
}
