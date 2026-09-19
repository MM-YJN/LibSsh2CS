using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.PemKey;

/// <summary>
/// PKCS#8 legacy PEM parsing — parity with libssh2's OpenSSL-backed
/// PEM_read_bio_PrivateKey path (openssl.c:5016): unencrypted PrivateKeyInfo
/// ("PRIVATE KEY") and PBES2-encrypted EncryptedPrivateKeyInfo
/// ("ENCRYPTED PRIVATE KEY", PBKDF2 + AES-CBC/DES-EDE3-CBC), with RSA,
/// EC, and Ed25519 (RFC 8410) inner keys. Fixtures generated with
/// <c>openssl genrsa</c>/<c>openssl genpkey</c> (OpenSSL 3.x defaults).
/// </summary>
public class Pkcs8PemTests
{
    [Fact]
    public void ParsePkcs8_Unencrypted_ExtractsMatchingPublicKey()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.pkcs8.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.pkcs8.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);

        Assert.Equal("none", key.CipherName);
        // Byte-identical to what ssh-keygen wrote for the same key.
        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParsePkcs8_Unencrypted_PassphraseIgnored()
    {
        // OpenSSL never asks for a passphrase on an unencrypted key.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.pkcs8.pem");

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "ignored");

        Assert.Equal("none", key.CipherName);
        Assert.True(key.PrivateKeyBlob.Length > 0);
    }

    [Fact]
    public void ParsePkcs8_SignsAndVerifiesAgainstPubKey()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.pkcs8.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.pkcs8.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);
        var parsed = SshPemKey.Parse(key);
        RsaPemKey rsa = Assert.IsType<RsaPemKey>(parsed);

        byte[] data = "pkcs8-roundtrip"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(rsa, data, "rsa-sha2-256");

        // sigBlob = [string "rsa-sha2-256"][string rawSig] — extract rawSig.
        int algoLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sigBlob.AsSpan(0, 4));
        int rawSigLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sigBlob.AsSpan(4 + algoLen, 4));
        byte[] rawSig = sigBlob.AsSpan(4 + algoLen + 4, rawSigLen).ToArray();

        using var rsaPub = RSA.Create();
        var readerPub = new SshWireReader(pubBlob);
        _ = readerPub.ReadSshBytes();   // "ssh-rsa"
        byte[] e = readerPub.ReadSshBytes().ToArray();
        byte[] n = readerPub.ReadSshBytes().ToArray();
        rsaPub.ImportParameters(new RSAParameters { Exponent = e, Modulus = n });

        Assert.True(rsaPub.VerifyData(data, rawSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "signature from the PKCS#8 key must verify against the pub file");
    }

    [Theory]
    [InlineData("legacy_pem.pkcs8_enc.pem")]          // PBKDF2-HMAC-SHA256 + AES-128-CBC
    [InlineData("legacy_pem.pkcs8_enc_aes256.pem")]   // PBKDF2-HMAC-SHA256 + AES-256-CBC
    [InlineData("legacy_pem.pkcs8_enc_des3.pem")]     // PBKDF2-HMAC-SHA256 + DES-EDE3-CBC
    [InlineData("legacy_pem.pkcs8_enc_sha1.pem")]     // no PRF element → HMAC-SHA1 default + AES-128-CBC
    public void ParseEncryptedPkcs8_CorrectPassphrase_ExtractsMatchingPublicKey(string fixtureName)
    {
        byte[] pem = FixtureLoader.LoadBytes(fixtureName);
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes(fixtureName[..^".pem".Length] + ".pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");

        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParseEncryptedPkcs8_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.pkcs8_enc.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "wrong"));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
        // The C's exact BAD_DECRYPT message (openssl.c:5039).
        Assert.Contains("Wrong passphrase for private key", ex.Message);
    }

    [Fact]
    public void ParseEncryptedPkcs8_MissingPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.pkcs8_enc.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
    }

    [Fact]
    public void ParseEncryptedPkcs8_SignsAndVerifiesAgainstPubKey()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.pkcs8_enc.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.pkcs8_enc.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");
        var parsed = SshPemKey.Parse(key);
        RsaPemKey rsa = Assert.IsType<RsaPemKey>(parsed);

        byte[] data = "encrypted-pkcs8-roundtrip"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(rsa, data, "rsa-sha2-256");

        int algoLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sigBlob.AsSpan(0, 4));
        int rawSigLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sigBlob.AsSpan(4 + algoLen, 4));
        byte[] rawSig = sigBlob.AsSpan(4 + algoLen + 4, rawSigLen).ToArray();

        using var rsaPub = RSA.Create();
        var readerPub = new SshWireReader(pubBlob);
        _ = readerPub.ReadSshBytes();   // "ssh-rsa"
        byte[] e = readerPub.ReadSshBytes().ToArray();
        byte[] n = readerPub.ReadSshBytes().ToArray();
        rsaPub.ImportParameters(new RSAParameters { Exponent = e, Modulus = n });

        Assert.True(rsaPub.VerifyData(data, rawSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "signature from the encrypted PKCS#8 key must verify against the pub file");
    }

    [Fact]
    public void ParsePkcs8_Ed25519_Unencrypted_ExtractsMatchingPublicKey()
    {
        // id-Ed25519 PKCS#8 (RFC 8410): the inner OCTET STRING is the raw
        // 32-byte seed; the public key is derived (RFC 8032 §5.1.5) and must
        // match OpenSSL's raw public key (the .pub fixture is built from
        // `openssl pkey -pubout` — ssh-keygen itself cannot read Ed25519
        // PKCS#8, but libssh2 via OpenSSL can).
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);

        Assert.Equal("none", key.CipherName);
        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParsePkcs8_Ed25519_SignsAndVerifiesAgainstPubKey()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);
        var parsed = SshPemKey.Parse(key);
        SshEd25519PemKey ed = Assert.IsType<SshEd25519PemKey>(parsed);

        byte[] data = "ed25519-pkcs8-roundtrip"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(ed, data, "ssh-ed25519");

        // sigBlob = [string "ssh-ed25519"][string rawSig(64)].
        var sigReader = new SshWireReader(sigBlob);
        _ = sigReader.ReadSshBytes();
        byte[] rawSig = sigReader.ReadSshBytes().ToArray();

        // pubBlob = [string "ssh-ed25519"][string A(32)].
        var readerPub = new SshWireReader(pubBlob);
        _ = readerPub.ReadSshBytes();
        byte[] publicKey = readerPub.ReadSshBytes().ToArray();

        Assert.True(Ed25519.Verify(publicKey, data, rawSig),
            "signature from the Ed25519 PKCS#8 key must verify against the pub file");
    }

    [Fact]
    public void ParsePkcs8_Ed25519_Encrypted_CorrectPassphrase_ExtractsMatchingPublicKey()
    {
        // `openssl genpkey -algorithm ED25519 -aes128` — PBES2-encrypted.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8_enc.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8_enc.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");

        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParsePkcs8_Ed25519_Encrypted_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ed25519_pkcs8_enc.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "wrong"));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
    }

    [Fact]
    public void ParsePkcs8_Ed25519_MismatchedEmbeddedPublicKey_ThrowsFile()
    {
        // PKCS#8 with a [1] public key that does not match the seed: OpenSSL
        // rejects it (verified empirically with `openssl pkey`) → the C's
        // plain FILE error.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ed25519_badpub.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem));

        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
        Assert.Contains("Unsupported private key file format", ex.Message);
    }

    [Fact]
    public void ParsePkcs8_X25519Oid_ThrowsFile()
    {
        // X25519 PKCS#8 ("BEGIN PRIVATE KEY" with id-X25519): the C's
        // PEM path hits its default case → FILE "Unsupported private key
        // file format" (openssl.c:5081-5088) — exact parity, not a gap.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.x25519_pkcs8.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem));

        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
        Assert.Contains("Unsupported private key file format", ex.Message);
    }

    [Fact]
    public void ParsePkcs8Garbage_ThrowsFile()
    {
        // Malformed DER under the PRIVATE KEY marker → the user-facing
        // libssh2 mapping (FILE "Unsupported private key file format",
        // openssl.c:5043-5047).
        const string garbage = """
            -----BEGIN PRIVATE KEY-----
            notbase64notbase64notbase64notbase64notbase64notbase64notbase64
            -----END PRIVATE KEY-----
            """;

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(Encoding.ASCII.GetBytes(garbage)));

        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
        Assert.Contains("Unsupported private key file format", ex.Message);
    }
}
