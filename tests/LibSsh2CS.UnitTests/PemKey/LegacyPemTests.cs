using System.Security.Cryptography;
using System.Text;

namespace LibSsh2CS.UnitTests.PemKey;

/// <summary>
/// Legacy PEM (unencrypted PKCS#1 "RSA PRIVATE KEY") parsing — parity with
/// libssh2's OpenSSL-backed PEM_read_bio_PrivateKey path (openssl.c:5016).
/// Fixtures generated with <c>ssh-keygen -t rsa -m PEM</c>.
/// </summary>
public class LegacyPemTests
{
    [Fact]
    public void ParseLegacyRsa_Unencrypted_ExtractsMatchingPublicKey()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.legacy_rsa");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.legacy_rsa.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);

        Assert.Equal("none", key.CipherName);
        Assert.Equal("none", key.KdfName);
        // The constructed public blob must byte-match what ssh-keygen wrote
        // to the .pub file.
        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParseLegacyRsa_Unencrypted_PassphraseIgnored()
    {
        // Parity with the C's silent-ignore quirk for unencrypted keys.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.legacy_rsa");

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "ignored");

        Assert.Equal("none", key.CipherName);
        Assert.True(key.PrivateKeyBlob.Length > 0);
    }

    [Fact]
    public void ParseLegacyRsa_SignsAndVerifiesAgainstPubKey()
    {
        // End-to-end: the constructed OpenSSH-format blobs must flow through
        // SshPemKey.Parse + SshSign, and the signature must verify against
        // the public key from the .pub file.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.legacy_rsa");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.legacy_rsa.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);
        var parsed = SshPemKey.Parse(key);
        RsaPemKey rsa = Assert.IsType<RsaPemKey>(parsed);

        byte[] data = "legacy-pem-roundtrip"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(rsa, data, "rsa-sha2-256");

        // sigBlob = [string "rsa-sha2-256"][string rawSig] — extract rawSig.
        int algoLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sigBlob.AsSpan(0, 4));
        int rawSigLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(sigBlob.AsSpan(4 + algoLen, 4));
        byte[] rawSig = sigBlob.AsSpan(4 + algoLen + 4, rawSigLen).ToArray();

        // Reconstruct the public key from the pub blob: [string "ssh-rsa"][string e][string n].
        using var rsaPub = RSA.Create();
        var readerPub = new SshWireReader(pubBlob);
        _ = readerPub.ReadSshBytes();   // "ssh-rsa"
        byte[] e = readerPub.ReadSshBytes().ToArray();
        byte[] n = readerPub.ReadSshBytes().ToArray();
        rsaPub.ImportParameters(new RSAParameters { Exponent = e, Modulus = n });

        Assert.True(rsaPub.VerifyData(data, rawSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "signature from the legacy-PEM key must verify against the pub file");
    }

    [Fact]
    public void ParseEncryptedLegacyRsa_CorrectPassphrase_ExtractsMatchingPublicKey()
    {
        // Fixture generated with `ssh-keygen -t rsa -m PEM -N 'testpass'`:
        // Proc-Type: 4,ENCRYPTED + DEK-Info: AES-128-CBC (parity with
        // OpenSSL's PEM_read path).
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.enc_rsa");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.enc_rsa.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");

        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParseEncryptedLegacyRsa_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.enc_rsa");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "wrong"));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
        // The C's exact BAD_DECRYPT message (openssl.c:5039).
        Assert.Contains("Wrong passphrase for private key", ex.Message);
    }

    [Fact]
    public void ParseEncryptedLegacyRsa_MissingPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.enc_rsa");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
    }

    [Fact]
    public void ParseEncryptedLegacyRsa_SignsAndVerifiesAgainstPubKey()
    {
        // End-to-end through SshPemKey + SshSign, verified against the .pub.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.enc_rsa");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.enc_rsa.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");
        var parsed = SshPemKey.Parse(key);
        RsaPemKey rsa = Assert.IsType<RsaPemKey>(parsed);

        byte[] data = "encrypted-legacy-pem-roundtrip"u8.ToArray();
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
            "signature from the encrypted legacy-PEM key must verify against the pub file");
    }

    [Fact]
    public void ParseGarbageLegacyArmor_ThrowsFile()
    {
        // Malformed DER under the RSA marker → the user-facing libssh2
        // mapping (FILE "Unsupported private key file format",
        // openssl.c:5043-5047).
        const string garbage = """
            -----BEGIN RSA PRIVATE KEY-----
            notbase64notbase64notbase64notbase64notbase64notbase64notbase64
            -----END RSA PRIVATE KEY-----
            """;

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(Encoding.ASCII.GetBytes(garbage)));

        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
        Assert.Contains("Unsupported private key file format", ex.Message);
    }
}
