using System.Security.Cryptography;
using System.Text;

namespace LibSsh2CS.UnitTests.PemKey;

/// <summary>
/// SEC1 EC legacy PEM parsing — parity with libssh2's OpenSSL-backed
/// PEM_read_bio_PrivateKey + gen_publickey_from_ec_evp path (openssl.c:5016,
/// 5076-5080): unencrypted and traditional-encrypted (Proc-Type/DEK-Info)
/// "EC PRIVATE KEY" (RFC 5915), plus EC PKCS#8 (id-ecPublicKey). Fixtures
/// generated with <c>openssl ecparam</c>/<c>openssl ec</c>/<c>openssl genpkey</c>.
/// </summary>
public class EcLegacyPemTests
{
    [Theory]
    [InlineData("legacy_pem.ec_sec1.pem", "ecdsa-sha2-nistp256")]   // prime256v1
    [InlineData("legacy_pem.ec_sec1_384.pem", "ecdsa-sha2-nistp384")]  // secp384r1
    [InlineData("legacy_pem.ec_sec1_521.pem", "ecdsa-sha2-nistp521")]  // secp521r1
    public void ParseSec1_Unencrypted_ExtractsMatchingPublicKey(string fixtureName, string expectedMethod)
    {
        byte[] pem = FixtureLoader.LoadBytes(fixtureName);
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes(fixtureName[..^".pem".Length] + ".pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);

        Assert.Equal("none", key.CipherName);
        // Byte-identical to what ssh-keygen wrote for the same key.
        Assert.Equal(pubBlob, key.PublicKeyBlob);
        // The blob starts with the method string.
        Assert.True(key.PublicKeyBlob.AsSpan(4).StartsWith(Encoding.ASCII.GetBytes(expectedMethod)));
    }

    [Fact]
    public void ParseSec1_Unencrypted_PassphraseIgnored()
    {
        // OpenSSL never asks for a passphrase on an unencrypted key.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_sec1.pem");

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "ignored");

        Assert.Equal("none", key.CipherName);
        Assert.True(key.PrivateKeyBlob.Length > 0);
    }

    [Fact]
    public void ParseSec1_SignsAndVerifiesAgainstPubKey()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_sec1.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ec_sec1.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);
        var parsed = SshPemKey.Parse(key);
        SshEcdsaPemKey ecdsa = Assert.IsType<SshEcdsaPemKey>(parsed);

        byte[] data = "sec1-ecdsa-roundtrip"u8.ToArray();
        byte[] sigBlob = SshSign.Sign(ecdsa, data, "ecdsa-sha2-nistp256");

        // sigBlob = [string algo][string rawSig], rawSig = [string r][string s]
        // — extract r and s and verify via a DER re-encode (the same path
        // OpenSSH's verifier uses).
        var sigReader = new SshWireReader(sigBlob);
        _ = sigReader.ReadSshBytes();   // "ecdsa-sha2-nistp256"
        byte[] rawSig = sigReader.ReadSshBytes().ToArray();
        var rsReader = new SshWireReader(rawSig);
        byte[] r = rsReader.ReadSshBytes().ToArray();
        byte[] s = rsReader.ReadSshBytes().ToArray();

        var readerPub = new SshWireReader(pubBlob);
        _ = readerPub.ReadSshBytes();   // "ecdsa-sha2-nistp256"
        _ = readerPub.ReadSshBytes();   // curve name
        byte[] point = readerPub.ReadSshBytes().ToArray();
        using var ecdsaPub = ECDsa.Create();
        ecdsaPub.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = DecodePoint(point),
        });

        byte[] der = EncodeEcdsaDerSig(r, s);
        Assert.True(ecdsaPub.VerifyData(data, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
            "signature from the SEC1 key must verify against the pub file");
    }

    [Fact]
    public void ParseSec1_Encrypted_CorrectPassphrase_ExtractsMatchingPublicKey()
    {
        // `openssl ec -aes128` — the traditional Proc-Type/DEK-Info scheme.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_sec1_enc.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ec_sec1_enc.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");

        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParseSec1_Encrypted_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_sec1_enc.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "wrong"));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
        // The C's exact BAD_DECRYPT message (openssl.c:5039).
        Assert.Contains("Wrong passphrase for private key", ex.Message);
    }

    [Fact]
    public void ParsePkcs8_Ec_Unencrypted_ExtractsMatchingPublicKey()
    {
        // id-ecPublicKey PKCS#8 — the inner OCTET STRING is SEC1.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_pkcs8.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ec_pkcs8.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem);

        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParsePkcs8_Ec_Encrypted_CorrectPassphrase_ExtractsMatchingPublicKey()
    {
        // `openssl genpkey -aes128` — PBES2-encrypted EC PKCS#8.
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_pkcs8_enc.pem");
        byte[] pubBlob = FixtureLoader.ParsePubFileBlob(
            Encoding.ASCII.GetString(FixtureLoader.LoadBytes("legacy_pem.ec_pkcs8_enc.pub")));

        OpenSshKey key = SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "testpass");

        Assert.Equal(pubBlob, key.PublicKeyBlob);
    }

    [Fact]
    public void ParsePkcs8_Ec_Encrypted_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        byte[] pem = FixtureLoader.LoadBytes("legacy_pem.ec_pkcs8_enc.pem");

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(pem, passphrase: "wrong"));

        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
    }

    [Fact]
    public void ParseEcGarbage_ThrowsFile()
    {
        // Malformed DER under the EC marker → the user-facing libssh2
        // mapping (FILE "Unsupported private key file format",
        // openssl.c:5043-5047).
        const string garbage = """
            -----BEGIN EC PRIVATE KEY-----
            notbase64notbase64notbase64notbase64notbase64notbase64notbase64
            -----END EC PRIVATE KEY-----
            """;

        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(Encoding.ASCII.GetBytes(garbage)));

        Assert.Equal(SshErrorCode.File, ex.ErrorCode);
        Assert.Contains("Unsupported private key file format", ex.Message);
    }

    /// <summary>SEC1 uncompressed point (0x04‖X‖Y) → ECParameters.Q.</summary>
    private static ECPoint DecodePoint(byte[] point)
    {
        Assert.Equal(0x04, point[0]);
        int half = (point.Length - 1) / 2;
        return new ECPoint
        {
            X = point.AsSpan(1, half).ToArray(),
            Y = point.AsSpan(1 + half, half).ToArray(),
        };
    }

    /// <summary>
    /// Encodes SSH-wire r and s as a DER <c>SEQUENCE { INTEGER r, INTEGER s }</c>
    /// (Rfc3279DerSequence), the format BCL's ECDsa.VerifyData expects.
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
    /// (tag 0x02): strips insignificant leading zeros, then prepends a 0x00
    /// sign guard if the value's high bit is set.
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
}
