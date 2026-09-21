using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Golden KATs for increment-8 hostkey verification, driven by the captured
/// <c>Fixtures/hostkey/&lt;type&gt;/</c> oracles (7 host-key types, one live
/// libssh2→OpenSSH handshake each, curve25519-sha256 kex). These are the
/// parity-critical tests: they pin the sig-blob parse, the hash-per-type
/// selection, the DER r/s reconstruction (ECDSA), and the BCL RSA/ECDsa/Ed25519
/// verify paths against real OpenSSH-produced signatures.
/// </summary>
public class HostKeyVerifierTests
{
    // The 7 in-scope host-key types. The dir name (carrying hyphens) is derived
    // from the enum so the Theory stays single-sourced.
    public static TheoryData<SshHostKeyType> Types => new()
    {
        SshHostKeyType.Ed25519,
        SshHostKeyType.Ecdsa256,
        SshHostKeyType.Ecdsa384,
        SshHostKeyType.Ecdsa521,
        SshHostKeyType.RsaSha256,
        SshHostKeyType.RsaSha512,
        SshHostKeyType.SshRsa,
    };

    [Theory]
    [MemberData(nameof(Types))]
    public void Verify_MatchesCapturedOracle(SshHostKeyType type)
    {
        HostKeyFixture fx = Load(type);
        Assert.True(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, fx.Sig, type));
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void Verify_TamperedExchangeHash_Fails(SshHostKeyType type)
    {
        HostKeyFixture fx = Load(type);
        byte[] badH = (byte[])fx.ExchangeHash.Clone();
        badH[0] ^= 0x01;   // flip one bit in the signed message
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, badH, fx.Sig, type));
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void Verify_TamperedSignature_Fails(SshHostKeyType type)
    {
        HostKeyFixture fx = Load(type);
        byte[] badSig = (byte[])fx.Sig.Clone();
        badSig[^1] ^= 0x01;   // flip one bit in the last byte (always sig body, never a length)
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, badSig, type));
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void Verify_TruncatedSignature_Fails(SshHostKeyType type)
    {
        HostKeyFixture fx = Load(type);
        byte[] shortSig = fx.Sig.AsSpan(0, fx.Sig.Length / 2).ToArray();
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, shortSig, type));
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void Verify_WrongHostKeyType_Fails(SshHostKeyType type)
    {
        HostKeyFixture fx = Load(type);
        // Present the captured blob but claim a different type — the embedded
        // sig-blob name will not match, so verify must fail before any crypto.
        SshHostKeyType wrong = type == SshHostKeyType.Ed25519
            ? SshHostKeyType.RsaSha256
            : SshHostKeyType.Ed25519;
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, fx.Sig, wrong));
    }

    [Theory]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    [InlineData("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    [InlineData("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000080")]
    public void Verify_RejectsInvalidEd25519PointsInPublicKeyAndR(string hex)
    {
        byte[] point = Convert.FromHexString(hex);
        HostKeyFixture fx = Load(SshHostKeyType.Ed25519);
        byte[] badKey = (byte[])fx.HostKey.Clone();
        point.CopyTo(badKey, badKey.Length - 32);
        Assert.False(HostKeyVerifier.Verify(badKey, fx.ExchangeHash, fx.Sig, SshHostKeyType.Ed25519));
        byte[] badSig = (byte[])fx.Sig.Clone();
        point.CopyTo(badSig, badSig.Length - 64);
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, badSig, SshHostKeyType.Ed25519));
    }

    [Fact]
    public void Verify_RejectsIdentityKeyForgery()
    {
        byte[] identity = new byte[32];
        identity[0] = 1;
        byte[] signature = new byte[64];
        // R = B, S = 1 satisfies the old equation for A = identity for every message.
        Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666").CopyTo(signature, 0);
        signature[32] = 1;
        Assert.False(HostKeyVerifier.Verify(BuildSigBlob("ssh-ed25519", identity), new byte[] { 42 },
            BuildSigBlob("ssh-ed25519", signature), SshHostKeyType.Ed25519));
    }

    [Fact]
    public void Verify_RejectsEd25519ScalarAtOrder()
    {
        HostKeyFixture fx = Load(SshHostKeyType.Ed25519);
        byte[] badSig = (byte[])fx.Sig.Clone();
        LibSsh2CS.Crypto.Ed25519.L.ToByteArray(isUnsigned: true).CopyTo(badSig, badSig.Length - 32);
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, badSig, SshHostKeyType.Ed25519));
    }

    [Fact]
    public void Verify_MismatchedSigName_Fails()
    {
        // A well-formed envelope with a name that doesn't match the negotiated type.
        HostKeyFixture fx = Load(SshHostKeyType.Ed25519);
        byte[] blob = BuildSigBlob("ssh-rsa", fx.Sig.AsSpan(4 + 11).ToArray());
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, blob, SshHostKeyType.Ed25519));
    }

    [Fact]
    public void Verify_UnknownType_Fails()
    {
        HostKeyFixture fx = Load(SshHostKeyType.Ed25519);
        Assert.False(HostKeyVerifier.Verify(fx.HostKey, fx.ExchangeHash, fx.Sig, SshHostKeyType.Unknown));
    }

    [Fact]
    public void Verify_MalformedRsaParameters_ReturnsFalse()
    {
        // BCL RSA.ImportParameters throws for attacker-controlled
        // degenerate modulus/exponent. The public contract says any parse or
        // verify failure returns false, so these must not escape as raw BCL
        // exceptions.
        byte[] hostKey = BuildBlob(
            System.Text.Encoding.ASCII.GetBytes("ssh-rsa"),
            new byte[] { 0 },      // e
            new byte[] { 0 });     // n
        byte[] sigBlob = BuildSigBlob("ssh-rsa", new byte[128]);
        byte[] exchangeHash = new byte[32];

        Assert.False(HostKeyVerifier.Verify(hostKey, exchangeHash, sigBlob, SshHostKeyType.SshRsa));
    }

    [Fact]
    public void Verify_OffCurveEcdsaPoint_ReturnsFalse()
    {
        // ECDsa.ImportParameters throws for an off-curve SEC1 point. The
        // verifier must convert that to a normal verification failure.
        byte[] point = new byte[65];
        point[0] = 0x04;   // uncompressed marker; X and Y are all zero (off-curve)
        byte[] hostKey = BuildBlob(
            System.Text.Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256"),
            System.Text.Encoding.ASCII.GetBytes("nistp256"),
            point);

        byte[] r = new byte[] { 1 };
        byte[] s = new byte[] { 1 };
        byte[] sigBody = BuildBlob(r, s);
        byte[] sigBlob = BuildSigBlob("ecdsa-sha2-nistp256", sigBody);
        byte[] exchangeHash = new byte[32];

        Assert.False(HostKeyVerifier.Verify(hostKey, exchangeHash, sigBlob, SshHostKeyType.Ecdsa256));
    }

    private static HostKeyFixture Load(SshHostKeyType type) => HostKeyFixtureLoader.Load(DirFor(type));

    private static string DirFor(SshHostKeyType type) => type switch
    {
        SshHostKeyType.Ed25519 => "ssh-ed25519",
        SshHostKeyType.Ecdsa256 => "ecdsa-sha2-nistp256",
        SshHostKeyType.Ecdsa384 => "ecdsa-sha2-nistp384",
        SshHostKeyType.Ecdsa521 => "ecdsa-sha2-nistp521",
        SshHostKeyType.RsaSha256 => "rsa-sha2-256",
        SshHostKeyType.RsaSha512 => "rsa-sha2-512",
        SshHostKeyType.SshRsa => "ssh-rsa",
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    /// <summary>Builds a <c>string name + string body</c> sig-blob envelope.</summary>
    private static byte[] BuildSigBlob(string name, byte[] body)
    {
        byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
        byte[] blob = new byte[4 + nameBytes.Length + 4 + body.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(0, 4), (uint)nameBytes.Length);
        nameBytes.CopyTo(blob, 4);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            blob.AsSpan(4 + nameBytes.Length, 4), (uint)body.Length);
        body.CopyTo(blob, 4 + nameBytes.Length + 4);
        return blob;
    }

    /// <summary>Builds a sequence of SSH string fields (u32 length + bytes).</summary>
    private static byte[] BuildBlob(params byte[][] parts)
    {
        int total = parts.Sum(p => 4 + p.Length);
        byte[] blob = new byte[total];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(offset, 4), (uint)part.Length);
            part.CopyTo(blob, offset + 4);
            offset += 4 + part.Length;
        }

        return blob;
    }
}
