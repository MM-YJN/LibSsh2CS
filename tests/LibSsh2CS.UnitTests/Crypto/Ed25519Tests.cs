using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Ed25519 verify known-answer tests from RFC 8032 §7.1 (TEST 1-3). If these
/// pass, the field arithmetic, point decompression, point arithmetic, base
/// point, and scalar range-check are all correct against the prime reference
/// implementation.
/// </summary>
public class Ed25519Tests
{
    /// <summary>
    /// RFC 8032 §7.1 TEST 1 — empty message. The canonical Ed25519 sanity vector.
    /// </summary>
    [Fact]
    public void Verify_Rfc8032_Test1_EmptyMessage_Accepts()
    {
        byte[] sk = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] pk = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] sig = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        // RFC public key is derived from the secret (SHA-512 lower half, clamped,
        // times basepoint). We verify only here, so we assert that the documented
        // public key validates the documented signature over the empty message.
        _ = sk; // secret not used by Verify; referenced for documentation parity.
        bool valid = Ed25519.Verify(pk, Array.Empty<byte>(), sig);
        Assert.True(valid);
    }

    /// <summary>
    /// RFC 8032 §7.1 TEST 2 — single-byte message (0x72).
    /// </summary>
    [Fact]
    public void Verify_Rfc8032_Test2_OneByteMessage_Accepts()
    {
        byte[] pk = Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        byte[] message = "r"u8.ToArray();
        byte[] sig = Convert.FromHexString(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

        bool valid = Ed25519.Verify(pk, message, sig);
        Assert.True(valid);
    }

    /// <summary>
    /// RFC 8032 §7.1 TEST 3 — two-byte message (af82).
    /// </summary>
    [Fact]
    public void Verify_Rfc8032_Test3_TwoByteMessage_Accepts()
    {
        byte[] pk = Convert.FromHexString("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        byte[] message = new byte[] { 0xaf, 0x82 };
        byte[] sig = Convert.FromHexString(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

        bool valid = Ed25519.Verify(pk, message, sig);
        Assert.True(valid);
    }

    /// <summary>
    /// A valid signature must be rejected if the message is tampered with.
    /// Guards against a verify that returns true unconditionally.
    /// </summary>
    [Fact]
    public void Verify_TamperedMessage_Rejected()
    {
        byte[] pk = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] sig = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        byte[] message = new byte[] { 0x01 }; // not the empty message that was signed

        bool valid = Ed25519.Verify(pk, message, sig);
        Assert.False(valid);
    }

    /// <summary>
    /// A single bit flipped in the signature must cause rejection.
    /// </summary>
    [Fact]
    public void Verify_TamperedSignature_Rejected()
    {
        byte[] pk = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] sig = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        sig[0] ^= 0x01; // flip the low bit of R

        bool valid = Ed25519.Verify(pk, Array.Empty<byte>(), sig);
        Assert.False(valid);
    }

    /// <summary>
    /// S &gt;= L must be rejected per RFC 8032 §5.1.7 step 1. Constructed by taking
    /// a valid S and setting its top byte so the scalar exceeds L.
    /// </summary>
    [Fact]
    public void Verify_SOutOfRange_Rejected()
    {
        byte[] pk = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] sig = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // S above is 2^256 - 1, far above L.

        bool valid = Ed25519.Verify(pk, Array.Empty<byte>(), sig);
        Assert.False(valid);
    }

    /// <summary>
    /// Malformed inputs (wrong lengths) must not throw and must return false.
    /// </summary>
    [Theory]
    [InlineData(16, 64)]
    [InlineData(32, 32)]
    [InlineData(31, 63)]
    public void Verify_MalformedLengths_ReturnFalse(int pkLen, int sigLen)
    {
        byte[] pk = new byte[pkLen];
        byte[] sig = new byte[sigLen];
        bool valid = Ed25519.Verify(pk, Array.Empty<byte>(), sig);
        Assert.False(valid);
    }
}
