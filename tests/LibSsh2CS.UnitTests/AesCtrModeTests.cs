using System.Security.Cryptography;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// AES-CTR mode known-answer tests. Vectors from RFC 3686 §F.5 (AES-128) and
/// NIST CTR test vectors. Verifies our manual CTR construction matches the
/// standard.
/// </summary>
public class AesCtrModeTests
{
    /// <summary>
    /// RFC 3686 §F.5.1, Counter 0 (initial counter = IV):
    /// Key: AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E
    /// IV:  00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01
    /// Plaintext block 1: "Single block msg" (16 bytes)
    /// Expected ciphertext verified against <c>openssl enc -aes-128-ctr</c>.
    /// </summary>
    [Fact]
    public void TransformAes128Ctr_Rfc3686Vector_MatchesOpenSslOutput()
    {
        byte[] key = Convert.FromHexString("AE6852F8121067CC4BF7A5765577F39E");
        byte[] iv = Convert.FromHexString("00000030000000000000000000000001");
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("Single block msg");
        byte[] expected = Convert.FromHexString("E4095D4FB7A7B3792D6175A3261311B8");

        byte[] actual = AesCtrMode.Transform(plaintext, key, iv);

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// CTR mode is symmetric: decrypt(encrypt(x)) == x. Round-trip on
    /// variable-length input (not aligned to block size).
    /// </summary>
    [Fact]
    public void Transform_RoundTrip_PreservesOriginalPlaintext()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = RandomNumberGenerator.GetBytes(100); // not 16-aligned

        byte[] ciphertext = AesCtrMode.Transform(plaintext, key, iv);
        byte[] roundtrip = AesCtrMode.Transform(ciphertext, key, iv);

        Assert.Equal(plaintext, roundtrip);
    }

    /// <summary>
    /// AES-256-CTR with a 32-byte key works correctly.
    /// </summary>
    [Fact]
    public void TransformAes256Ctr_RoundTrip_PreservesPlaintext()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = RandomNumberGenerator.GetBytes(256);

        byte[] ciphertext = AesCtrMode.Transform(plaintext, key, iv);
        byte[] roundtrip = AesCtrMode.Transform(ciphertext, key, iv);

        Assert.Equal(plaintext, roundtrip);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Theory]
    [InlineData(15)]  // too short
    [InlineData(17)]  // too long
    [InlineData(24)]  // AES-192 (valid)
    public void Transform_RejectsInvalidKeyLength(int keyLength)
    {
        // AES-192 (24) is valid; only test the rejection cases.
        if (keyLength == 24)
        {
            byte[] key = RandomNumberGenerator.GetBytes(keyLength);
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            byte[] plaintext = new byte[] { 1, 2, 3 };
            byte[] result = AesCtrMode.Transform(plaintext, key, iv); // should not throw
            Assert.Equal(plaintext.Length, result.Length);
        }
        else
        {
            byte[] key = RandomNumberGenerator.GetBytes(keyLength);
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            Assert.Throws<ArgumentOutOfRangeException>(() => AesCtrMode.Transform(new byte[] { 1, 2, 3 }, key, iv));
        }
    }

    [Fact]
    public void Transform_RejectsInvalidIvLength()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] iv = RandomNumberGenerator.GetBytes(15); // not 16
        Assert.Throws<ArgumentOutOfRangeException>(() => AesCtrMode.Transform(new byte[] { 1, 2, 3 }, key, iv));
    }
}
