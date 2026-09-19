using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// ChaCha20 known-answer tests. libssh2's <c>chacha.c</c> is the Bernstein
/// original (8-byte nonce + 8-byte counter), NOT RFC 8439's IETF variant (4-byte
/// counter + 12-byte nonce), so no RFC vector reproduces. The expected bytes here
/// were captured by compiling the upstream <c>chacha.c</c> verbatim and dumping
/// its keystream on the same inputs (see generate-goldens.sh).
/// </summary>
public class ChaCha20Tests
{
    // key = 0x00..0x1f (the canonical 256-bit test key), iv = 8 zero bytes,
    // counter = 0. Encrypting 80 zero bytes yields the raw keystream (two blocks
    // + a partial third), exercising the 20-round permutation and the counter
    // increment between blocks.
    private const string GoldenKeystream80 =
        "39fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4cd8ea2492" +
        "2b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c" +
        "18b84231ade6a6d113615c61af434e27";

    // Same key, iv = {0,0,0,9,0,0,0,4a}, counter = {1,0,0,0,0,0,0,0}. Exercises
    // the ivsetup-with-counter path (the C `counter != NULL` branch).
    private const string GoldenIvCounterBlock =
        "98f17a63810d031c3693986691316d20b7b1f9d11f8c57ae8376ad21a144f193" +
        "f2ee4aee752d1e62833da3edfd63feda04efb2a851229d21397d0cdb938a7eed";

    private static byte[] TestKey()
    {
        byte[] k = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            k[i] = (byte)i;
        }

        return k;
    }

    [Fact]
    public void Keystream_DefaultKeyZeroIv_80Bytes_MatchesGolden()
    {
        var chacha = new ChaCha20();
        chacha.KeySetup(TestKey());
        chacha.IvSetup(new byte[8]);

        byte[] zeros = new byte[80];
        byte[] output = new byte[80];
        chacha.EncryptBytes(zeros, output);

        Assert.Equal(Convert.FromHexString(GoldenKeystream80), output);
    }

    [Fact]
    public void Block_IvAndCounterSingleBlock_MatchesGolden()
    {
        var chacha = new ChaCha20();
        chacha.KeySetup(TestKey());
        chacha.IvSetup(
            Convert.FromHexString("000000090000004a"),
            Convert.FromHexString("0100000000000000"));

        byte[] zeros = new byte[64];
        byte[] output = new byte[64];
        chacha.EncryptBytes(zeros, output);

        Assert.Equal(Convert.FromHexString(GoldenIvCounterBlock), output);
    }

    [Fact]
    public void RoundTrip_EncryptThenDecrypt_RestoresMessage()
    {
        // ChaCha20 is an XOR stream cipher: re-running the keystream (same
        // key/iv/counter) over the ciphertext restores the plaintext. Exercises a
        // multi-block message with a partial final block (100 = 64 + 36).
        byte[] plaintext = new byte[100];
        for (int i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)(i * 7 + 3);
        }

        byte[] ciphertext = new byte[100];
        var enc = new ChaCha20();
        enc.KeySetup(TestKey());
        enc.IvSetup(new byte[8]);
        enc.EncryptBytes(plaintext, ciphertext);

        byte[] restored = new byte[100];
        var dec = new ChaCha20();
        dec.KeySetup(TestKey());
        dec.IvSetup(new byte[8]);
        dec.EncryptBytes(ciphertext, restored);

        Assert.Equal(plaintext, restored);
    }

    [Fact]
    public void Encrypt_InPlace_RoundTrips()
    {
        byte[] data = new byte[64];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(0xa0 + i);
        }

        byte[] original = (byte[])data.Clone();
        var chacha = new ChaCha20();
        chacha.KeySetup(TestKey());
        chacha.IvSetup(new byte[8]);
        chacha.EncryptBytes(data, data);

        Assert.NotEqual(original, data);

        var dec = new ChaCha20();
        dec.KeySetup(TestKey());
        dec.IvSetup(new byte[8]);
        dec.EncryptBytes(data, data);

        Assert.Equal(original, data);
    }

    [Fact]
    public void KeySetup_RejectsBadKeyLength()
    {
        var chacha = new ChaCha20();
        Assert.Throws<ArgumentException>(() => chacha.KeySetup(new byte[31]));
    }

    [Fact]
    public void IvSetup_RejectsBadIvLength()
    {
        var chacha = new ChaCha20();
        chacha.KeySetup(TestKey());
        Assert.Throws<ArgumentException>(() => chacha.IvSetup(new byte[7]));
    }

    [Fact]
    public void IvSetup_RejectsBadCounterLength()
    {
        var chacha = new ChaCha20();
        chacha.KeySetup(TestKey());
        Assert.Throws<ArgumentException>(() => chacha.IvSetup(new byte[8], new byte[7]));
    }

    [Fact]
    public void Encrypt_RejectsUndersizedCipher()
    {
        var chacha = new ChaCha20();
        chacha.KeySetup(TestKey());
        chacha.IvSetup(new byte[8]);
        Assert.Throws<ArgumentException>(() => chacha.EncryptBytes(new byte[16], new byte[15]));
    }
}
