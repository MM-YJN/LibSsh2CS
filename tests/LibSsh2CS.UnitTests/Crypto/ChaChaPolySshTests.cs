using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// SSH ChaCha20-Poly1305 AEAD tests. The encryption golden was captured from the
/// upstream <c>cipher-chachapoly.c</c> <c>chachapoly_crypt</c> on a fixed
/// (key, seqnr, aad, payload) — the real parity target for
/// <c>chacha20-poly1305@openssh.com</c>. No RFC vector applies: the construction
/// differs from RFC 8439's single-key AEAD.
/// </summary>
public class ChaChaPolySshTests
{
    // key = 0x00..0x3f (main ‖ header, 64 bytes).
    private static byte[] Key()
    {
        byte[] k = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            k[i] = (byte)i;
        }

        return k;
    }

    // src = 4-byte AAD (big-endian length 20) ‖ 20-byte payload (0x40..0x53).
    private static byte[] MakePlaintext()
    {
        byte[] src = new byte[24];
        src[3] = 20; // aad: length = 0x00000014
        for (int i = 0; i < 20; i++)
        {
            src[4 + i] = (byte)(0x40 + i);
        }

        return src;
    }

    private const uint Seqnr = 42;
    private const string AadCipherHex = "08ce9803";
    private const string PayloadCipherHex = "be10e9c93e770bb96529342141bce6805b17402b";
    private const string TagHex = "f45dbbb46d46ef1a52aba7504478636a";

    [Fact]
    public void Encrypt_FixedKeySeqnr_MatchesGolden()
    {
        var aead = new ChaChaPolySsh();
        aead.Init(Key());

        byte[] src = MakePlaintext();
        byte[] dest = new byte[4 + 20 + 16];
        aead.Crypt(Seqnr, dest, src, len: 20, aadlen: 4, encrypt: true);

        Assert.Equal(Convert.FromHexString(AadCipherHex), dest.AsSpan(0, 4).ToArray());
        Assert.Equal(Convert.FromHexString(PayloadCipherHex), dest.AsSpan(4, 20).ToArray());
        Assert.Equal(Convert.FromHexString(TagHex), dest.AsSpan(24, 16).ToArray());
    }

    [Fact]
    public void Decrypt_RoundTrip_RestoresPlaintext()
    {
        var enc = new ChaChaPolySsh();
        enc.Init(Key());
        byte[] src = MakePlaintext();
        byte[] ciphertext = new byte[4 + 20 + 16];
        enc.Crypt(Seqnr, ciphertext, src, len: 20, aadlen: 4, encrypt: true);

        var dec = new ChaChaPolySsh();
        dec.Init(Key());
        byte[] restored = new byte[4 + 20];
        dec.Crypt(Seqnr, restored, ciphertext, len: 20, aadlen: 4, encrypt: false);

        Assert.Equal(src, restored);
    }

    [Fact]
    public void GetLength_DecryptsEncryptedLengthField()
    {
        // The header key encrypts the 4-byte packet length; GetLength reverses it
        // for the reader. Encrypt produced aad-cipher 08ce9803 → length 20.
        var aead = new ChaChaPolySsh();
        aead.Init(Key());

        Assert.Equal(20u, aead.GetLength(Seqnr, Convert.FromHexString(AadCipherHex)));
    }

    [Fact]
    public void Decrypt_TamperedTag_ThrowsDecrypt()
    {
        var enc = new ChaChaPolySsh();
        enc.Init(Key());
        byte[] src = MakePlaintext();
        byte[] ciphertext = new byte[4 + 20 + 16];
        enc.Crypt(Seqnr, ciphertext, src, len: 20, aadlen: 4, encrypt: true);

        // Flip a bit in the tag (offset 25 = inside the 16-byte tag region).
        ciphertext[25] ^= 0x01;

        var dec = new ChaChaPolySsh();
        dec.Init(Key());
        byte[] restored = new byte[4 + 20];

        SshException ex = Assert.Throws<SshException>(
            () => dec.Crypt(Seqnr, restored, ciphertext, len: 20, aadlen: 4, encrypt: false));
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsDecrypt()
    {
        // Flipping a payload byte changes the recomputed Poly1305 tag → mismatch.
        var enc = new ChaChaPolySsh();
        enc.Init(Key());
        byte[] src = MakePlaintext();
        byte[] ciphertext = new byte[4 + 20 + 16];
        enc.Crypt(Seqnr, ciphertext, src, len: 20, aadlen: 4, encrypt: true);

        ciphertext[10] ^= 0x80;

        var dec = new ChaChaPolySsh();
        dec.Init(Key());
        byte[] restored = new byte[4 + 20];

        SshException ex = Assert.Throws<SshException>(
            () => dec.Crypt(Seqnr, restored, ciphertext, len: 20, aadlen: 4, encrypt: false));
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    [Fact]
    public void Init_RejectsBadKeyLength()
    {
        var aead = new ChaChaPolySsh();
        SshException ex = Assert.Throws<SshException>(() => aead.Init(new byte[32]));
        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
    }

    [Fact]
    public void Crypt_Encrypt_RejectsUndersizedDest()
    {
        var aead = new ChaChaPolySsh();
        aead.Init(Key());
        byte[] src = MakePlaintext();
        Assert.Throws<ArgumentException>(
            () => aead.Crypt(Seqnr, new byte[20], src, len: 20, aadlen: 4, encrypt: true));
    }

    [Fact]
    public void Crypt_Decrypt_RejectsUndersizedSrc()
    {
        var aead = new ChaChaPolySsh();
        aead.Init(Key());
        Assert.Throws<ArgumentException>(
            () => aead.Crypt(Seqnr, new byte[24], new byte[23], len: 20, aadlen: 4, encrypt: false));
    }

    [Fact]
    public void GetLength_RejectsShortCiphertext()
    {
        var aead = new ChaChaPolySsh();
        aead.Init(Key());
        Assert.Throws<SshException>(() => aead.GetLength(Seqnr, new byte[3]));
    }
}
