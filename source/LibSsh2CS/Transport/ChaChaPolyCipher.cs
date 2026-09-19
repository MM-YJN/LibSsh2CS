using LibSsh2CS.Crypto;

namespace LibSsh2CS.Transport;

/// <summary>
/// ChaCha20-Poly1305 (<c>chacha20-poly1305@openssh.com</c>). A thin
/// <see cref="ICipher"/> wrapper over the already-ported SSH two-key AEAD
/// (<see cref="ChaChaPolySsh"/>): the 64-byte key is main‖header, the sequence
/// number is the nonce, and the length field is recovered via the header key.
/// </summary>
internal sealed class ChaChaPolyCipher : ICipher
{
    private readonly ChaChaPolySsh _aead = new();

    public string Name => "chacha20-poly1305@openssh.com";
    public int BlockSize => 8;
    public int IvLen => 0;
    public int KeyLen => ChaChaPolySsh.KeySize;
    public int AuthTagLen => ChaChaPolySsh.TagSize;
    public CipherFlags Flags => CipherFlags.RequiresFullPacket;

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt)
    {
        _aead.Init(key);
    }

    public void Crypt(Span<byte> data) => throw new NotSupportedException($"{Name} is an AEAD cipher; use CryptAead");

    public void CryptAead(uint seqno, Span<byte> dest, ReadOnlySpan<byte> src, int payloadLen, int aadLen, bool encrypt)
    {
        _aead.Crypt(seqno, dest, src, payloadLen, aadLen, encrypt);
    }

    public bool TryGetLength(uint seqno, ReadOnlySpan<byte> ciphertext, out uint length)
    {
        if (ciphertext.Length < 4)
        {
            length = 0;
            return false;
        }

        length = _aead.GetLength(seqno, ciphertext.Slice(0, 4));
        return true;
    }

    public void Dispose()
    {
    }
}
