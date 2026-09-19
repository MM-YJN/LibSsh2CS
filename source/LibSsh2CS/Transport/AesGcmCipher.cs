using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// AES-{128,256}-GCM (<c>aes{128,256}-gcm@openssh.com</c>, RFC 5647). The 12-byte
/// IV from key derivation is split into a 4-byte fixed prefix and an 8-byte
/// invocation counter, exactly as OpenSSL's <c>EVP_CTRL_AEAD_SET_IV_FIXED</c> +
/// <c>EVP_CTRL_GCM_IV_GEN</c> do (<c>openssl.c:1002-1058</c>): the nonce per
/// packet is <c>fixed[0..4] ‖ BE64(initial_counter)</c> and the invocation
/// counter increments per packet. The 4-byte packet length is authenticated
/// associated data (not encrypted).
/// </summary>
internal sealed class AesGcmCipher : ICipher
{
    private readonly int _keyLen;
    private AesGcm? _gcm;
    private byte[]? _key;
    private readonly byte[] _fixedPrefix = new byte[4]; // iv[0..4]
    private ulong _invocationCounter;          // BE64(iv[4..12])

    public AesGcmCipher(int keyLen)
    {
        if (keyLen is not (16 or 32))
        {
            throw new ArgumentOutOfRangeException(nameof(keyLen));
        }

        _keyLen = keyLen;
    }

    public string Name => _keyLen == 16 ? "aes128-gcm@openssh.com" : "aes256-gcm@openssh.com";
    public int BlockSize => 16;
    public int IvLen => 12;
    public int KeyLen => _keyLen;
    public int AuthTagLen => 16;
    public CipherFlags Flags => CipherFlags.IntegratedMac | CipherFlags.PktLenAad;

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt)
    {
        if (key.Length != _keyLen)
        {
            throw new SshException(SshErrorCode.Inval, $"{Name}: key must be {_keyLen} bytes");
        }

        if (iv.Length != 12)
        {
            throw new SshException(SshErrorCode.Inval, $"{Name}: iv must be 12 bytes");
        }

        _key = key.ToArray();
        iv.Slice(0, 4).CopyTo(_fixedPrefix);
        _invocationCounter = BinaryPrimitives.ReadUInt64BigEndian(iv.Slice(4, 8));
        _gcm?.Dispose();
        _gcm = new AesGcm(_key, 16);
    }

    public void Crypt(Span<byte> data) => throw new NotSupportedException($"{Name} is an AEAD cipher; use CryptAead");

    public void CryptAead(uint seqno, Span<byte> dest, ReadOnlySpan<byte> src, int payloadLen, int aadLen, bool encrypt)
    {
        if (_gcm is null)
        {
            throw new InvalidOperationException("AesGcmCipher: Init not called");
        }

        if (aadLen < 0 || payloadLen < 0)
        {
            throw new SshException(SshErrorCode.Inval, "negative length");
        }

        int encNeeded = aadLen + payloadLen + (encrypt ? AuthTagLen : 0);
        int decNeeded = aadLen + payloadLen + (encrypt ? 0 : AuthTagLen);
        if (dest.Length < encNeeded || src.Length < decNeeded)
        {
            throw new ArgumentException("AES-GCM buffer too small");
        }

        // nonce = fixed[0..4] ‖ BE64(invocation counter)
        Span<byte> nonce = stackalloc byte[12];
        _fixedPrefix.AsSpan().CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(4), _invocationCounter);

        // The 4-byte length (AAD) passes through unchanged (authenticated, not encrypted).
        src.Slice(0, aadLen).CopyTo(dest.Slice(0, aadLen));

        ReadOnlySpan<byte> aad = src.Slice(0, aadLen);
        try
        {
            if (encrypt)
            {
                _gcm.Encrypt(
                    nonce,
                    src.Slice(aadLen, payloadLen),
                    dest.Slice(aadLen, payloadLen),
                    dest.Slice(aadLen + payloadLen, AuthTagLen),
                    aad);
            }
            else
            {
                _gcm.Decrypt(
                    nonce,
                    src.Slice(aadLen, payloadLen),
                    src.Slice(aadLen + payloadLen, AuthTagLen),
                    dest.Slice(aadLen, payloadLen),
                    aad);
            }
        }
        catch (CryptographicException)
        {
            throw new SshException(SshErrorCode.Decrypt, $"{Name} authentication tag mismatch");
        }

        unchecked
        {
            _invocationCounter++;
        }
    }

    public bool TryGetLength(uint seqno, ReadOnlySpan<byte> ciphertext, out uint length)
    {
        if (ciphertext.Length < 4)
        {
            length = 0;
            return false;
        }

        // The length is plaintext AAD for AES-GCM.
        length = BinaryPrimitives.ReadUInt32BigEndian(ciphertext.Slice(0, 4));
        return true;
    }

    public void Dispose()
    {
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
        }

        _gcm?.Dispose();
        _gcm = null;
    }
}
