using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// AES-{128,192,256}-CTR. CTR is a stream cipher: keystream = AES(counter),
/// XORed with the plaintext. The counter persists across packets (each direction
/// keeps one), matching libssh2's persistent AES-CTR context. Decryption is
/// identical to encryption.
/// </summary>
/// <remarks>
/// Reuses the tested <see cref="AesCtrMode"/> primitive for the actual keystream
/// generation; this adapter owns only the persistent counter advancement.
/// </remarks>
internal sealed class AesCtrCipher : ICipher
{
    private readonly int _keyLen;
    private Aes? _aes;
    private byte[]? _key;
    private byte[]? _counter; // 16-byte big-endian, persistent across packets.

    public AesCtrCipher(int keyLen)
    {
        if (keyLen is not (16 or 24 or 32))
        {
            throw new ArgumentOutOfRangeException(nameof(keyLen));
        }

        _keyLen = keyLen;
    }

    public string Name => _keyLen switch
    {
        16 => "aes128-ctr",
        24 => "aes192-ctr",
        _ => "aes256-ctr",
    };

    public int BlockSize => 16;
    public int IvLen => 16;
    public int KeyLen => _keyLen;
    public int AuthTagLen => 0;
    public CipherFlags Flags => CipherFlags.None;

    [SuppressMessage("Security", "CA5358:Do not use cipher in ECB mode", Justification = "ECB is intentional here: CTR mode is constructed by encrypting the counter as a single 16-byte block. We never use ECB on multi-block data.")]
    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt)
    {
        if (key.Length != _keyLen)
        {
            throw new SshException(SshErrorCode.Inval, $"{Name}: key must be {_keyLen} bytes");
        }

        if (iv.Length != 16)
        {
            throw new SshException(SshErrorCode.Inval, $"{Name}: iv must be 16 bytes");
        }

        // CTR is symmetric (encrypt == decrypt); the encrypt parameter is ignored
        // by libssh2's CTR init too.
        _key ??= new byte[_keyLen];
        _counter ??= new byte[16];

        key.CopyTo(_key);
        iv.CopyTo(_counter);

        _aes?.Dispose();
        _aes = Aes.Create();
        _aes.SetKey(_key);
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
    }

    public void Crypt(Span<byte> data)
    {
        if (_aes is null || _key is null || _counter is null)
        {
            throw new InvalidOperationException("AesCtrCipher: Init not called");
        }

        // TransformInPlace XORs the keystream into data in place AND advances
        // _counter in place — no AddBe16 needed (the old code advanced _counter
        // separately because AesCtrMode.Transform used an internal counter copy).
        AesCtrMode.TransformInPlace(data, _aes, _counter);
    }

    public void CryptAead(uint seqno, Span<byte> dest, ReadOnlySpan<byte> src, int payloadLen, int aadLen, bool encrypt)
        => throw new NotSupportedException($"{Name} is not an AEAD cipher");

    public bool TryGetLength(uint seqno, ReadOnlySpan<byte> ciphertext, out uint length)
    {
        length = 0;
        return false;
    }

    public void Dispose()
    {
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
        }

        if (_counter is not null)
        {
            CryptographicOperations.ZeroMemory(_counter);
        }

        _aes?.Dispose();
        _aes = null;
    }
}
