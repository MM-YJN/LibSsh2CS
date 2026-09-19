using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// AES-{128,192,256}-CBC. Port of the <c>crypt_init</c>/<c>crypt_encrypt</c>
/// path over OpenSSL's AES-CBC. CBC chains across packets: the same
/// <see cref="Aes"/> instance is reused for every packet in a direction, and the
/// last ciphertext block of each packet becomes the next packet's IV — matching
/// libssh2's single persistent cipher context.
/// </summary>
/// <remarks>
/// Uses the span-based <see cref="SymmetricAlgorithm.TryEncryptCbc"/>/
/// <see cref="SymmetricAlgorithm.TryDecryptCbc"/> surface (no
/// <see cref="ICryptoTransform"/>, no <see cref="SymmetricAlgorithm.Key"/>/
/// <see cref="SymmetricAlgorithm.IV"/> array properties). The CBC IV carry is
/// tracked explicitly here because the span APIs are stateless per call (each
/// call takes the IV explicitly and does not chain), whereas the previous
/// <see cref="ICryptoTransform"/> path carried it internally.
/// </remarks>
internal sealed class AesCbcCipher : ICipher
{
    private readonly int _keyLen;
    private Aes? _aes;
    private byte[]? _key;
    private byte[]? _iv; // 16-byte CBC IV, persisted across packets.
    private bool _encrypt;

    public AesCbcCipher(int keyLen)
    {
        if (keyLen is not (16 or 24 or 32))
        {
            throw new ArgumentOutOfRangeException(nameof(keyLen));
        }

        _keyLen = keyLen;
    }

    public string Name => _keyLen switch
    {
        16 => "aes128-cbc",
        24 => "aes192-cbc",
        _ => "aes256-cbc",
    };

    public int BlockSize => 16;
    public int IvLen => 16;
    public int KeyLen => _keyLen;
    public int AuthTagLen => 0;
    public CipherFlags Flags => CipherFlags.None;

    [SuppressMessage("Security", "CA5401:Do not use cipher with non-default IV", Justification = "SSH CBC mandates the KDF-derived IV per RFC 4253 §6.2; a random/default IV would break the protocol.")]
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

        if (_key is null)
        {
            _key = new byte[_keyLen];
            _iv = new byte[16];
        }

        key.CopyTo(_key);
        iv.CopyTo(_iv);
        _encrypt = encrypt;

        _aes?.Dispose();
        _aes = Aes.Create();
        _aes.SetKey(_key);
        _aes.Mode = CipherMode.CBC;
        _aes.Padding = PaddingMode.None;
    }

    public void Crypt(Span<byte> data)
    {
        if (_aes is null || _key is null || _iv is null)
        {
            throw new InvalidOperationException("AesCbcCipher: Init not called");
        }

        if (data.Length == 0 || data.Length % 16 != 0)
        {
            throw new SshException(SshErrorCode.Inval, "CBC input must be a non-empty multiple of 16 bytes");
        }

        // TryEncryptCbc/TryDecryptCbc do not support overlapping input/output
        // (destination must be distinct from plaintext/ciphertext), so transform
        // into a scratch buffer then copy back. The last ciphertext block becomes
        // the IV for the next packet, preserving the CBC chain across calls.
        byte[]? rented = null;
        Span<byte> scratch = (data.Length <= 256) ? stackalloc byte[256] : (rented = ArrayPool<byte>.Shared.Rent(data.Length));
        try
        {
            Span<byte> output = scratch.Slice(0, data.Length);
            bool ok = _encrypt
                ? _aes.TryEncryptCbc(data, _iv, output, out int written, PaddingMode.None)
                : _aes.TryDecryptCbc(data, _iv, output, out written, PaddingMode.None);

            if (!ok || written != data.Length)
            {
                throw new CryptographicException($"{Name}: CBC transform failed (written={written}, len={data.Length})");
            }

            // Advance the persistent IV to the last ciphertext block (the chain carry).
            if (_encrypt)
            {
                output.Slice(output.Length - 16, 16).CopyTo(_iv);
            }
            else
            {
                // For decrypt the chain input is the last *ciphertext* block, i.e. the
                // last 16 bytes of the input, not the output.
                data.Slice(data.Length - 16, 16).CopyTo(_iv);
            }

            output.CopyTo(data);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scratch);
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
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

        if (_iv is not null)
        {
            CryptographicOperations.ZeroMemory(_iv);
        }

        _aes?.Dispose();
        _aes = null;
    }
}
