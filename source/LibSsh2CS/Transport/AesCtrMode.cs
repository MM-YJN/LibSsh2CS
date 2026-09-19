using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// AES in CTR (counter) mode. Implemented manually because the .NET BCL
/// (<c>System.Security.Cryptography.Aes</c>) only exposes CBC and ECB cipher
/// modes — CTR is not a <c>CipherMode</c> enum member.
/// </summary>
/// <remarks>
/// <para>
/// CTR mode turns a block cipher into a stream cipher: a monotonically
/// increasing counter is encrypted to produce a keystream, which is XORed
/// with the plaintext. Decryption is identical to encryption.
/// </para>
/// <para>
/// Required for SSH (RFC 4253 §6.3 — AES-CTR is the mandatory cipher) and for
/// OpenSSH-format encrypted private keys (default cipher is
/// <c>aes256-ctr</c>). The counter is treated as a 128-bit big-endian integer
/// and incremented by 1 per block, matching OpenSSH / OpenSSL behavior.
/// </para>
/// <para>
/// Implemented over BCL <see cref="Aes"/> in ECB mode (encrypting one block at
/// a time). This is the standard CTR construction.
/// </para>
/// </remarks>
internal static class AesCtrMode
{
    /// <summary>The AES block size in bytes (always 16).</summary>
    public const int BlockSize = 16;

    /// <summary>
    /// Encrypts or decrypts (identical in CTR mode) <paramref name="input"/>
    /// using the given 128/192/256-bit key and 128-bit initial counter.
    /// </summary>
    /// <param name="input">The plaintext or ciphertext (in-place not supported; output is a new array).</param>
    /// <param name="key">The AES key (16, 24, or 32 bytes).</param>
    /// <param name="initialCounter">The 16-byte initial counter / IV.</param>
    /// <returns>The output bytes (same length as <paramref name="input"/>).</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown if key length is not 16/24/32 bytes or IV length is not 16 bytes.
    /// </exception>
    [SuppressMessage("Security", "CA5358:Do not use cipher in ECB mode", Justification = "ECB is intentional here: CTR mode is constructed by encrypting the counter as a single block. We never actually use ECB on multi-block data; each call encrypts exactly one 16-byte block.")]
    public static byte[] Transform(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> initialCounter)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentOutOfRangeException(nameof(key), "AES key must be 16, 24, or 32 bytes");
        }

        if (initialCounter.Length != BlockSize)
        {
            throw new ArgumentOutOfRangeException(nameof(initialCounter), "Initial counter must be 16 bytes");
        }

        byte[] output = new byte[input.Length];
        input.CopyTo(output);

        using var aes = Aes.Create();
        aes.SetKey(key); // span — no key.ToArray()
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        // TransformInPlace advances the counter in place, so use a local copy.
        byte[] counter = initialCounter.ToArray();
        try
        {
            TransformInPlace(output, aes, counter);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }

        return output;
    }

    /// <summary>
    /// In-place AES-CTR transform (encrypt == decrypt). Zero-allocations: the
    /// keystream block lives on the stack. The <paramref name="aes"/> instance must
    /// already be keyed (via <see cref="SymmetricAlgorithm.SetKey"/>) and set to
    /// ECB/None; the caller owns its lifecycle. <paramref name="counter"/> is
    /// advanced in place by one per keystream block consumed (a trailing partial
    /// block still consumes a full block, matching OpenSSL's CTR behavior).
    /// </summary>
    /// <param name="data">Transformed in place (CTR XOR is safe in-place).</param>
    /// <param name="aes">Pre-keyed AES instance in ECB mode. Not disposed here.</param>
    /// <param name="counter">16-byte big-endian counter; mutated in place.</param>
    [SuppressMessage("Security", "CA5358:Do not use cipher in ECB mode", Justification = "ECB is intentional here: CTR mode is constructed by encrypting the counter as a single 16-byte block. We never use ECB on multi-block data.")]
    public static void TransformInPlace(Span<byte> data, Aes aes, Span<byte> counter)
    {
        if (counter.Length != BlockSize)
        {
            throw new ArgumentOutOfRangeException(nameof(counter), "Counter must be 16 bytes");
        }

        // CTR is a stream cipher: no block-alignment requirement, no minimum length.
        if (data.Length == 0)
        {
            return;
        }

        Span<byte> keystream = stackalloc byte[BlockSize];

        int offset = 0;
        while (offset < data.Length)
        {
            // Keystream block = AES_ECB(counter). Note: TryEncryptEcb puts
            // PaddingMode BEFORE the out parameter (unlike TryEncryptCbc).
            if (!aes.TryEncryptEcb(counter, keystream, PaddingMode.None, out int written) || written != BlockSize)
            {
                throw new CryptographicException($"AES-CTR: ECB keystream block failed (written={written})");
            }

            // XOR keystream into data in place. CTR is a stream cipher, so in-place
            // XOR is safe (unlike CBC, which needs a separate output buffer).
            int chunk = Math.Min(BlockSize, data.Length - offset);
            for (int i = 0; i < chunk; i++)
            {
                data[offset + i] ^= keystream[i];
            }

            offset += chunk;

            // Advance the 128-bit big-endian counter by 1 (mutates the caller's span).
            IncrementBE(counter);
        }

        // Zero the keystream so it doesn't linger on the stack.
        CryptographicOperations.ZeroMemory(keystream);
    }

    /// <summary>Increments a 16-byte big-endian counter in place by 1.</summary>
    private static void IncrementBE(Span<byte> counter)
    {
        for (int i = BlockSize - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                return;
            }
        }
    }
}
