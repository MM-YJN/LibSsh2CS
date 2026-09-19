// Translated from libssh2 src/cipher-chachapoly.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Adapted by Will Cosgrove <will@panic.com> for libssh2
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibSsh2CS.Crypto;

/// <summary>
/// SSH's ChaCha20-Poly1305 AEAD — 1:1 port of libssh2
/// <c>cipher-chachapoly.c</c>. This is the <c>chacha20-poly1305@openssh.com</c>
/// packet construction, NOT the RFC 8439 single-key AEAD.
/// </summary>
/// <remarks>
/// <para>
/// <b>Construction</b> (PROTOCOL.chacha20poly1305): the 64-byte key is split into
/// a 32-byte main key and a 32-byte header key. Per packet (sequence number
/// <c>seqnr</c>, used as the 8-byte nonce):
/// <list type="number">
/// <item>The Poly1305 one-time key is ChaCha20(main, seqnr, counter=0) — the
/// first 32 bytes of keystream block 0.</item>
/// <item>The header key encrypts the 4-byte packet length (AAD) at counter 0.
/// This is what <see cref="GetLength"/> reverses.</item>
/// <item>The main key encrypts the payload (everything after the length) at
/// counter <b>1</b> (block 0 was consumed for the Poly1305 key).</item>
/// <item>The Poly1305 tag covers the (encrypted length ‖ encrypted payload);
/// on decrypt it is verified <b>before</b> the payload is decrypted.</item>
/// </list>
/// </para>
/// <para>
/// <b>Nonce byte order (the classic footgun).</b> <c>cipher-chachapoly.c</c>
/// builds the nonce via <c>_libssh2_store_u64</c>, which is <b>big-endian</b>
/// (network order); <c>chacha.c</c> then little-endian-loads it. So the nonce
/// span handed to <see cref="ChaCha20.IvSetup(ReadOnlySpan{byte})"/> is the <c>seqnr</c> as
/// 8 big-endian bytes, NOT little-endian. The block-1 counter, by contrast, is
/// <c>{1,0,0,0,0,0,0,0}</c> (little-endian 1). Both are reproduced exactly here.
/// </para>
/// <para>
/// libssh2 C functions replaced: <c>chachapoly_init</c> → <see cref="Init"/>,
/// <c>chachapoly_crypt</c> → <see cref="Crypt"/>,
/// <c>chachapoly_get_length</c> → <see cref="GetLength"/>. The
/// <c>chachapoly_timingsafe_bcmp</c> constant-time compare becomes
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </para>
/// </remarks>
internal sealed class ChaChaPolySsh
{
    /// <summary>Size of the split key (main ‖ header), in bytes.</summary>
    public const int KeySize = 64;

    /// <summary>Poly1305 tag size, in bytes.</summary>
    public const int TagSize = Poly1305.TagLength;

    // The block-1 counter as 8 little-endian bytes (cipher-chachapoly.c `one`).
    private static readonly byte[] s_counterOne = { 1, 0, 0, 0, 0, 0, 0, 0 };

    private readonly ChaCha20 _main = new();
    private readonly ChaCha20 _header = new();

    /// <summary>
    /// Sets up the main and header ChaCha20 contexts from a 64-byte key (first
    /// 32 = main, last 32 = header). Port of <c>chachapoly_init</c>.
    /// </summary>
    public void Init(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new SshException(
                SshErrorCode.Inval,
                "chacha20-poly1305@openssh.com requires a 64-byte (main‖header) key");
        }

        _main.KeySetup(key.Slice(0, 32));
        _header.KeySetup(key.Slice(32, 32));
    }

    /// <summary>
    /// Encrypts or decrypts one SSH packet. Port of <c>chachapoly_crypt</c>.
    /// On encrypt, <paramref name="dest"/> receives aadlen + len bytes of
    /// ciphertext followed by the 16-byte tag. On decrypt, the tag at
    /// <c>src[aadlen+len..]</c> is verified first; on mismatch a
    /// <see cref="SshException"/>(<see cref="SshErrorCode.Decrypt"/>) is
    /// thrown and <paramref name="dest"/> is left untouched.
    /// </summary>
    /// <param name="seqnr">The 32-bit packet sequence number; both the ChaCha20
    /// nonce and the Poly1305 key derivation derive from it.</param>
    /// <param name="dest">Output buffer. Encrypt: at least
    /// <c>aadlen + len + TagSize</c>. Decrypt: at least <c>aadlen + len</c>.</param>
    /// <param name="src">Input buffer. Encrypt: aadlen + len. Decrypt:
    /// aadlen + len + TagSize (ciphertext ‖ tag).</param>
    /// <param name="len">Payload length (bytes after the AAD).</param>
    /// <param name="aadlen">AAD length (the encrypted 4-byte packet length; may
    /// be 0 when the caller handles the length field separately).</param>
    /// <param name="encrypt"><c>true</c> = encrypt and append tag; <c>false</c> =
    /// verify tag then decrypt.</param>
    public void Crypt(uint seqnr, Span<byte> dest, ReadOnlySpan<byte> src, int len, int aadlen, bool encrypt)
    {
        unchecked
        {
            if (aadlen < 0 || len < 0)
            {
                throw new SshException(SshErrorCode.Inval, "negative length");
            }

            int needed = aadlen + len + (encrypt ? TagSize : 0);
            if (dest.Length < needed)
            {
                throw new ArgumentException("dest buffer too small", nameof(dest));
            }

            int srcNeeded = aadlen + len + (encrypt ? 0 : TagSize);
            if (src.Length < srcNeeded)
            {
                throw new ArgumentException("src buffer too small", nameof(src));
            }

            Span<byte> seqbuf = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(seqbuf, seqnr);

            // One-time Poly1305 key = ChaCha20(main, seqnr, counter=0), 32 bytes.
            // polyKey must be zeroed first (cipher-chachapoly.c memset) — stackalloc
            // is uninitialized, and EncryptBytes XORs the keystream into it.
            Span<byte> polyKey = stackalloc byte[Poly1305.KeyLength];
            polyKey.Clear();
            _main.IvSetup(seqbuf);
            _main.EncryptBytes(polyKey, polyKey);

            try
            {
                if (!encrypt)
                {
                    // Verify tag before decrypting (the SSH ordering).
                    Span<byte> expected = stackalloc byte[TagSize];
                    Poly1305.Auth(expected, src.Slice(0, aadlen + len), polyKey);
                    ReadOnlySpan<byte> actual = src.Slice(aadlen + len, TagSize);
                    if (!CryptographicOperations.FixedTimeEquals(expected, actual))
                    {
                        throw new SshException(
                            SshErrorCode.Decrypt,
                            "chacha20-poly1305@openssh.com authentication tag mismatch");
                    }
                }

                if (aadlen > 0)
                {
                    // Header key encrypts the length field (counter=0).
                    _header.IvSetup(seqbuf);
                    _header.EncryptBytes(src.Slice(0, aadlen), dest.Slice(0, aadlen));
                }

                // Main key encrypts the payload at counter=1 (block 0 → poly key).
                _main.IvSetup(seqbuf, s_counterOne);
                _main.EncryptBytes(src.Slice(aadlen, len), dest.Slice(aadlen, len));

                if (encrypt)
                {
                    Poly1305.Auth(dest.Slice(aadlen + len, TagSize), dest.Slice(0, aadlen + len), polyKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(polyKey);
            }
        }
    }

    /// <summary>
    /// Decrypts and returns the 4-byte encrypted packet length (the header-key
    /// AAD path). Port of <c>chachapoly_get_length</c>.
    /// </summary>
    public uint GetLength(uint seqnr, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < 4)
        {
            throw new SshException(SshErrorCode.Inval, "need 4 bytes of ciphertext length");
        }

        Span<byte> seqbuf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(seqbuf, seqnr);
        _header.IvSetup(seqbuf);

        Span<byte> buf = stackalloc byte[4];
        _header.EncryptBytes(ciphertext.Slice(0, 4), buf);
        return BinaryPrimitives.ReadUInt32BigEndian(buf);
    }
}
