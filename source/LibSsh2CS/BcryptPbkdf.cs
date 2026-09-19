// Translated from libssh2 src/bcrypt_pbkdf.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * Copyright (C) Ted Unangst <tedu@openbsd.org>
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
 * SPDX-License-Identifier: MIT
 */

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibSsh2CS;

/// <summary>
/// Managed 1:1 port of <c>bcrypt_pbkdf.c</c> from libssh2 1.11.1_DEV.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#5 PBKDF2 implementation using the "bcrypt" hash. The bcrypt hash
/// function is derived from the bcrypt password hashing function with the
/// following modifications (quoted from the C source):
/// </para>
/// <para>
/// 1. The input password and salt are preprocessed with SHA512.<br/>
/// 2. The output length is expanded to 256 bits.<br/>
/// 3. Subsequently the magic string to be encrypted is lengthened and modified
///    to "OxychromaticBlowfishSwatDynamite".<br/>
/// 4. The hash function is defined to perform 64 rounds of initial state
///    expansion.
/// </para>
/// <para>
/// One modification from official pbkdf2: instead of outputting key material
/// linearly, output bytes are mixed (non-linear stride) so an attacker must
/// compute the entirety of the key material to assemble any subkey.
/// </para>
/// <para>
/// <b>Source:</b> <c>~/repo/libssh2/src/bcrypt_pbkdf.c</c> lines 1–210.
/// Depends on <see cref="BlowfishContext"/> (the C source includes blowfish.c
/// source-level at line 27).
/// </para>
/// <para>
/// The SHA-512 operations use BCL <see cref="SHA512.HashData(byte[])"/> instead
/// of libssh2's <c>libssh2_sha512_*</c> backend wrappers. Explicit-zero
/// operations use <see cref="CryptographicOperations.ZeroMemory"/> instead of
/// libssh2's <c>_libssh2_explicit_zero</c>.
/// </para>
/// <para>
/// <b>License:</b> MIT (Ted Unangst / OpenBSD).
/// </para>
/// </remarks>
internal static class BcryptPbkdf
{
    /// <summary>BCRYPT_BLOCKS = 8 (8 × uint32 = 32 bytes).</summary>
    private const int BcryptBlocks = 8;

    /// <summary>Output size of one bcrypt_hash invocation = BCRYPT_BLOCKS × 4 = 32 bytes.</summary>
    private const int BcryptHashSize = BcryptBlocks * 4;

    /// <summary>SHA-512 digest length in bytes.</summary>
    private const int Sha512DigestLength = 64;

    /// <summary>
    /// bcrypt PBKDF2 key derivation. Ported 1:1 from <c>bcrypt_pbkdf()</c>.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="rounds">Number of rounds (must be ≥ 1).</param>
    /// <param name="keyLength">Desired output key length in bytes (must be > 0).</param>
    /// <returns>The derived key bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown if <paramref name="rounds"/> &lt; 1, or any input length is zero,
    /// or <paramref name="keyLength"/> exceeds 32 × 32 bytes, or salt exceeds
    /// 1 MB. Matches the C function's <c>-1</c> return conditions.
    /// </exception>
    public static byte[] Derive(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, uint rounds, int keyLength)
    {
        // Validate (mirrors the C function's early-return conditions).
        if (rounds < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(rounds), "rounds must be >= 1");
        }

        if (password.Length == 0 || salt.Length == 0 || keyLength == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(keyLength), "pass, salt, and key length must be > 0");
        }

        if (keyLength > BcryptHashSize * BcryptHashSize)
        {
            throw new ArgumentOutOfRangeException(nameof(keyLength), "key length exceeds maximum");
        }

        if (salt.Length > 1 << 20)
        {
            throw new ArgumentOutOfRangeException(nameof(salt), "salt exceeds 1MB");
        }

        byte[] key = new byte[keyLength];
        int origKeyLen = keyLength;

        // countsalt = salt || count (4 bytes big-endian)
        byte[] countsalt = new byte[salt.Length + 4];
        salt.CopyTo(countsalt);

        int stride = (keyLength + BcryptHashSize - 1) / BcryptHashSize;
        int amt = (keyLength + stride - 1) / stride;

        // Collapse password: sha2pass = SHA512(password)
        byte[] sha2pass = SHA512.HashData(password);

        byte[] sha2salt = new byte[Sha512DigestLength];
        byte[] outs = new byte[BcryptHashSize];
        byte[] tmpout = new byte[BcryptHashSize];

        // Generate key material, BcryptHashSize bytes at a time.
        for (uint count = 1; keyLength > 0; count++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(countsalt.AsSpan(salt.Length, 4), count);

            // First round: salt is the count-augmented salt.
            SHA512.HashData(countsalt, sha2salt.AsSpan());

            BcryptHash(sha2pass, sha2salt, tmpout);
            Array.Copy(tmpout, outs, BcryptHashSize);

            for (uint i = 1u; i < rounds; i++)
            {
                // Subsequent rounds: salt is the previous output.
                SHA512.HashData(tmpout, sha2salt.AsSpan());

                BcryptHash(sha2pass, sha2salt, tmpout);
                for (int j = 0; j < BcryptHashSize; j++)
                {
                    outs[j] ^= tmpout[j];
                }
            }

            // pbkdf2 deviation: output non-linearly.
            if (amt > keyLength)
            {
                amt = keyLength;
            }

            int written;
            for (written = 0; written < amt; written++)
            {
                int dest = written * stride + (int)(count - 1);
                if (dest >= origKeyLen)
                {
                    break;
                }

                key[dest] = outs[written];
            }

            keyLength -= written;
        }

        // Zap sensitive state.
        CryptographicOperations.ZeroMemory(sha2pass);
        CryptographicOperations.ZeroMemory(sha2salt);
        CryptographicOperations.ZeroMemory(outs);
        CryptographicOperations.ZeroMemory(tmpout);
        CryptographicOperations.ZeroMemory(countsalt);

        return key;
    }

    /// <summary>
    /// The bcrypt hash function. Ported 1:1 from <c>bcrypt_hash()</c>.
    /// Operates on pre-hashed (SHA-512) inputs and produces a 32-byte output.
    /// </summary>
    [SuppressMessage("Performance", "IDE0230:Use UTF-8 string literal", Justification = "Magic plaintext constructed from char literals (not a UTF-8 string literal) to mirror the C source's uint8_t[] initializer byte-for-byte; the byte-array form is deliberate for parity with blowfish.c.")]
    private static void BcryptHash(byte[] sha2pass, byte[] sha2salt, byte[] outs)
    {
        var state = new BlowfishContext();

        // Magic plaintext: "OxychromaticBlowfishSwatDynamite" (32 bytes).
        // Constructed from char literals (not a UTF-8 string literal) to mirror
        // the C source's uint8_t[] initializer byte-for-byte. IDE0230 (UTF-8
        // string literal) is suppressed because the byte-array form is
        // deliberate for parity with blowfish.c.
        byte[] ciphertext = new byte[BcryptHashSize]
        {
            (byte)'O', (byte)'x', (byte)'y', (byte)'c', (byte)'h', (byte)'r', (byte)'o', (byte)'m',
            (byte)'a', (byte)'t', (byte)'i', (byte)'c', (byte)'B', (byte)'l', (byte)'o', (byte)'w',
            (byte)'f', (byte)'i', (byte)'s', (byte)'h', (byte)'S', (byte)'w', (byte)'a', (byte)'t',
            (byte)'D', (byte)'y', (byte)'n', (byte)'a', (byte)'m', (byte)'i', (byte)'t', (byte)'e',
        };

        uint[] cdata = new uint[BcryptBlocks];

        // Key expansion.
        state.InitState();
        state.ExpandState(sha2salt, Sha512DigestLength, sha2pass, Sha512DigestLength);
        for (int i = 0; i < 64; i++)
        {
            state.Expand0State(sha2salt, Sha512DigestLength);
            state.Expand0State(sha2pass, Sha512DigestLength);
        }

        // Encryption: stream ciphertext into uint32 words, then 64 rounds of blf_enc.
        int j = 0;
        for (int i = 0; i < BcryptBlocks; i++)
        {
            cdata[i] = BlowfishContext.Stream2Word(ciphertext, ciphertext.Length, ref j);
        }

        for (int i = 0; i < 64; i++)
        {
            state.BlfEnc(cdata, 0, BcryptBlocks / 2);
        }

        // Copy out — note the byte-swap (big-endian uint32 → little-endian byte layout).
        // This is a deliberate choice of the original bcrypt_pbkdf code, not a bug.
        for (int i = 0; i < BcryptBlocks; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(outs.AsSpan(4 * i, 4), cdata[i]);
        }

        // Zap.
        CryptographicOperations.ZeroMemory(ciphertext);
        Array.Clear(cdata, 0, cdata.Length);
    }
}
