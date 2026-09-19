// Contains code translated from libsodium Ed25519 ref10.
// See THIRD-PARTY-NOTICES.md for provenance and LICENSE for project terms.
/*
 * ISC License
 *
 * Copyright (c) 2013-2026
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
 */

using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace LibSsh2CS.Crypto;

/// <summary>
/// Ed25519 (RFC 8032) signature verification and signing on the twisted Edwards
/// curve edwards25519. Used for <c>ssh-ed25519</c> host-key verification
/// and Ed25519-based publickey userauth.
/// </summary>
/// <remarks>
/// <para>
/// Both <see cref="Verify(byte[], byte[], byte[])"/> and <see cref="Sign(byte[], byte[])"/>
/// are <b>constant-time</b>: the field arithmetic (<see cref="Fe25519Ops"/>), the
/// point operations (<see cref="Ge25519Ops"/>), the scalar multiplication
/// (<see cref="Ge25519ScalarMult"/>), and the mod-L arithmetic
/// (<see cref="ScalarModL"/>) are all branchless on secret data. The
/// long-term private scalar in <see cref="Sign"/> no longer leaks through
/// field-arithmetic timing.
/// </para>
/// <para>
/// libssh2 delegates Ed25519 to its crypto backend (OpenSSL
/// <c>EVP_DigestVerify</c> / <c>EVP_DigestSign</c>); there is no vendored
/// ed25519 in libssh2. This is ported from RFC 8032.
/// Verify checks the unbatched equation <c>[S]B = R + [h]A</c> (RFC 8032 §5.1.7:
/// "sufficient, but not required") — the same check the Python reference uses,
/// which passes all RFC §7.1 vectors. Verification also requires canonical A and R
/// encodings, rejects points with [8]P = identity, and requires S &lt; L. These
/// rules do not assert full prime-subgroup membership or full libsodium equivalence.
/// </para>
/// <para>
/// libssh2 C functions replaced: <c>hostkey_method_ssh_ed25519_sig_verify</c>
/// (hostkey.c ~1251) and <c>_libssh2_ed25519_verify</c> (openssl.c ~4504) both
/// collapse to <see cref="Verify(byte[], byte[], byte[])"/>. Signature-blob
/// parsing (skip the <c>ssh-ed25519</c> type prefix) is done by the caller
/// (<c>Transport/HostKeyVerifier.cs</c>). The sign path replaces
/// <c>_libssh2_ed25519_sign</c> (openssl.c ~4380), which delegates to OpenSSL
/// <c>EVP_DigestSign</c>; we implement RFC 8032 §5.1.5 directly.
/// </para>
/// </remarks>
internal static class Ed25519
{
    /// <summary>
    /// The Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
    /// (RFC 8032 §5.1, Table 1). Used to range-check the scalar S and to encode
    /// L as a 32-byte little-endian value for constant-time byte comparison.
    /// </summary>
    public static readonly BigInteger L = BigInteger.Pow(2, 252)
        + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);

    /// <summary>
    /// L in its canonical 32-byte little-endian encoding, used for constant-time
    /// range check of the scalar S in <see cref="Verify(byte[], byte[], byte[])"/>.
    /// Matches libsodium's <c>sc25519_is_canonical</c> table at
    /// <c>ed25519_ref10.c:2517</c>.
    /// </summary>
    private static readonly byte[] s_lBytes =
    {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };

    /// <summary>
    /// Verifies an Ed25519 signature (RFC 8032 §5.1.7).
    /// </summary>
    /// <param name="publicKey">The 32-byte encoded public key A.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="signature">The 64-byte signature (R ‖ S).</param>
    /// <returns><c>true</c> if the signature is valid.</returns>
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64)
        {
            return false;
        }

        // Step 1: decode A and R. Both must be valid curve points.
        if (Ge25519Ops.FromBytes(out GeP3 a, publicKey) != 0)
        {
            return false;
        }

        if (Ge25519Ops.FromBytes(out GeP3 r, signature.AsSpan(0, 32).ToArray()) != 0)
        {
            return false;
        }

        // Verification requires canonical encodings and excludes points of order dividing 8.
        // This does not impose a full prime-subgroup membership check.
        byte[] encoded = new byte[32];
        Ge25519Ops.P3ToBytes(encoded, in a);
        if (!CryptographicOperations.FixedTimeEquals(encoded, publicKey) || IsSmallOrder(in a))
        {
            return false;
        }

        Ge25519Ops.P3ToBytes(encoded, in r);
        if (!CryptographicOperations.FixedTimeEquals(encoded, signature.AsSpan(0, 32)) || IsSmallOrder(in r))
        {
            return false;
        }

        // Step 2: range-check S < L (RFC 8032 §5.1.7 step 1). Constant-time
        // byte compare; rejects S ≥ L without leaking which check failed.
        byte[] sBytes = signature.AsSpan(32, 32).ToArray();
        if (!IsBelowL(sBytes))
        {
            return false;
        }

        // Step 3: k = SHA-512(R ‖ A ‖ M) interpreted little-endian, reduced mod L.
        byte[] kBytes = Sha512ModL(signature.AsSpan(0, 32).ToArray(), publicKey, message);

        // Step 4: compute [S]B and R + [k]A. The unbatched verification equation
        // is [S]B == R + [k]A. We compute both sides independently and compare
        // encodings.
        Ge25519ScalarMult.Base(out GeP3 sB, sBytes);
        Ge25519ScalarMult.ScalarMult(out GeP3 kA, kBytes, in a);

        // R + [k]A: convert kA to cached form, add R, then convert to projective P2.
        Ge25519Ops.P3ToCached(out GeCached kACached, in kA);
        Ge25519Ops.Add(out GeP1P1 rhsP1P1, in r, in kACached);

        // Compare encodings.
        Ge25519Ops.P3ToP2(out GeP2 sBP2, in sB);
        Ge25519Ops.P1P1ToP2(out GeP2 rhsP2, in rhsP1P1);

        byte[] lhsEnc = new byte[32];
        Ge25519Ops.P2ToBytes(lhsEnc, in sBP2);

        byte[] rhsEnc = new byte[32];
        Ge25519Ops.P2ToBytes(rhsEnc, in rhsP2);

        return CryptographicOperations.FixedTimeEquals(lhsEnc, rhsEnc);
    }

    /// <summary>Returns whether [8]P is the identity (order dividing the cofactor).</summary>
    internal static bool IsSmallOrder(in GeP3 point)
    {
        GeP3 multiple = point;
        for (int i = 0; i < 3; i++)
        {
            Ge25519Ops.P3Dbl(out GeP1P1 doubled, in multiple);
            Ge25519Ops.P1P1ToP3(out multiple, in doubled);
        }

        byte[] encoded = new byte[32];
        Ge25519Ops.P3ToBytes(encoded, in multiple);
        byte[] identity = new byte[32];
        identity[0] = 1;
        return CryptographicOperations.FixedTimeEquals(encoded, identity);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Sign (RFC 8032 §5.1.5) — used for publickey userauth.
    // Uses Fe/Ge/ScalarModL for constant-time operation on the
    // long-term private scalar.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Signs <paramref name="message"/> with the Ed25519 private key seed
    /// and returns the 64-byte signature <c>R ‖ S</c>. Port of RFC 8032 §5.1.5.
    /// </summary>
    /// <param name="seed">The 32-byte Ed25519 private key seed (the first half
    /// of the OpenSSH-format Ed25519 private key blob — the second half is the
    /// public key copy).</param>
    /// <param name="message">The message to sign. For SSH publickey auth this is
    /// <c>session_id ‖ USERAUTH_REQUEST</c>.</param>
    /// <returns>A 64-byte signature: <c>R (32 bytes LE) ‖ S (32 bytes LE)</c>.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="seed"/> is
    /// not exactly 32 bytes.</exception>
    public static byte[] Sign(byte[] seed, byte[] message)
    {
        if (seed.Length != 32)
        {
            throw new ArgumentException("Ed25519 seed must be 32 bytes", nameof(seed));
        }

        // Step 1: h = SHA-512(seed) → 64 bytes.
        byte[] h = SHA512.HashData(seed);

        // Step 2: a = clamp(h[0..32]). The clamped scalar is the long-term private
        // key; all subsequent operations on it must be constant-time.
        byte[] scalarBytes = h.AsSpan(0, 32).ToArray();
        scalarBytes[0] &= 0b1111_1000;
        scalarBytes[31] &= 0b0111_1111;
        scalarBytes[31] |= 0b0100_0000;

        // Step 3: prefix = h[32..64] (used to derive r per message).
        byte[] prefix = h.AsSpan(32, 32).ToArray();

        // Step 4: A = encode(a * B). Computed via the constant-time fixed-base
        // scalar mult; A is part of the SHA-512 input for k derivation below.
        byte[] A = PublicKeyFromScalar(scalarBytes);

        // Step 5: r = SHA-512(prefix ‖ message) interpreted little-endian, reduced mod L.
        byte[] rBytes = HashModL(prefix, message);

        // Step 6: R = encode(r * B).
        Ge25519ScalarMult.Base(out GeP3 rB, rBytes);
        byte[] R = new byte[32];
        Ge25519Ops.P3ToBytes(R, in rB);

        // Step 7: k = SHA-512(R ‖ A ‖ message) reduced mod L.
        byte[] kBytes = Sha512ModL(R, A, message);

        // Step 8: S = (r + a * k) mod L. Computed via the constant-time ScalarModL.MulAdd,
        // which evaluates (a * k + r) mod L without leaking the value of a.
        byte[] S = ScalarModL.MulAdd(scalarBytes, kBytes, rBytes);

        // Output: R (32 LE) ‖ S (32 LE).
        byte[] sig = new byte[64];
        Buffer.BlockCopy(R, 0, sig, 0, 32);
        Buffer.BlockCopy(S, 0, sig, 32, 32);

        CryptographicOperations.ZeroMemory(h);
        CryptographicOperations.ZeroMemory(scalarBytes);
        CryptographicOperations.ZeroMemory(prefix);
        CryptographicOperations.ZeroMemory(rBytes);
        return sig;
    }

    /// <summary>
    /// Derives the 32-byte Ed25519 public key A = encode(a·B) from the
    /// 32-byte private key seed (RFC 8032 §5.1.5 steps 1-2, 4). Used to
    /// rebuild OpenSSH-format blobs from legacy PKCS#8 Ed25519 keys — the
    /// equivalent of OpenSSL's <c>EVP_PKEY_get_raw_public_key</c> on a key
    /// loaded from PEM (openssl.c:2196-2210).
    /// </summary>
    public static byte[] GetPublicKey(byte[] seed)
    {
        if (seed.Length != 32)
        {
            throw new ArgumentException("Ed25519 seed must be 32 bytes", nameof(seed));
        }

        // h = SHA-512(seed); a = clamp(h[0..32]).
        byte[] h = SHA512.HashData(seed);
        byte[] scalarBytes = h.AsSpan(0, 32).ToArray();
        scalarBytes[0] &= 0b1111_1000;
        scalarBytes[31] &= 0b0111_1111;
        scalarBytes[31] |= 0b0100_0000;
        CryptographicOperations.ZeroMemory(h);

        try
        {
            return PublicKeyFromScalar(scalarBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalarBytes);
        }
    }

    /// <summary>encode(a·B) for a clamped private scalar (RFC 8032 §5.1.5 step 4).</summary>
    private static byte[] PublicKeyFromScalar(byte[] scalarBytes)
    {
        Ge25519ScalarMult.Base(out GeP3 aB, scalarBytes);
        byte[] A = new byte[32];
        Ge25519Ops.P3ToBytes(A, in aB);
        return A;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Drops the T coordinate of a GeP3 to produce a GeP2 view of the same
    /// point. Inline wrapper around <see cref="Ge25519Ops.P3ToP2"/> so the
    /// verify path reads more like the math equation <c>[S]B == R + [k]A</c>.
    /// </summary>
    private static void ToP2(out GeP2 r, in GeP3 p) => Ge25519Ops.P3ToP2(out r, in p);

    /// <summary>
    /// Computes <c>SHA-512(prefix ‖ message)</c> interpreted little-endian and
    /// reduced mod L. Used by <see cref="Sign"/> step 5 (<c>r</c> derivation).
    /// Mirrors <see cref="Sha512ModL(byte[], byte[], byte[])"/> but with a
    /// single prefix+message input instead of <c>R ‖ A ‖ M</c>.
    /// </summary>
    private static byte[] HashModL(byte[] prefix, byte[] message)
    {
        int len = prefix.Length + message.Length;
        byte[] buf = new byte[len];
        prefix.AsSpan().CopyTo(buf);
        message.AsSpan().CopyTo(buf.AsSpan(prefix.Length));

        byte[] hash = SHA512.HashData(buf);
        CryptographicOperations.ZeroMemory(buf);
        return ScalarModL.Reduce(hash);
    }

    /// <summary>
    /// Computes <c>SHA-512(r ‖ a ‖ message)</c> interpreted little-endian and
    /// reduced mod L (RFC 8032 §5.1.7 step 2; the <c>sha512_modq</c> of the
    /// Python reference). Used by <see cref="Verify"/> (k) and <see cref="Sign"/>
    /// step 7 (k).
    /// </summary>
    private static byte[] Sha512ModL(byte[] r, byte[] a, byte[] message)
    {
        int len = r.Length + a.Length + message.Length;
        byte[] buf = new byte[len];
        r.AsSpan().CopyTo(buf);
        a.AsSpan().CopyTo(buf.AsSpan(r.Length));
        message.AsSpan().CopyTo(buf.AsSpan(r.Length + a.Length));

        byte[] hash = SHA512.HashData(buf);
        return ScalarModL.Reduce(hash);
    }

    /// <summary>
    /// Constant-time less-than comparison of a 32-byte little-endian scalar
    /// against L. Returns true iff <c>s &lt; L</c>. Port of libsodium's
    /// <c>sc25519_is_canonical</c> (<c>ed25519_ref10.c:2513-2533</c>) — slightly
    /// adapted (we want strictly-less, libsodium wants not-canonical = ≥).
    /// </summary>
    private static bool IsBelowL(byte[] s)
    {
        // Walk from the most-significant byte (index 31) down. c tracks "we've
        // seen a byte where s < L" (so the overall value is < L). n tracks "all
        // bytes so far have been equal" — once we hit a difference, n goes to 0
        // and stays there.
        byte c = 0;
        byte n = 1;
        for (int i = 31; i >= 0; i--)
        {
            // ((s[i] - L[i]) >> 8) is 0xff (sign-extended via byte wrap) iff s[i] < L[i],
            // 0 otherwise. Masked by n so we only act on the first non-equal byte.
            c |= (byte)(((s[i] - s_lBytes[i]) >> 8) & n);

            // ((s[i] ^ L[i]) - 1) >> 8 is 0xff iff s[i] == L[i] (the XOR is 0,
            // 0 - 1 wraps to 0xff). Bitwise AND with n: stays 1 only if all
            // higher bytes were equal.
            n &= (byte)(((s[i] ^ s_lBytes[i]) - 1) >> 8);
        }

        return c != 0;
    }
}
