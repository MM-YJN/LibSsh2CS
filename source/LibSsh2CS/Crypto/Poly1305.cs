// Translated from libssh2 src/poly1305.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 * Copyright not intended 2024.
 *
 * SPDX-License-Identifier: SAX-PD-2.0
 */

using System.Buffers.Binary;

namespace LibSsh2CS.Crypto;

/// <summary>
/// Poly1305 one-shot MAC — 1:1 port of libssh2 <c>poly1305.c</c>
/// (Andrew Moon's <c>poly1305-donna-unrolled</c>). The reference C is a single
/// function <c>poly1305_auth</c>; this class mirrors it as a stateless
/// <see cref="Auth(Span{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </summary>
/// <remarks>
/// <para>
/// Poly1305 is nonce-independent, so (unlike <see cref="ChaCha20"/>) it is
/// directly verifiable against RFC 8439 §2.5.2 — that vector is the primary KAT.
/// The 26-bit-limb decomposition, the 5×(r,s) multiply, and the final
/// reduction+serialize all mirror <c>poly1305.c</c> line-for-line.
/// </para>
/// <para>
/// SSH uses Poly1305 only inside <see cref="ChaChaPolySsh"/>, where the 32-byte
/// key is the first Poly1305-key block of ChaCha20(main, seqnr, counter=0).
/// </para>
/// </remarks>
internal static class Poly1305
{
    /// <summary>Poly1305 key length in bytes (r ‖ s).</summary>
    public const int KeyLength = 32;

    /// <summary>Poly1305 authentication tag length in bytes.</summary>
    public const int TagLength = 16;

    /// <summary>
    /// Computes the 16-byte Poly1305 tag over <paramref name="message"/> using
    /// the 32-byte <paramref name="key"/> (clamped r ‖ s). Port of
    /// <c>poly1305_auth</c>.
    /// </summary>
    public static void Auth(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length < TagLength)
        {
            throw new ArgumentException("tag buffer must be at least 16 bytes", nameof(tag));
        }

        if (key.Length != KeyLength)
        {
            throw new ArgumentException("key must be exactly 32 bytes", nameof(key));
        }

        unchecked
        {
            uint t0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
            uint t1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
            uint t2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
            uint t3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));

            // Clamp the r half into five 26-bit limbs (poly1305-donna layout).
            uint r0 = t0 & 0x3ffffff;
            t0 >>= 26;
            t0 |= t1 << 6;
            uint r1 = t0 & 0x3ffff03;
            t1 >>= 20;
            t1 |= t2 << 12;
            uint r2 = t1 & 0x3ffc0ff;
            t2 >>= 14;
            t2 |= t3 << 18;
            uint r3 = t2 & 0x3f03fff;
            t3 >>= 8;
            uint r4 = t3 & 0x00fffff;

            // Precompute s_i = 5 * r_i (used in the mod (2^130 - 5) reduction).
            uint s1 = r1 * 5;
            uint s2 = r2 * 5;
            uint s3 = r3 * 5;
            uint s4 = r4 * 5;

            uint h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

            int inlen = message.Length;
            int off = 0;

            // Full 16-byte blocks (C: poly1305_donna_16bytes → poly1305_donna_mul).
            while (inlen >= 16)
            {
                t0 = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(off, 4));
                t1 = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(off + 4, 4));
                t2 = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(off + 8, 4));
                t3 = BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(off + 12, 4));
                off += 16;
                inlen -= 16;

                Accumulate(ref h0, ref h1, ref h2, ref h3, ref h4, t0, t1, t2, t3, pad: 1u << 24);
                MultiplyReduce(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4);
            }

            // Final partial block (C: poly1305_donna_atmost15bytes). The 0x01 pad
            // byte lives in the data, so no implicit 2^130 bit is added here.
            if (inlen > 0)
            {
                Span<byte> mp = stackalloc byte[16];
                message.Slice(off, inlen).CopyTo(mp);
                mp[inlen] = 1;
                if (inlen + 1 < 16)
                {
                    mp.Slice(inlen + 1).Clear();
                }

                t0 = BinaryPrimitives.ReadUInt32LittleEndian(mp.Slice(0, 4));
                t1 = BinaryPrimitives.ReadUInt32LittleEndian(mp.Slice(4, 4));
                t2 = BinaryPrimitives.ReadUInt32LittleEndian(mp.Slice(8, 4));
                t3 = BinaryPrimitives.ReadUInt32LittleEndian(mp.Slice(12, 4));

                Accumulate(ref h0, ref h1, ref h2, ref h3, ref h4, t0, t1, t2, t3, pad: 0);
                MultiplyReduce(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4);
            }

            Finish(tag, h0, h1, h2, h3, h4, key);
        }
    }

    // Adds a 16-byte block (t0..t3 LE) into the h accumulator across the five
    // 26-bit limbs, plus the 2^130 padding bit (full block: pad = 1<<24; partial:
    // pad = 0 since the 0x01 byte is already in the data). Lines 106-110 / 166-170.
    private static void Accumulate(
        ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4,
        uint t0, uint t1, uint t2, uint t3, uint pad)
    {
        unchecked
        {
            h0 += t0 & 0x3ffffff;
            h1 += (uint)((((ulong)t1 << 32) | t0) >> 26) & 0x3ffffff;
            h2 += (uint)((((ulong)t2 << 32) | t1) >> 20) & 0x3ffffff;
            h3 += (uint)((((ulong)t3 << 32) | t2) >> 14) & 0x3ffffff;
            h4 += (t3 >> 8) | pad;
        }
    }

    // The 5×5 multiply-and-reduce mod (2^130 - 5). Lines 113-144. The carry is
    // propagated and folded back into h0 as b*5 (the "−5" of the modulus).
    private static void MultiplyReduce(
        ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4,
        uint r0, uint r1, uint r2, uint r3, uint r4,
        uint s1, uint s2, uint s3, uint s4)
    {
        unchecked
        {
            ulong t0 = Mul64(h0, r0) + Mul64(h1, s4) + Mul64(h2, s3) + Mul64(h3, s2) + Mul64(h4, s1);
            ulong t1 = Mul64(h0, r1) + Mul64(h1, r0) + Mul64(h2, s4) + Mul64(h3, s3) + Mul64(h4, s2);
            ulong t2 = Mul64(h0, r2) + Mul64(h1, r1) + Mul64(h2, r0) + Mul64(h3, s4) + Mul64(h4, s3);
            ulong t3 = Mul64(h0, r3) + Mul64(h1, r2) + Mul64(h2, r1) + Mul64(h3, r0) + Mul64(h4, s4);
            ulong t4 = Mul64(h0, r4) + Mul64(h1, r3) + Mul64(h2, r2) + Mul64(h3, r1) + Mul64(h4, r0);

            h0 = (uint)t0 & 0x3ffffff;
            ulong c = t0 >> 26;

            t1 += c;
            h1 = (uint)t1 & 0x3ffffff;
            uint b = (uint)(t1 >> 26);

            t2 += b;
            h2 = (uint)t2 & 0x3ffffff;
            b = (uint)(t2 >> 26);

            t3 += b;
            h3 = (uint)t3 & 0x3ffffff;
            b = (uint)(t3 >> 26);

            t4 += b;
            h4 = (uint)t4 & 0x3ffffff;
            b = (uint)(t4 >> 26);

            h0 += b * 5;
        }
    }

    // Final full reduction, conditional subtract of (2^130 - 5), add the s half
    // of the key, and serialize as 16 little-endian bytes. Lines 174-205.
    private static void Finish(
        Span<byte> tag, uint h0, uint h1, uint h2, uint h3, uint h4,
        ReadOnlySpan<byte> key)
    {
        unchecked
        {
            uint b = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += b;
            b = h1 >> 26;
            h1 &= 0x3ffffff;
            h2 += b;
            b = h2 >> 26;
            h2 &= 0x3ffffff;
            h3 += b;
            b = h3 >> 26;
            h3 &= 0x3ffffff;
            h4 += b;
            b = h4 >> 26;
            h4 &= 0x3ffffff;
            h0 += b * 5;
            b = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += b;

            // g = h + 5, then conditionally pick g if it didn't overflow 2^130.
            uint g0 = h0 + 5;
            b = g0 >> 26;
            g0 &= 0x3ffffff;
            uint g1 = h1 + b;
            b = g1 >> 26;
            g1 &= 0x3ffffff;
            uint g2 = h2 + b;
            b = g2 >> 26;
            g2 &= 0x3ffffff;
            uint g3 = h3 + b;
            b = g3 >> 26;
            g3 &= 0x3ffffff;
            uint g4 = h4 + b - (1u << 26);

            // b = (g4 >> 31) - 1  → all-ones if h+5 fit in 130 bits (g4 high bit
            // clear), else 0. This is the C uint logical-shift + wraparound; the
            // enclosing unchecked context makes `- 1` wrap to 0xFFFFFFFF.
            b = (g4 >> 31) - 1;
            uint nb = ~b;
            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            // Add the s half of the key (key[16..32]) and serialize. Each limb
            // expression is a uint32 (the C truncates h_i << k to uint32 before
            // promoting to uint64 for the add), so cast to ulong here to force the
            // addition in 64-bit — otherwise the sum wraps and the carry chain
            // (f1 += f0>>32, …) goes wrong.
            ulong f0 = (ulong)(h0 | (h1 << 26)) + BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
            ulong f1 = (ulong)((h1 >> 6) | (h2 << 20)) + BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
            ulong f2 = (ulong)((h2 >> 12) | (h3 << 14)) + BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
            ulong f3 = (ulong)((h3 >> 18) | (h4 << 8)) + BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));

            f1 += f0 >> 32;
            f2 += f1 >> 32;
            f3 += f2 >> 32;

            BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(0, 4), (uint)f0);
            BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(4, 4), (uint)f1);
            BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(8, 4), (uint)f2);
            BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(12, 4), (uint)f3);
        }
    }

    // mul32x32_64(a,b) = (uint64_t)(a) * (b). Promoting to ulong keeps the full
    // 64-bit product (inputs are < 2^26 limbs).
    private static ulong Mul64(uint a, uint b) => (ulong)a * b;
}
