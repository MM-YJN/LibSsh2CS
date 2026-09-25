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

using System.Runtime.InteropServices;

namespace LibSsh2CS.Crypto;

/// <summary>
/// Constant-time scalar multiplication on edwards25519. Direct C# port of
/// libsodium's <c>ge25519_scalarmult_base</c> (fixed-base) and
/// <c>ge25519_scalarmult</c> (variable-base).
/// </summary>
/// <remarks>
/// <para>
/// <b>Fixed-base</b> uses the precomputed <see cref="GeBasepointTable"/> (32×8
/// Duif precomp entries) with a radix-16 sliding-window decomposition of the
/// scalar. <b>Variable-base</b> builds an 8-entry cached lookup table at
/// runtime (1·P, 2·P, …, 8·P) and runs the same radix-16 ladder over it.
/// </para>
/// <para>
/// Both functions are constant-time on the scalar: every iteration of the main
/// loop runs the same sequence of <c>CMove8</c> + <c>Add</c> + <c>Double</c>
/// operations, with the scalar-dependent choice absorbed by the constant-time
/// lookup. No branch depends on a secret-derived value.
/// </para>
/// <para>
/// libsodium C functions replaced (both in <c>ed25519_ref10.c</c>):
/// <c>ge25519_scalarmult_base</c> (:914-963), <c>ge25519_scalarmult</c>
/// (:822-902). <c>ge25519_double_scalarmult_vartime</c> (:726-809) is NOT
/// ported — Ed25519 verify stays unbatched (<c>[S]B = R + [h]A</c> as three
/// scalar mults).
/// </para>
/// <para>
/// <b>Precondition:</b> <c>a[31] &lt;= 127</c> for both methods. The Ed25519
/// scalar clamp (<c>a[31] &amp;= 0x7F</c>) ensures this for sign; libsodium's
/// scalarmult_base / scalarmult document the same precondition.
/// </para>
/// </remarks>
internal static class Ge25519ScalarMult
{
    /// <summary>
    /// Computes <c>h = a * B</c> (the Ed25519 base point). Constant-time on
    /// <paramref name="a"/>. Port of <c>ge25519_scalarmult_base</c>
    /// (libsodium <c>ed25519_ref10.c:914-963</c>).
    /// </summary>
    /// <param name="h">Receives the resulting point in extended coordinates.</param>
    /// <param name="a">The 32-byte little-endian scalar. <c>a[31]</c> must be
    /// at most 127 (top bit clear).</param>
    public static void Base(out GeP3 h, ReadOnlySpan<byte> a)
    {
        if (a.Length != 32)
        {
            throw new ArgumentException("Scalar must be exactly 32 bytes", nameof(a));
        }

        // Step 1: radix-16 decomposition. Each byte a[i] is split into two
        // signed 4-bit nibbles e[2i] (low) and e[2i+1] (high). Initial range
        // for each e[i] is [0, 15].
        Span<sbyte> e = stackalloc sbyte[64];
        for (int i = 0; i < 32; i++)
        {
            e[(2 * i) + 0] = (sbyte)(a[i] & 15);
            e[(2 * i) + 1] = (sbyte)((a[i] >> 4) & 15);
        }

        // Step 2: carry propagation to balanced signed radix-16. Each e[i] ends
        // up in [-8, 8]; e[63] in [-8, 7] (since a[31] <= 127 ⇒ top nibble <= 7).
        // The total value Σ e[i] * 16^i is preserved exactly.
        sbyte carry = 0;
        for (int i = 0; i < 63; i++)
        {
            e[i] += carry;
            carry = (sbyte)((e[i] + 8) >> 4);
            e[i] -= (sbyte)(carry * 16);
        }

        e[63] += carry;

        // Step 3: process odd-indexed nibbles (i = 1, 3, ..., 63). For each,
        // constant-time select e[i] * 256^(i/2) * B from the precomputed table
        // and mixed-add into h. The 4 doublings in step 4 multiply these
        // contributions by 16, so combined with step 5 each byte a[k] of the
        // scalar contributes a[k] * 256^k * B.
        Ge25519Ops.P3Zero(out h);
        for (int i = 1; i < 64; i += 2)
        {
            SelectFromBaseTable(out GePrecomp t, i / 2, e[i]);
            Ge25519Ops.MAdd(out GeP1P1 r, in h, in t);
            Ge25519Ops.P1P1ToP3(out h, in r);
        }

        // Step 4: 4 doublings — h = 16 * h.
        Ge25519Ops.P3Dbl(out GeP1P1 r2, in h);
        Ge25519Ops.P1P1ToP2(out GeP2 s, in r2);
        Ge25519Ops.P2Dbl(out r2, in s);
        Ge25519Ops.P1P1ToP2(out s, in r2);
        Ge25519Ops.P2Dbl(out r2, in s);
        Ge25519Ops.P1P1ToP2(out s, in r2);
        Ge25519Ops.P2Dbl(out r2, in s);
        Ge25519Ops.P1P1ToP3(out h, in r2);

        // Step 5: process even-indexed nibbles (i = 0, 2, ..., 62).
        for (int i = 0; i < 64; i += 2)
        {
            SelectFromBaseTable(out GePrecomp t, i / 2, e[i]);
            Ge25519Ops.MAdd(out GeP1P1 r, in h, in t);
            Ge25519Ops.P1P1ToP3(out h, in r);
        }
    }

    /// <summary>
    /// Computes <c>h = a * p</c> for an arbitrary point <paramref name="p"/>.
    /// Constant-time on <paramref name="a"/>. Port of <c>ge25519_scalarmult</c>
    /// (libsodium <c>ed25519_ref10.c:822-902</c>).
    /// </summary>
    /// <param name="h">Receives the resulting point in extended coordinates.</param>
    /// <param name="a">The 32-byte little-endian scalar. <c>a[31]</c> must be
    /// at most 127 (top bit clear).</param>
    /// <param name="p">The point to multiply (in extended coordinates).</param>
    public static void ScalarMult(out GeP3 h, ReadOnlySpan<byte> a, in GeP3 p)
    {
        if (a.Length != 32)
        {
            throw new ArgumentException("Scalar must be exactly 32 bytes", nameof(a));
        }

        // Build an 8-entry cached lookup table at runtime: pi[j-1] = j * p for j in 1..8.
        // Matches the libsodium construction (ed25519_ref10.c:834-862):
        //   pi[0] = p
        //   pi[1] = 2p
        //   pi[2] = 3p = 2p + p
        //   pi[3] = 4p = 2*2p
        //   pi[4] = 5p = 4p + p
        //   pi[5] = 6p = 2*3p
        //   pi[6] = 7p = 6p + p
        //   pi[7] = 8p = 2*4p
        Ge25519Ops.P3ToCached(out GeCached pi0, in p);

        Ge25519Ops.P3Dbl(out GeP1P1 t2, in p);
        Ge25519Ops.P1P1ToP3(out GeP3 p2, in t2);
        Ge25519Ops.P3ToCached(out GeCached pi1, in p2);

        Ge25519Ops.Add(out GeP1P1 t3, in p, in pi1);
        Ge25519Ops.P1P1ToP3(out GeP3 p3, in t3);
        Ge25519Ops.P3ToCached(out GeCached pi2, in p3);

        Ge25519Ops.P3Dbl(out GeP1P1 t4, in p2);
        Ge25519Ops.P1P1ToP3(out GeP3 p4, in t4);
        Ge25519Ops.P3ToCached(out GeCached pi3, in p4);

        Ge25519Ops.Add(out GeP1P1 t5, in p, in pi3);
        Ge25519Ops.P1P1ToP3(out GeP3 p5, in t5);
        Ge25519Ops.P3ToCached(out GeCached pi4, in p5);

        Ge25519Ops.P3Dbl(out GeP1P1 t6, in p3);
        Ge25519Ops.P1P1ToP3(out GeP3 p6, in t6);
        Ge25519Ops.P3ToCached(out GeCached pi5, in p6);

        Ge25519Ops.Add(out GeP1P1 t7, in p, in pi5);
        Ge25519Ops.P1P1ToP3(out GeP3 p7, in t7);
        Ge25519Ops.P3ToCached(out GeCached pi6, in p7);

        Ge25519Ops.P3Dbl(out GeP1P1 t8, in p4);
        Ge25519Ops.P1P1ToP3(out GeP3 p8, in t8);
        Ge25519Ops.P3ToCached(out GeCached pi7, in p8);

        // pi is a fixed-size scratch table for this call; keep it on the stack
        // rather than allocating a GeCached[8] per scalar multiplication.
        Span<GeCached> pi = stackalloc GeCached[8];
        pi[0] = pi0;
        pi[1] = pi1;
        pi[2] = pi2;
        pi[3] = pi3;
        pi[4] = pi4;
        pi[5] = pi5;
        pi[6] = pi6;
        pi[7] = pi7;

        // Radix-16 decomposition + carry propagation (same as Base).
        Span<sbyte> e = stackalloc sbyte[64];
        for (int i = 0; i < 32; i++)
        {
            e[(2 * i) + 0] = (sbyte)(a[i] & 15);
            e[(2 * i) + 1] = (sbyte)((a[i] >> 4) & 15);
        }

        sbyte carry = 0;
        for (int i = 0; i < 63; i++)
        {
            e[i] += carry;
            carry = (sbyte)((e[i] + 8) >> 4);
            e[i] -= (sbyte)(carry * 16);
        }

        e[63] += carry;

        // Main ladder: from high nibble to low, h = 16 * (h + e[i]*p) per step.
        // After all 64 steps, h = Σ e[i] * 16^i * p = a * p.
        Ge25519Ops.P3Zero(out h);
        for (int i = 63; i != 0; i--)
        {
            Ge25519Ops.CMove8Cached(out GeCached t, pi, e[i]);
            Ge25519Ops.Add(out GeP1P1 r, in h, in t);

            Ge25519Ops.P1P1ToP2(out GeP2 s, in r);
            Ge25519Ops.P2Dbl(out r, in s);
            Ge25519Ops.P1P1ToP2(out s, in r);
            Ge25519Ops.P2Dbl(out r, in s);
            Ge25519Ops.P1P1ToP2(out s, in r);
            Ge25519Ops.P2Dbl(out r, in s);
            Ge25519Ops.P1P1ToP2(out s, in r);
            Ge25519Ops.P2Dbl(out r, in s);

            Ge25519Ops.P1P1ToP3(out h, in r);
        }

        Ge25519Ops.CMove8Cached(out GeCached tf, pi, e[0]);
        Ge25519Ops.Add(out GeP1P1 rf, in h, in tf);
        Ge25519Ops.P1P1ToP3(out h, in rf);
    }

    /// <summary>
    /// Selects <c>e * base[pos][j-1]</c> (with sign flip for negative <paramref name="b"/>)
    /// from the precomputed basepoint table. Port of <c>ge25519_cmov8_base</c>
    /// (libsodium <c>ed25519_ref10.c:642-653</c>).
    /// </summary>
    private static void SelectFromBaseTable(out GePrecomp t, int pos, sbyte b)
    {
        // View row `pos` of the contiguous 32×8 table as a span — no copy.
        // GePrecomp is an unmanaged struct and the table is a fixed-size
        // static readonly array, so this view is valid for the call duration.
        ReadOnlySpan<GePrecomp> row =
            MemoryMarshal.CreateReadOnlySpan(ref GeBasepointTable.Table[pos, 0], 8);
        Ge25519Ops.CMove8Precomp(out t, row, b);
    }
}
