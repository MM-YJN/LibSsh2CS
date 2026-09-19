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

using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS.Crypto;

/// <summary>
/// Constant-time arithmetic over GF(2^255 - 19) operating on <see cref="Fe"/> values.
/// </summary>
/// <remarks>
/// <para>
/// Direct C# port of libsodium's <c>crypto_core/ed25519/ref10/fe_25_5/*.c</c>. The
/// algorithm is identical to the int32-limb libsodium version; we use 64-bit limbs
/// throughout (the <see cref="long"/> C# type) for cleaner arithmetic with no
/// narrowing step. The carry chain keeps limbs bounded exactly as in libsodium.
/// </para>
/// <para>
/// <b>Constant-time guarantee:</b> no method branches on values derived from secret
/// inputs. Conditional moves and swaps use the standard sign-extended mask trick
/// <c>long mask = -((long)bit);</c> which produces all-zeros when <c>bit == 0</c>
/// and all-ones when <c>bit == 1</c>. Limb combinations use <c>(x &amp; mask) | (y &amp; ~mask)</c>.
/// </para>
/// <para>
/// libsodium C files replaced:
/// <c>fe_25_5/fe.h</c>, <c>fe_neg.c</c>, <c>fe_add.c</c>, <c>fe_sub.c</c>,
/// <c>fe_mul.c</c>, <c>fe_sq.c</c>, <c>fe_sq2.c</c>, <c>fe_mul121666.c</c>,
/// <c>fe_invert.c</c>, <c>fe_pow22523.c</c>, <c>fe_tobytes.c</c>, <c>fe_frombytes.c</c>,
/// <c>fe_isnonzero.c</c>, <c>fe_isnegative.c</c>, <c>fe_cmov.c</c>, <c>fe_0.c</c>,
/// <c>fe_1.c</c>, <c>fe_copy.c</c>.
/// </para>
/// </remarks>
internal static class Fe25519Ops
{
    // The field characteristic is p = 2^255 - 19; the relation 2^255 ≡ 19 (mod p) is
    // used in the final carry step of Mul/Sq (the wrap-around multiplier).

    /// <summary>Returns the field element 0.</summary>
    public static Fe Zero()
    {
        Fe h = default;
        h._l0 = 0;
        h._l1 = 0;
        h._l2 = 0;
        h._l3 = 0;
        h._l4 = 0;
        h._l5 = 0;
        h._l6 = 0;
        h._l7 = 0;
        h._l8 = 0;
        h._l9 = 0;
        return h;
    }

    /// <summary>Returns the field element 1.</summary>
    public static Fe One()
    {
        Fe h = default;
        h._l0 = 1;
        h._l1 = 0;
        h._l2 = 0;
        h._l3 = 0;
        h._l4 = 0;
        h._l5 = 0;
        h._l6 = 0;
        h._l7 = 0;
        h._l8 = 0;
        h._l9 = 0;
        return h;
    }

    /// <summary>
    /// Returns the field element whose value is the small integer <paramref name="n"/>
    /// (used only for known constants like 2, 19, 121665 — |n| must fit in a limb).
    /// </summary>
    public static Fe FromSmall(long n)
    {
        Fe h = default;
        h._l0 = n;
        h._l1 = 0;
        h._l2 = 0;
        h._l3 = 0;
        h._l4 = 0;
        h._l5 = 0;
        h._l6 = 0;
        h._l7 = 0;
        h._l8 = 0;
        h._l9 = 0;
        return h;
    }

    /// <summary>Element-wise copy (struct assignment; <paramref name="h"/> receives <paramref name="f"/>).</summary>
    public static void Copy(out Fe h, in Fe f) => h = f;

    /// <summary>Computes <c>(f + g)</c>. Limb-wise add; no carry.</summary>
    public static void Add(out Fe h, in Fe f, in Fe g)
    {
        h._l0 = f._l0 + g._l0;
        h._l1 = f._l1 + g._l1;
        h._l2 = f._l2 + g._l2;
        h._l3 = f._l3 + g._l3;
        h._l4 = f._l4 + g._l4;
        h._l5 = f._l5 + g._l5;
        h._l6 = f._l6 + g._l6;
        h._l7 = f._l7 + g._l7;
        h._l8 = f._l8 + g._l8;
        h._l9 = f._l9 + g._l9;
    }

    /// <summary>Computes <c>(f - g)</c>. Limb-wise subtract; no carry.</summary>
    public static void Sub(out Fe h, in Fe f, in Fe g)
    {
        h._l0 = f._l0 - g._l0;
        h._l1 = f._l1 - g._l1;
        h._l2 = f._l2 - g._l2;
        h._l3 = f._l3 - g._l3;
        h._l4 = f._l4 - g._l4;
        h._l5 = f._l5 - g._l5;
        h._l6 = f._l6 - g._l6;
        h._l7 = f._l7 - g._l7;
        h._l8 = f._l8 - g._l8;
        h._l9 = f._l9 - g._l9;
    }

    /// <summary>Computes <c>-f</c>. Limb-wise negate; no carry.</summary>
    public static void Neg(out Fe h, in Fe f)
    {
        h._l0 = -f._l0;
        h._l1 = -f._l1;
        h._l2 = -f._l2;
        h._l3 = -f._l3;
        h._l4 = -f._l4;
        h._l5 = -f._l5;
        h._l6 = -f._l6;
        h._l7 = -f._l7;
        h._l8 = -f._l8;
        h._l9 = -f._l9;
    }

    /// <summary>
    /// Field multiplication: <c>h = f * g (mod p)</c>. Port of
    /// <c>ed25519_ref10_fe_25_5.h :: fe25519_mul</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each contribution <c>f_i * g_j * 2^(pos_i + pos_j)</c> lands in the destination
    /// limb <c>k</c> at a specific bit-offset. For even <c>k</c>, half of the
    /// contributions land at offset 1 (rather than 0), so they pick up an extra factor
    /// of 2 — expressed via the <c>f_i_2 = 2*f_i</c> precomputation. Wrapped
    /// contributions (where <c>pos_i + pos_j &gt;= 255</c>) get an extra factor of 19,
    /// or 38 when the offset is also 1.
    /// </para>
    /// <para>
    /// The precomputed <c>g_j_19</c> / <c>g_j_38</c> variables combine the wrap factor
    /// (19) with the optional offset factor (2) so each output coefficient is a single
    /// 64-bit sum of products. This is line-for-line from libsodium.
    /// </para>
    /// </remarks>
    public static void Mul(out Fe h, in Fe f, in Fe g)
    {
        long f0 = f._l0;
        long f1 = f._l1;
        long f2 = f._l2;
        long f3 = f._l3;
        long f4 = f._l4;
        long f5 = f._l5;
        long f6 = f._l6;
        long f7 = f._l7;
        long f8 = f._l8;
        long f9 = f._l9;

        long g0 = g._l0;
        long g1 = g._l1;
        long g2 = g._l2;
        long g3 = g._l3;
        long g4 = g._l4;
        long g5 = g._l5;
        long g6 = g._l6;
        long g7 = g._l7;
        long g8 = g._l8;
        long g9 = g._l9;

        // Doubled-f for odd indices (used for no-wrap pairs that contribute at offset 1
        // within an even limb — i.e., (1,1) in h2, (3,3) in h6, etc. — AND for wrapped
        // offset-1 pairs where it combines with g_j_19 to give factor 38).
        long f1_2 = 2 * f1;
        long f3_2 = 2 * f3;
        long f5_2 = 2 * f5;
        long f7_2 = 2 * f7;
        long f9_2 = 2 * f9;

        // 19* of g limbs (for wrapped pairs). When combined with f_i_2 this gives 38*.
        long g1_19 = 19 * g1;
        long g2_19 = 19 * g2;
        long g3_19 = 19 * g3;
        long g4_19 = 19 * g4;
        long g5_19 = 19 * g5;
        long g6_19 = 19 * g6;
        long g7_19 = 19 * g7;
        long g8_19 = 19 * g8;
        long g9_19 = 19 * g9;

        // For each h_k: sum the no-wrap pairs (i+j=k) and the wrapped pairs (i+j=k+10).
        // Wrapped pairs pick up factor 19 (or 38 when offset within the destination limb
        // is 1). The "offset 1" condition holds for even k when i is odd.
        long h0 = (f0 * g0)
                + (f1_2 * g9_19) + (f2 * g8_19) + (f3_2 * g7_19) + (f4 * g6_19)
                + (f5_2 * g5_19) + (f6 * g4_19) + (f7_2 * g3_19) + (f8 * g2_19) + (f9_2 * g1_19);
        long h1 = (f0 * g1) + (f1 * g0)
                + (f2 * g9_19) + (f3 * g8_19) + (f4 * g7_19) + (f5 * g6_19)
                + (f6 * g5_19) + (f7 * g4_19) + (f8 * g3_19) + (f9 * g2_19);
        long h2 = (f0 * g2) + (f1_2 * g1) + (f2 * g0)
                + (f3_2 * g9_19) + (f4 * g8_19) + (f5_2 * g7_19) + (f6 * g6_19)
                + (f7_2 * g5_19) + (f8 * g4_19) + (f9_2 * g3_19);
        long h3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0)
                + (f4 * g9_19) + (f5 * g8_19) + (f6 * g7_19) + (f7 * g6_19) + (f8 * g5_19) + (f9 * g4_19);
        long h4 = (f0 * g4) + (f1_2 * g3) + (f2 * g2) + (f3_2 * g1) + (f4 * g0)
                + (f5_2 * g9_19) + (f6 * g8_19) + (f7_2 * g7_19) + (f8 * g6_19) + (f9_2 * g5_19);
        long h5 = (f0 * g5) + (f1 * g4) + (f2 * g3) + (f3 * g2) + (f4 * g1) + (f5 * g0)
                + (f6 * g9_19) + (f7 * g8_19) + (f8 * g7_19) + (f9 * g6_19);
        long h6 = (f0 * g6) + (f1_2 * g5) + (f2 * g4) + (f3_2 * g3) + (f4 * g2) + (f5_2 * g1) + (f6 * g0)
                + (f7_2 * g9_19) + (f8 * g8_19) + (f9_2 * g7_19);
        long h7 = (f0 * g7) + (f1 * g6) + (f2 * g5) + (f3 * g4) + (f4 * g3) + (f5 * g2) + (f6 * g1) + (f7 * g0)
                + (f8 * g9_19) + (f9 * g8_19);
        long h8 = (f0 * g8) + (f1_2 * g7) + (f2 * g6) + (f3_2 * g5) + (f4 * g4) + (f5_2 * g3) + (f6 * g2) + (f7_2 * g1) + (f8 * g0)
                + (f9_2 * g9_19);
        long h9 = (f0 * g9) + (f1 * g8) + (f2 * g7) + (f3 * g6) + (f4 * g5) + (f5 * g4) + (f6 * g3) + (f7 * g2) + (f8 * g1) + (f9 * g0);

        ReduceAndCarry(out h, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9);
    }

    /// <summary>
    /// Field squaring: <c>h = f^2 (mod p)</c>. Port of
    /// <c>ed25519_ref10_fe_25_5.h :: fe25519_sq</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each contribution <c>f_i * f_j * 2^(pos_i + pos_j)</c> lands in the destination
    /// limb <c>k</c> at a specific bit-offset. For squaring, off-diagonal pairs (i,j)
    /// with i != j appear twice (symmetric factor 2). The total factor for each
    /// contribution is the product of:
    /// <list type="bullet">
    /// <item>Symmetric-pair factor: 2 if i != j, 1 if i == j (diagonal).</item>
    /// <item>Offset factor: 2 if the contribution lands at offset 1 within an even
    /// limb, 1 otherwise.</item>
    /// <item>Wrap factor: 19 if pos_i + pos_j >= 255, 1 otherwise.</item>
    /// </list>
    /// The prefix-numbering convention in libsodium's variable names encodes the
    /// combined factor: <c>_2</c> = 2 (symmetric), <c>_4</c> = 4 (symmetric + offset),
    /// <c>_19</c> = 19 (wrap), <c>_38</c> = 38 (wrap + offset, no symmetric — diagonal),
    /// <c>_76</c> = 76 (symmetric + offset + wrap).
    /// </para>
    /// </remarks>
    public static void Sq(out Fe h, in Fe f)
    {
        long f0 = f._l0;
        long f1 = f._l1;
        long f2 = f._l2;
        long f3 = f._l3;
        long f4 = f._l4;
        long f5 = f._l5;
        long f6 = f._l6;
        long f7 = f._l7;
        long f8 = f._l8;
        long f9 = f._l9;

        long f0_2 = 2 * f0;
        long f1_2 = 2 * f1;
        long f2_2 = 2 * f2;
        long f3_2 = 2 * f3;
        long f4_2 = 2 * f4;
        long f5_2 = 2 * f5;
        long f6_2 = 2 * f6;
        long f7_2 = 2 * f7;
        long f5_38 = 38 * f5;
        long f6_19 = 19 * f6;
        long f7_38 = 38 * f7;
        long f8_19 = 19 * f8;
        long f9_38 = 38 * f9;

        // Each product is named fij_c where c is the combined factor (1 implied if absent).
        // Verbatim from libsodium ed25519_ref10_fe_25_5.h::fe25519_sq.
        long f0f0 = f0 * f0;
        long f0f1_2 = f0_2 * f1;
        long f0f2_2 = f0_2 * f2;
        long f0f3_2 = f0_2 * f3;
        long f0f4_2 = f0_2 * f4;
        long f0f5_2 = f0_2 * f5;
        long f0f6_2 = f0_2 * f6;
        long f0f7_2 = f0_2 * f7;
        long f0f8_2 = f0_2 * f8;
        long f0f9_2 = f0_2 * f9;
        long f1f1_2 = f1_2 * f1;
        long f1f2_2 = f1_2 * f2;
        long f1f3_4 = f1_2 * f3_2;
        long f1f4_2 = f1_2 * f4;
        long f1f5_4 = f1_2 * f5_2;
        long f1f6_2 = f1_2 * f6;
        long f1f7_4 = f1_2 * f7_2;
        long f1f8_2 = f1_2 * f8;
        long f1f9_76 = f1_2 * f9_38;
        long f2f2 = f2 * f2;
        long f2f3_2 = f2_2 * f3;
        long f2f4_2 = f2_2 * f4;
        long f2f5_2 = f2_2 * f5;
        long f2f6_2 = f2_2 * f6;
        long f2f7_2 = f2_2 * f7;
        long f2f8_38 = f2_2 * f8_19;
        long f2f9_38 = f2 * f9_38;
        long f3f3_2 = f3_2 * f3;
        long f3f4_2 = f3_2 * f4;
        long f3f5_4 = f3_2 * f5_2;
        long f3f6_2 = f3_2 * f6;
        long f3f7_76 = f3_2 * f7_38;
        long f3f8_38 = f3_2 * f8_19;
        long f3f9_76 = f3_2 * f9_38;
        long f4f4 = f4 * f4;
        long f4f5_2 = f4_2 * f5;
        long f4f6_38 = f4_2 * f6_19;
        long f4f7_38 = f4 * f7_38;
        long f4f8_38 = f4_2 * f8_19;
        long f4f9_38 = f4 * f9_38;
        long f5f5_38 = f5 * f5_38;
        long f5f6_38 = f5_2 * f6_19;
        long f5f7_76 = f5_2 * f7_38;
        long f5f8_38 = f5_2 * f8_19;
        long f5f9_76 = f5_2 * f9_38;
        long f6f6_19 = f6 * f6_19;
        long f6f7_38 = f6 * f7_38;
        long f6f8_38 = f6_2 * f8_19;
        long f6f9_38 = f6 * f9_38;
        long f7f7_38 = f7 * f7_38;
        long f7f8_38 = f7_2 * f8_19;
        long f7f9_76 = f7_2 * f9_38;
        long f8f8_19 = f8 * f8_19;
        long f8f9_38 = f8 * f9_38;
        long f9f9_38 = f9 * f9_38;

        long h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        long h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        long h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

        ReduceAndCarry(out h, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9);
    }

    /// <summary>
    /// Field squaring with factor 2: <c>h = 2 * f^2 (mod p)</c>. Port of <c>fe_sq2.c</c>.
    /// Same as <see cref="Sq"/> with an additional doubling of the products; used by
    /// X25519 Montgomery ladder where 2*squares appear frequently.
    /// </summary>
    public static void Sq2(out Fe h, in Fe f)
    {
        Sq(out Fe sq, in f);
        Add(out h, in sq, in sq);
    }

    /// <summary>
    /// Multiply by the small constant 121666 (the X25519 ladder constant a24 + 1).
    /// Port of <c>fe_mul121666.c</c>.
    /// </summary>
    public static void Mul121666(out Fe h, in Fe f)
    {
        long h0 = 121666 * f._l0;
        long h1 = 121666 * f._l1;
        long h2 = 121666 * f._l2;
        long h3 = 121666 * f._l3;
        long h4 = 121666 * f._l4;
        long h5 = 121666 * f._l5;
        long h6 = 121666 * f._l6;
        long h7 = 121666 * f._l7;
        long h8 = 121666 * f._l8;
        long h9 = 121666 * f._l9;

        ReduceAndCarry(out h, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9);
    }

    /// <summary>
    /// The standard ref10 2-pass carry chain. Takes the raw (post-multiplication) limb
    /// values and produces a normalized <see cref="Fe"/> whose limbs are bounded to
    /// roughly [-2^25, 2^25]. Port of the carry chain at the end of <c>fe_mul.c</c>.
    /// </summary>
    /// <remarks>
    /// The "rounding bias" of <c>1&lt;&lt;25</c> / <c>1&lt;&lt;24</c> makes the arithmetic-shift
    /// equivalent to round-to-nearest, so that even after addition chains limbs remain in
    /// range without explicit subtraction of p. The final wrap multiplies by 19 because
    /// <c>2^255 ≡ 19 (mod p)</c>.
    /// </remarks>
    private static void ReduceAndCarry(
        out Fe h,
        ref long h0, ref long h1, ref long h2, ref long h3, ref long h4,
        ref long h5, ref long h6, ref long h7, ref long h8, ref long h9)
    {
        long carry0 = (h0 + (1L << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        long carry1 = (h1 + (1L << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;

        long carry2 = (h2 + (1L << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;

        long carry3 = (h3 + (1L << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;

        long carry4 = (h4 + (1L << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        long carry5 = (h5 + (1L << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        long carry6 = (h6 + (1L << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        long carry7 = (h7 + (1L << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        long carry8 = (h8 + (1L << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        long carry9 = (h9 + (1L << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        // Second pass on limb 0 only — limb 0 may have grown from the wrap-around carry.
        carry0 = (h0 + (1L << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        h._l0 = h0;
        h._l1 = h1;
        h._l2 = h2;
        h._l3 = h3;
        h._l4 = h4;
        h._l5 = h5;
        h._l6 = h6;
        h._l7 = h7;
        h._l8 = h8;
        h._l9 = h9;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Encoding (fe_frombytes / fe_tobytes)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Decodes a 32-byte little-endian value into a field element. The high bit of
    /// byte 31 (bit 255) is masked off (it cannot be represented in the standard
    /// limb layout — callers that need it, like wrapping a raw scalar, do so by
    /// adding 19 to the result after this call). Port of <c>fe_frombytes.c</c>.
    /// </summary>
    public static void FromBytes(out Fe h, ReadOnlySpan<byte> s)
    {
        // Each limb spans 25 or 26 bits at a known position. We load 4 bytes at the
        // starting offset of each limb and right-shift to align to position 0; the
        // mask strips the bits belonging to the next limb.
        //
        // Limb bit positions: 0, 26, 51, 77, 102, 128, 153, 179, 204, 230.
        // Starting byte for each limb = position // 8: 0, 3, 6, 9, 12, 16, 19, 22, 25, 28.
        // Bit shift within the loaded 32-bit value = position - (byte_offset * 8):
        //   0, 2, 3, 5, 6, 0, 1, 3, 4, 6.
        long h0 = Load4(s, 0) & 0x3FFFFFFL;             // bits 0–25  (26 bits)
        long h1 = (Load4(s, 3) >> 2) & 0x1FFFFFFL;      // bits 26–50 (25 bits)
        long h2 = (Load4(s, 6) >> 3) & 0x3FFFFFFL;      // bits 51–76 (26 bits)
        long h3 = (Load4(s, 9) >> 5) & 0x1FFFFFFL;      // bits 77–101 (25 bits)
        long h4 = (Load4(s, 12) >> 6) & 0x3FFFFFFL;     // bits 102–127 (26 bits)
        long h5 = Load4(s, 16) & 0x1FFFFFFL;            // bits 128–152 (25 bits)
        long h6 = (Load4(s, 19) >> 1) & 0x3FFFFFFL;     // bits 153–178 (26 bits)
        long h7 = (Load4(s, 22) >> 3) & 0x1FFFFFFL;     // bits 179–203 (25 bits)
        long h8 = (Load4(s, 25) >> 4) & 0x3FFFFFFL;     // bits 204–229 (26 bits)
        long h9 = (Load4(s, 28) >> 6) & 0x1FFFFFFL;     // bits 230–254 (25 bits, bit 255 dropped)

        h._l0 = h0;
        h._l1 = h1;
        h._l2 = h2;
        h._l3 = h3;
        h._l4 = h4;
        h._l5 = h5;
        h._l6 = h6;
        h._l7 = h7;
        h._l8 = h8;
        h._l9 = h9;
    }

    /// <summary>
    /// Encodes a field element to its canonical 32-byte little-endian form (fully
    /// reduced mod p). Port of <c>fe_tobytes.c</c>.
    /// </summary>
    public static void ToBytes(Span<byte> s, in Fe h)
    {
        // Reduce mod p with a final carry chain. After this, every limb is in [0, 2^25) or
        // [0, 2^26) as appropriate, and the combined value is the canonical representative
        // in [0, p). We then pack the 10 limbs back into 32 bytes.
        Fe hCopy = h;

        // First a carry chain to bring everything non-negative (round-to-nearest):
        // p is slightly less than 2^255, so we might still have a value greater than p
        // after reduction. We compute q = floor((h + p) / 2^255) — this is 0 or 1 — and
        // subtract q*p from h. Because p = 2^255 - 19, q*p = q*2^255 - 19*q, so subtracting
        // q*p means subtracting q from limb 9's high bit (effectively zeroing it) and
        // adding 19*q to limb 0.

        // Step 1: full freeze so every limb is non-negative (modular).
        Freeze(ref hCopy);

        // Step 2: extract bytes by re-splitting the limb array into 8-bit windows.
        long h0 = hCopy._l0;
        long h1 = hCopy._l1;
        long h2 = hCopy._l2;
        long h3 = hCopy._l3;
        long h4 = hCopy._l4;
        long h5 = hCopy._l5;
        long h6 = hCopy._l6;
        long h7 = hCopy._l7;
        long h8 = hCopy._l8;
        long h9 = hCopy._l9;

        // Pack 10 limbs (radices 26, 25, 26, 25, 26, 25, 26, 25, 26, 25) into 32 bytes.
        s[0] = (byte)(h0 >> 0);
        s[1] = (byte)(h0 >> 8);
        s[2] = (byte)(h0 >> 16);
        s[3] = (byte)((h0 >> 24) | (h1 << 2));
        s[4] = (byte)(h1 >> 6);
        s[5] = (byte)(h1 >> 14);
        s[6] = (byte)((h1 >> 22) | (h2 << 3));
        s[7] = (byte)(h2 >> 5);
        s[8] = (byte)(h2 >> 13);
        s[9] = (byte)((h2 >> 21) | (h3 << 5));
        s[10] = (byte)(h3 >> 3);
        s[11] = (byte)(h3 >> 11);
        s[12] = (byte)((h3 >> 19) | (h4 << 6));
        s[13] = (byte)(h4 >> 2);
        s[14] = (byte)(h4 >> 10);
        s[15] = (byte)(h4 >> 18);
        s[16] = (byte)(h5 >> 0);
        s[17] = (byte)(h5 >> 8);
        s[18] = (byte)(h5 >> 16);
        s[19] = (byte)((h5 >> 24) | (h6 << 1));
        s[20] = (byte)(h6 >> 7);
        s[21] = (byte)(h6 >> 15);
        s[22] = (byte)((h6 >> 23) | (h7 << 3));
        s[23] = (byte)(h7 >> 5);
        s[24] = (byte)(h7 >> 13);
        s[25] = (byte)((h7 >> 21) | (h8 << 4));
        s[26] = (byte)(h8 >> 4);
        s[27] = (byte)(h8 >> 12);
        s[28] = (byte)((h8 >> 20) | (h9 << 6));
        s[29] = (byte)(h9 >> 2);
        s[30] = (byte)(h9 >> 10);
        s[31] = (byte)(h9 >> 18);
    }

    /// <summary>
    /// Fully reduces <paramref name="h"/> in place so every limb is in <c>[0, 2^radix)</c>
    /// and the combined value is the canonical representative mod p (i.e. in <c>[0, p)</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The carry chain uses the SUPERCOP ref10 interleaved order (carry all
    /// 26-bit limbs, then all 25-bit limbs, then 26-bit again, etc.) — this is
    /// what the original ref10 <c>fe_tobytes.c</c> uses, NOT a linear chain. We
    /// use the plain <c>h &gt;&gt; radix</c> shift (no rounding bias), which is a no-op
    /// for canonical inputs (limbs in <c>[0, 2^radix)</c>) and correctly normalizes
    /// wide-range inputs (limbs in roughly <c>[-2^25, 2^25]</c> after Mul/Sq output).
    /// </para>
    /// <para>
    /// The rounding-bias variant <c>(h + 1&lt;&lt;(radix-1)) &gt;&gt; radix</c> used by some
    /// ref10 ports only works for "narrow" inputs centered around 0; it spuriously
    /// wraps canonical inputs whose limbs are near the radix maximum (e.g., the
    /// value <c>p</c> itself, whose non-zero limb 0 plus all-max high limbs triggers
    /// phantom carries).
    /// </para>
    /// <para>
    /// After the carry chain, h is in <c>[0, 2^255)</c>; we then do a
    /// constant-time conditional subtract of <c>p = 2^255 - 19</c> via the radix
    /// complement of <c>p</c> to land in <c>[0, p)</c>.
    /// </para>
    /// </remarks>
    public static void Freeze(ref Fe h)
    {
        long h0 = h._l0;
        long h1 = h._l1;
        long h2 = h._l2;
        long h3 = h._l3;
        long h4 = h._l4;
        long h5 = h._l5;
        long h6 = h._l6;
        long h7 = h._l7;
        long h8 = h._l8;
        long h9 = h._l9;

        // Libsodium ref10's fe_tobytes q-chain (fe_tobytes.c). The
        // previous SUPERCOP interleaved carry chain + h−p borrow selection kept
        // the exact (possibly negative-limb) representation whenever the value
        // was below p, so a sparse input with one extreme negative limb (e.g.
        // h5 = −2^25, all others 0 — within the [−2^25, 2^25] input
        // range) froze to a representation with h1 = −1, and ToBytes
        // sign-extended the negative limb into the packed bytes (output
        // ED FF … FF 7F instead of the canonical p − 2^153).
        //
        // The q-chain is exact for all signed inputs in (−p, p): the biased
        // carry cascade computes q = ⌊h / 2^255⌋ (the +2^24 bias makes the
        // arithmetic right shift round negative limbs correctly), then
        // h − p·q = h − 2^255·q + 19·q: the 2^255·q term vanishes mod 2^255 and
        // 19·q lands in h0. The sequential carry chain then canonicalizes the
        // limbs; the result is in [0, p) with every limb in radix, for every
        // signed input in (−p, p). Arithmetic right shifts on signed long
        // sign-extend for negative values, correctly producing the borrow.
        long q = (19 * h9 + (1L << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        h0 += 19 * q;

        long carry0 = h0 >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        long carry1 = h1 >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        long carry2 = h2 >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        long carry3 = h3 >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        long carry4 = h4 >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        long carry5 = h5 >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;
        long carry6 = h6 >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;
        long carry7 = h7 >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;
        long carry8 = h8 >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;
        long carry9 = h9 >> 25;
        h9 -= carry9 << 25;

        h._l0 = h0;
        h._l1 = h1;
        h._l2 = h2;
        h._l3 = h3;
        h._l4 = h4;
        h._l5 = h5;
        h._l6 = h6;
        h._l7 = h7;
        h._l8 = h8;
        h._l9 = h9;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Predicates
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Returns 1 if <paramref name="f"/> is the zero element, 0 otherwise. Constant-time.
    /// Port of <c>fe_isnonzero.c</c> (inverted sense).
    /// </summary>
    public static int IsZero(in Fe f)
    {
        Fe copy = f;
        Freeze(ref copy);

        // OR all limbs together; if any bit is set the element is nonzero.
        long bits = copy._l0 | copy._l1 | copy._l2 | copy._l3 | copy._l4
                  | copy._l5 | copy._l6 | copy._l7 | copy._l8 | copy._l9;

        // (bits | -bits) has its sign bit set iff bits != 0 (since -bits = ~bits + 1
        // flips all the low zero bits and adds 1 to the lowest 1 bit, leaving the sign
        // bit set whenever any bit was set). Arithmetic >> 63 yields 0 (bits==0) or
        // -1 = 0xFFFF…FFFF (bits!=0). Adding 1 produces 1 if bits==0, 0 if bits!=0.
        long result = ((bits | (-bits)) >> 63) + 1;
        return (int)result;
    }

    /// <summary>
    /// Returns 1 if <paramref name="f"/> is "negative" (odd parity in canonical encoding),
    /// 0 otherwise. Constant-time. Port of <c>fe_isnegative.c</c>.
    /// </summary>
    public static int IsNegative(in Fe f)
    {
        Fe copy = f;
        Freeze(ref copy);
        return (int)(copy._l0 & 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Conditional moves and swaps
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Conditional move: if <paramref name="b"/> is 1, sets <paramref name="f"/> to
    /// <paramref name="g"/>; if <paramref name="b"/> is 0, leaves <paramref name="f"/>
    /// unchanged. Constant-time. Port of <c>fe_cmov.c</c>.
    /// </summary>
    public static void CMove(ref Fe f, in Fe g, int b)
    {
        // Sign-extend b to a 64-bit mask: 0 → 0x0000…, 1 → 0xFFFF… (note that b is
        // assumed to be 0 or 1; we use -b which is 0 or -1).
        long mask = -((long)b);

        f._l0 = (f._l0 & ~mask) | (g._l0 & mask);
        f._l1 = (f._l1 & ~mask) | (g._l1 & mask);
        f._l2 = (f._l2 & ~mask) | (g._l2 & mask);
        f._l3 = (f._l3 & ~mask) | (g._l3 & mask);
        f._l4 = (f._l4 & ~mask) | (g._l4 & mask);
        f._l5 = (f._l5 & ~mask) | (g._l5 & mask);
        f._l6 = (f._l6 & ~mask) | (g._l6 & mask);
        f._l7 = (f._l7 & ~mask) | (g._l7 & mask);
        f._l8 = (f._l8 & ~mask) | (g._l8 & mask);
        f._l9 = (f._l9 & ~mask) | (g._l9 & mask);
    }

    /// <summary>
    /// Conditional swap: if <paramref name="bit"/> is 1, exchanges the two values;
    /// if 0, leaves both unchanged. Constant-time. Used by the X25519 Montgomery
    /// ladder (the eponymous "conditional swap" of X25519); retained for the
    /// shared field-arithmetic stack even though X25519 is now BCL-backed.
    /// </summary>
    public static void CSwap(ref Fe a, ref Fe b, int bit)
    {
        long mask = -((long)bit);

        Swap(ref a, ref b, mask);
    }

    private static void Swap(ref Fe x, ref Fe y, long mask)
    {
        long t;
        t = (x._l0 ^ y._l0) & mask;
        x._l0 ^= t;
        y._l0 ^= t;
        t = (x._l1 ^ y._l1) & mask;
        x._l1 ^= t;
        y._l1 ^= t;
        t = (x._l2 ^ y._l2) & mask;
        x._l2 ^= t;
        y._l2 ^= t;
        t = (x._l3 ^ y._l3) & mask;
        x._l3 ^= t;
        y._l3 ^= t;
        t = (x._l4 ^ y._l4) & mask;
        x._l4 ^= t;
        y._l4 ^= t;
        t = (x._l5 ^ y._l5) & mask;
        x._l5 ^= t;
        y._l5 ^= t;
        t = (x._l6 ^ y._l6) & mask;
        x._l6 ^= t;
        y._l6 ^= t;
        t = (x._l7 ^ y._l7) & mask;
        x._l7 ^= t;
        y._l7 ^= t;
        t = (x._l8 ^ y._l8) & mask;
        x._l8 ^= t;
        y._l8 ^= t;
        t = (x._l9 ^ y._l9) & mask;
        x._l9 ^= t;
        y._l9 ^= t;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Exponentiation chains
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Inversion: <c>h = f^(-1) (mod p)</c> via Fermat's little theorem
    /// (<c>f^(p-2) mod p</c>). Port of <c>ed25519_ref10.c :: fe25519_invert</c>.
    /// Constant-time fixed exponentiation ladder.
    /// </summary>
    [SuppressMessage("Performance", "IDE0059:Unnecessary assignment of a value", Justification = "Locals are reused via `out`/`in` re-assignment — analyzer false positive on the ported chain.")]
    public static void Invert(out Fe h, in Fe z)
    {
        Sq(out Fe t0, in z);
        Sq(out Fe t1, in t0);
        Sq(out t1, in t1);
        Mul(out t1, in z, in t1);
        Mul(out t0, in t0, in t1);
        Sq(out Fe t2, in t0);
        Mul(out t1, in t1, in t2);
        Sq(out t2, in t1);
        for (int i = 1; i < 5; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t1, in t2, in t1);
        Sq(out t2, in t1);
        for (int i = 1; i < 10; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t2, in t2, in t1);
        Sq(out Fe t3, in t2);
        for (int i = 1; i < 20; ++i)
        {
            Sq(out t3, in t3);
        }

        Mul(out t2, in t3, in t2);
        for (int i = 1; i < 11; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t1, in t2, in t1);
        Sq(out t2, in t1);
        for (int i = 1; i < 50; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t2, in t2, in t1);
        Sq(out t3, in t2);
        for (int i = 1; i < 100; ++i)
        {
            Sq(out t3, in t3);
        }

        Mul(out t2, in t3, in t2);
        for (int i = 1; i < 51; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t1, in t2, in t1);
        for (int i = 1; i < 6; ++i)
        {
            Sq(out t1, in t1);
        }

        Mul(out h, in t1, in t0);
    }

    /// <summary>
    /// Computes <c>h = f^((p-5)/8) = f^(2^252 - 3) (mod p)</c>. Port of
    /// <c>ed25519_ref10.c :: fe25519_pow22523</c>. Used by Ed25519 point decompression
    /// (the square-root of the recoverable x-coordinate, since p ≡ 5 (mod 8)).
    /// </summary>
    [SuppressMessage("Performance", "IDE0059:Unnecessary assignment of a value", Justification = "Locals are reused via `out`/`in` re-assignment — analyzer false positive on the ported chain.")]
    public static void Pow22523(out Fe h, in Fe z)
    {
        Sq(out Fe t0, in z);
        Sq(out Fe t1, in t0);
        Sq(out t1, in t1);
        Mul(out t1, in z, in t1);
        Mul(out t0, in t0, in t1);
        Sq(out t0, in t0);
        Mul(out t0, in t1, in t0);
        Sq(out t1, in t0);
        for (int i = 1; i < 5; ++i)
        {
            Sq(out t1, in t1);
        }

        Mul(out t0, in t1, in t0);
        Sq(out t1, in t0);
        for (int i = 1; i < 10; ++i)
        {
            Sq(out t1, in t1);
        }

        Mul(out t1, in t1, in t0);
        Sq(out Fe t2, in t1);
        for (int i = 1; i < 20; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t1, in t2, in t1);
        for (int i = 1; i < 11; ++i)
        {
            Sq(out t1, in t1);
        }

        Mul(out t0, in t1, in t0);
        Sq(out t1, in t0);
        for (int i = 1; i < 50; ++i)
        {
            Sq(out t1, in t1);
        }

        Mul(out t1, in t1, in t0);
        Sq(out t2, in t1);
        for (int i = 1; i < 100; ++i)
        {
            Sq(out t2, in t2);
        }

        Mul(out t1, in t2, in t1);
        for (int i = 1; i < 51; ++i)
        {
            Sq(out t1, in t1);
        }

        Mul(out t0, in t1, in t0);
        Sq(out t0, in t0);
        Sq(out t0, in t0);
        Mul(out h, in t0, in z);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Small helpers for byte loading (fe_frombytes.c uses these)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>Little-endian 4-byte load from <paramref name="s"/> at the given offset.</summary>
    private static long Load4(ReadOnlySpan<byte> s, int offset)
    {
        return (long)s[offset]
             | ((long)s[offset + 1] << 8)
             | ((long)s[offset + 2] << 16)
             | ((long)s[offset + 3] << 24);
    }
}
