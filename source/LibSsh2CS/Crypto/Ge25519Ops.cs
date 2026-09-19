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
/// Point operations on edwards25519 over the constant-time <see cref="Fe"/> field.
/// Direct C# port of libsodium's <c>crypto_core/ed25519/ref10/ed25519_ref10.c</c>
/// point-addition / doubling / decode / encode routines.
/// </summary>
/// <remarks>
/// <para>
/// All operations are constant-time on secret data: branches never depend on
/// secret-derived values; conditional moves use the sign-extended mask idiom
/// from <see cref="Fe25519Ops"/>. <see cref="FromBytes"/> and <see cref="IsOnCurve"/>
/// accept/reject on public encodings and may branch on the result.
/// </para>
/// <para>
/// libsodium C functions replaced (all from <c>ed25519_ref10.c</c> unless noted):
/// <c>ge25519_add</c> (:230), <c>ge25519_sub</c> (:682), <c>ge25519_madd</c> (:380),
/// <c>ge25519_msub</c> (:401), <c>ge25519_p2_dbl</c> (:455), <c>ge25519_p3_dbl</c> (:549),
/// <c>ge25519_p1p1_to_p2</c> (:422), <c>ge25519_p1p1_to_p3</c> (:434),
/// <c>ge25519_p3_to_p2</c> (:523), <c>ge25519_p3_to_cached</c> (:493),
/// <c>ge25519_p3_to_precomp</c> (:502), <c>ge25519_p3_tobytes</c> (:531),
/// <c>ge25519_tobytes</c> (:701), <c>ge25519_frombytes</c> (:294),
/// <c>ge25519_is_on_curve</c> (:1020), the <c>equal</c>/<c>negative</c>/:cmov* helpers.
/// </para>
/// </remarks>
internal static class Ge25519Ops
{
    // ════════════════════════════════════════════════════════════════════════
    // Curve constants — direct ports of fe_25_5/constants.h. The libsodium limb
    // values are already canonical (each limb in [-2^25, 2^25]), so we assign
    // directly without going through FromBytes.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Curve constant d = -121665/121666 (mod p), per RFC 8032 §5.1.
    /// Port of fe_25_5/constants.h::<c>d</c>.
    /// </summary>
    private static readonly Fe s_d = FromLimbs(
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116);

    /// <summary>
    /// 2 * d, port of fe_25_5/constants.h::<c>d2</c>.
    /// </summary>
    private static readonly Fe s_d2 = FromLimbs(
        -21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199);

    /// <summary>
    /// sqrt(-1) mod p, port of fe_25_5/constants.h::<c>sqrtm1</c>.
    /// </summary>
    private static readonly Fe s_sqrtm1 = FromLimbs(
        -32595792, -7943725, 9377950, 3500415, 12389472,
        -272473, -25146209, -2005654, 326686, 11406482);

    private static Fe FromLimbs(long l0, long l1, long l2, long l3, long l4, long l5, long l6, long l7, long l8, long l9)
    {
        Fe h = default;
        h._l0 = l0;
        h._l1 = l1;
        h._l2 = l2;
        h._l3 = l3;
        h._l4 = l4;
        h._l5 = l5;
        h._l6 = l6;
        h._l7 = l7;
        h._l8 = l8;
        h._l9 = l9;
        return h;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Zero-element constructors — ports of ge25519_p2_0 / p3_0 / cached_0 / precomp_0.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sets <paramref name="h"/> to the identity element (0:1:1) in projective
    /// coordinates. Port of <c>ge25519_p2_0</c> (:443-449).
    /// </summary>
    public static void P2Zero(out GeP2 h)
    {
        h = default;
        h._x = Fe25519Ops.Zero();
        h._y = Fe25519Ops.One();
        h._z = Fe25519Ops.One();
    }

    /// <summary>
    /// Sets <paramref name="h"/> to the identity element (0:1:1:0) in extended
    /// coordinates. Port of <c>ge25519_p3_0</c> (:471-478).
    /// </summary>
    public static void P3Zero(out GeP3 h)
    {
        h = default;
        h._x = Fe25519Ops.Zero();
        h._y = Fe25519Ops.One();
        h._z = Fe25519Ops.One();
        h._t = Fe25519Ops.Zero();
    }

    /// <summary>
    /// Sets <paramref name="h"/> to the identity element (1:1:1:0) in cached
    /// coordinates. Port of <c>ge25519_cached_0</c> (:480-487).
    /// </summary>
    public static void CachedZero(out GeCached h)
    {
        h = default;
        h._yPlusX = Fe25519Ops.One();
        h._yMinusX = Fe25519Ops.One();
        h._z = Fe25519Ops.One();
        h._t2D = Fe25519Ops.Zero();
    }

    /// <summary>
    /// Sets <paramref name="h"/> to the identity element (1:1:0) in Duif
    /// precomp coordinates. Port of <c>ge25519_precomp_0</c> (:557-563).
    /// </summary>
    public static void PrecompZero(out GePrecomp h)
    {
        h = default;
        h._yPlusX = Fe25519Ops.One();
        h._yMinusX = Fe25519Ops.One();
        h._xy2D = Fe25519Ops.Zero();
    }

    // ════════════════════════════════════════════════════════════════════════
    // Point addition — ports of ge25519_add / madd / msub / sub.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Computes <c>r = p + q</c> (extended + cached → completed). Port of
    /// <c>ge25519_add</c> (:230-246).
    /// </summary>
    public static void Add(out GeP1P1 r, in GeP3 p, in GeCached q)
    {
        Fe25519Ops.Add(out Fe t0, in p._y, in p._x);
        Fe25519Ops.Sub(out Fe ymx, in p._y, in p._x); // r._y temporarily
        Fe25519Ops.Mul(out Fe rz, in t0, in q._yPlusX); // r._z temporarily
        Fe25519Ops.Mul(out Fe ry, in ymx, in q._yMinusX); // r._y
        Fe25519Ops.Mul(out Fe rt, in q._t2D, in p._t); // r._t
        Fe25519Ops.Mul(out Fe rx, in p._z, in q._z); // r._x temporarily
        Fe25519Ops.Add(out t0, in rx, in rx); // doubled
        Fe25519Ops.Sub(out r._x, in rz, in ry);
        Fe25519Ops.Add(out r._y, in rz, in ry);
        Fe25519Ops.Add(out r._z, in t0, in rt);
        Fe25519Ops.Sub(out r._t, in t0, in rt);
    }

    /// <summary>
    /// Computes <c>r = p - q</c> (extended − cached → completed). Port of
    /// <c>ge25519_sub</c> (:682-698).
    /// </summary>
    public static void Sub(out GeP1P1 r, in GeP3 p, in GeCached q)
    {
        Fe25519Ops.Add(out Fe t0, in p._y, in p._x);
        Fe25519Ops.Sub(out Fe ymx, in p._y, in p._x); // r._y temporarily
        Fe25519Ops.Mul(out Fe rz, in t0, in q._yMinusX); // r._z temporarily
        Fe25519Ops.Mul(out Fe ry, in ymx, in q._yPlusX); // r._y
        Fe25519Ops.Mul(out Fe rt, in q._t2D, in p._t); // r._t
        Fe25519Ops.Mul(out Fe rx, in p._z, in q._z); // r._x temporarily
        Fe25519Ops.Add(out t0, in rx, in rx); // doubled
        Fe25519Ops.Sub(out r._x, in rz, in ry);
        Fe25519Ops.Add(out r._y, in rz, in ry);
        Fe25519Ops.Sub(out r._z, in t0, in rt);
        Fe25519Ops.Add(out r._t, in t0, in rt);
    }

    /// <summary>
    /// Mixed addition: <c>r = p + q</c> (extended + precomp → completed).
    /// Port of <c>ge25519_madd</c> (:380-395). Used by fixed-base scalar mult.
    /// </summary>
    public static void MAdd(out GeP1P1 r, in GeP3 p, in GePrecomp q)
    {
        Fe25519Ops.Add(out Fe t0, in p._y, in p._x);
        Fe25519Ops.Sub(out Fe ymx, in p._y, in p._x); // r._y temporarily
        Fe25519Ops.Mul(out Fe rz, in t0, in q._yPlusX); // r._z temporarily
        Fe25519Ops.Mul(out Fe ry, in ymx, in q._yMinusX); // r._y
        Fe25519Ops.Mul(out Fe rt, in q._xy2D, in p._t); // r._t
        Fe25519Ops.Add(out t0, in p._z, in p._z); // 2*p->Z (p is extended, Z is single)
        Fe25519Ops.Sub(out r._x, in rz, in ry);
        Fe25519Ops.Add(out r._y, in rz, in ry);
        Fe25519Ops.Add(out r._z, in t0, in rt);
        Fe25519Ops.Sub(out r._t, in t0, in rt);
    }

    /// <summary>
    /// Mixed subtraction: <c>r = p - q</c> (extended − precomp → completed).
    /// Port of <c>ge25519_msub</c> (:401-416). Used by fixed-base scalar mult.
    /// </summary>
    public static void MSub(out GeP1P1 r, in GeP3 p, in GePrecomp q)
    {
        Fe25519Ops.Add(out Fe t0, in p._y, in p._x);
        Fe25519Ops.Sub(out Fe ymx, in p._y, in p._x); // r._y temporarily
        Fe25519Ops.Mul(out Fe rz, in t0, in q._yMinusX); // r._z temporarily
        Fe25519Ops.Mul(out Fe ry, in ymx, in q._yPlusX); // r._y
        Fe25519Ops.Mul(out Fe rt, in q._xy2D, in p._t); // r._t
        Fe25519Ops.Add(out t0, in p._z, in p._z); // 2*p->Z
        Fe25519Ops.Sub(out r._x, in rz, in ry);
        Fe25519Ops.Add(out r._y, in rz, in ry);
        Fe25519Ops.Sub(out r._z, in t0, in rt);
        Fe25519Ops.Add(out r._t, in t0, in rt);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Point doubling — ports of ge25519_p2_dbl / p3_dbl.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Computes <c>r = 2*p</c> (projective → completed). Port of
    /// <c>ge25519_p2_dbl</c> (:455-469).
    /// </summary>
    public static void P2Dbl(out GeP1P1 r, in GeP2 p)
    {
        Fe25519Ops.Sq(out Fe rx, in p._x); // r._x
        Fe25519Ops.Sq(out Fe rz, in p._y); // r._z
        Fe25519Ops.Sq2(out Fe rt, in p._z); // r._t (2 * Z^2)
        Fe25519Ops.Add(out Fe ry, in p._x, in p._y); // r._y temporarily
        Fe25519Ops.Sq(out Fe t0, in ry);
        Fe25519Ops.Add(out ry, in rz, in rx);
        Fe25519Ops.Sub(out rz, in rz, in rx);
        Fe25519Ops.Sub(out r._x, in t0, in ry);
        Fe25519Ops.Sub(out r._t, in rt, in rz);
        r._y = ry;
        r._z = rz;
    }

    /// <summary>
    /// Computes <c>r = 2*p</c> (extended → completed) via the projective-doubling
    /// formula. Port of <c>ge25519_p3_dbl</c> (:549-555).
    /// </summary>
    public static void P3Dbl(out GeP1P1 r, in GeP3 p)
    {
        P3ToP2(out GeP2 q, in p);
        P2Dbl(out r, in q);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Representation conversions — ports of p1p1_to_p2 / p1p1_to_p3 / p3_to_p2
    //                                                              / p3_to_cached.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Converts a completed point to projective coordinates. Port of
    /// <c>ge25519_p1p1_to_p2</c> (:422-428).
    /// </summary>
    public static void P1P1ToP2(out GeP2 r, in GeP1P1 p)
    {
        Fe25519Ops.Mul(out r._x, in p._x, in p._t);
        Fe25519Ops.Mul(out r._y, in p._y, in p._z);
        Fe25519Ops.Mul(out r._z, in p._z, in p._t);
    }

    /// <summary>
    /// Converts a completed point to extended coordinates. Port of
    /// <c>ge25519_p1p1_to_p3</c> (:434-441).
    /// </summary>
    public static void P1P1ToP3(out GeP3 r, in GeP1P1 p)
    {
        Fe25519Ops.Mul(out r._x, in p._x, in p._t);
        Fe25519Ops.Mul(out r._y, in p._y, in p._z);
        Fe25519Ops.Mul(out r._z, in p._z, in p._t);
        Fe25519Ops.Mul(out r._t, in p._x, in p._y);
    }

    /// <summary>
    /// Drops the T coordinate (extended → projective). Port of
    /// <c>ge25519_p3_to_p2</c> (:523-529).
    /// </summary>
    public static void P3ToP2(out GeP2 r, in GeP3 p)
    {
        r._x = p._x;
        r._y = p._y;
        r._z = p._z;
    }

    /// <summary>
    /// Converts an extended point to cached form. Port of <c>ge25519_p3_to_cached</c>
    /// (:493-500). Used to set up the lookup table for variable-base scalar mult.
    /// </summary>
    public static void P3ToCached(out GeCached r, in GeP3 p)
    {
        Fe25519Ops.Add(out r._yPlusX, in p._y, in p._x);
        Fe25519Ops.Sub(out r._yMinusX, in p._y, in p._x);
        r._z = p._z;
        Fe25519Ops.Mul(out r._t2D, in p._t, in s_d2);
    }

    /// <summary>
    /// Converts an extended point to Duif precomp form. Port of
    /// <c>ge25519_p3_to_precomp</c> (:502-517). Used to derive basepoint-table
    /// entries; not on any hot path.
    /// </summary>
    public static void P3ToPrecomp(out GePrecomp pi, in GeP3 p)
    {
        Fe25519Ops.Invert(out Fe recip, in p._z);
        Fe25519Ops.Mul(out Fe x, in p._x, in recip);
        Fe25519Ops.Mul(out Fe y, in p._y, in recip);
        Fe25519Ops.Add(out pi._yPlusX, in y, in x);
        Fe25519Ops.Sub(out pi._yMinusX, in y, in x);
        Fe25519Ops.Mul(out Fe xy, in x, in y);
        Fe25519Ops.Mul(out pi._xy2D, in xy, in s_d2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Byte I/O — ports of ge25519_frombytes / p3_tobytes / tobytes.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Decodes a 32-byte Edwards point encoding into extended coordinates.
    /// Port of <c>ge25519_frombytes</c> (:294-329). Constant-time; returns 0 on
    /// success and -1 if the encoding does not correspond to a curve point.
    /// </summary>
    [SuppressMessage("Performance", "IDE0059:Unnecessary assignment of a value", Justification = "Locals are reused via `out`/`in` re-assignment — analyzer false positive on the ported chain.")]
    public static int FromBytes(out GeP3 h, ReadOnlySpan<byte> s)
    {
        if (s.Length != 32)
        {
            // Length precondition violated; emit identity. Caller is expected to
            // range-check before calling; this matches the libsodium contract
            // (caller-supplied buffer is always 32 bytes).
            P3Zero(out h);
            return -1;
        }

        h = default;
        Fe25519Ops.FromBytes(out h._y, s);
        h._z = Fe25519Ops.One();
        Fe25519Ops.Sq(out Fe u, in h._y);
        Fe25519Ops.Mul(out Fe v, in u, in s_d);
        Fe25519Ops.Sub(out u, in u, in h._z); // u = y^2 - 1
        Fe25519Ops.Add(out v, in v, in h._z); // v = d*y^2 + 1

        Fe25519Ops.Mul(out h._x, in u, in v);
        Fe25519Ops.Pow22523(out h._x, in h._x);
        Fe25519Ops.Mul(out h._x, in u, in h._x); // u * ((u*v)^((p-5)/8))

        Fe25519Ops.Sq(out Fe vxx, in h._x);
        Fe25519Ops.Mul(out vxx, in vxx, in v);
        Fe25519Ops.Sub(out Fe mRootCheck, in vxx, in u); // v*x^2 - u
        Fe25519Ops.Add(out Fe pRootCheck, in vxx, in u); // v*x^2 + u
        int hasMRoot = Fe25519Ops.IsZero(in mRootCheck);
        int hasPRoot = Fe25519Ops.IsZero(in pRootCheck);
        Fe25519Ops.Mul(out Fe xSqrtm1, in h._x, in s_sqrtm1); // x*sqrt(-1)
        Fe25519Ops.CMove(ref h._x, in xSqrtm1, 1 - hasMRoot);

        Fe25519Ops.Neg(out Fe negx, in h._x);
        // Constant-time sign selection: pick negative root iff the encoding's sign
        // bit (s[31] bit 7) disagrees with x's current sign. Matches libsodium
        // (:325). `optblocker_u8` in the C source is volatile-zero and is folded
        // out; we omit it here as the C# JIT does not perform the same
        // value-range optimization that the C version guards against.
        int signBit = (s[31] >> 7) & 1;
        int xNeg = Fe25519Ops.IsNegative(in h._x);
        Fe25519Ops.CMove(ref h._x, in negx, xNeg ^ signBit);
        Fe25519Ops.Mul(out h._t, in h._x, in h._y);

        return (hasMRoot | hasPRoot) - 1;
    }

    /// <summary>
    /// Encodes an extended point to its 32-byte compressed form. Port of
    /// <c>ge25519_p3_tobytes</c> (:531-543).
    /// </summary>
    public static void P3ToBytes(Span<byte> s, in GeP3 h)
    {
        Fe25519Ops.Invert(out Fe recip, in h._z);
        Fe25519Ops.Mul(out Fe x, in h._x, in recip);
        Fe25519Ops.Mul(out Fe y, in h._y, in recip);
        Fe25519Ops.Freeze(ref y);
        Fe25519Ops.ToBytes(s, in y);
        s[31] ^= (byte)(Fe25519Ops.IsNegative(in x) << 7);
    }

    /// <summary>
    /// Encodes a projective point to its 32-byte compressed form. Port of
    /// <c>ge25519_tobytes</c> (:701-713). Used after scalar multiplication that
    /// yields a GeP2 result.
    /// </summary>
    public static void P2ToBytes(Span<byte> s, in GeP2 h)
    {
        Fe25519Ops.Invert(out Fe recip, in h._z);
        Fe25519Ops.Mul(out Fe x, in h._x, in recip);
        Fe25519Ops.Mul(out Fe y, in h._y, in recip);
        Fe25519Ops.Freeze(ref y);
        Fe25519Ops.ToBytes(s, in y);
        s[31] ^= (byte)(Fe25519Ops.IsNegative(in x) << 7);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Curve membership — port of ge25519_is_on_curve.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Returns 1 iff <paramref name="p"/> satisfies the curve equation
    /// <c>-x^2 + y^2 = 1 + d*x^2*y^2</c>. Port of <c>ge25519_is_on_curve</c>
    /// (:1020-1043). Constant-time (the result is public).
    /// </summary>
    [SuppressMessage("Performance", "IDE0059:Unnecessary assignment of a value", Justification = "Locals are reused via `out`/`in` re-assignment — analyzer false positive on the ported chain.")]
    public static int IsOnCurve(in GeP3 p)
    {
        Fe25519Ops.Sq(out Fe x2, in p._x);
        Fe25519Ops.Sq(out Fe y2, in p._y);
        Fe25519Ops.Sq(out Fe z2, in p._z);
        Fe25519Ops.Sub(out Fe t0, in y2, in x2);
        Fe25519Ops.Mul(out t0, in t0, in z2);

        Fe25519Ops.Mul(out Fe t1, in x2, in y2);
        Fe25519Ops.Mul(out t1, in t1, in s_d);
        Fe25519Ops.Sq(out Fe z4, in z2);
        Fe25519Ops.Add(out t1, in t1, in z4);
        Fe25519Ops.Sub(out t0, in t0, in t1);

        return Fe25519Ops.IsZero(in t0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Constant-time helpers — ports of equal / negative / cmov / cmov8.
    // These are the building blocks for the radix-16 lookup in scalar mult.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Constant-time equality test on signed bytes. Returns 1 iff <paramref name="b"/>
    /// equals <paramref name="c"/>, else 0. Port of libsodium's <c>equal</c>
    /// (:565-585); the C shift-by-29 idiom was a uint32 narrowing workaround and
    /// is replaced here by the equivalent sign-extended shift-by-31.
    /// </summary>
    private static int Equal(sbyte b, sbyte c)
    {
        int x = (b ^ c) & 0xFF;
        // x is 0 iff b == c. (x-1) is -1 (all bits set) iff x == 0, else [0, 254].
        // Arithmetic >> 31 sign-extends; & 1 extracts the result bit.
        return ((x - 1) >> 31) & 1;
    }

    /// <summary>
    /// Constant-time sign test on a signed byte. Returns 1 iff
    /// <paramref name="b"/> is negative (sign bit set), else 0. Port of
    /// libsodium's <c>negative</c> (:587-601).
    /// </summary>
    private static int Negative(sbyte b) => (b >> 7) & 1;

    /// <summary>
    /// Conditional move of an entire precomp point. Port of <c>ge25519_cmov</c>
    /// (:603-609).
    /// </summary>
    public static void CMovePrecomp(ref GePrecomp t, in GePrecomp u, int b)
    {
        Fe25519Ops.CMove(ref t._yPlusX, in u._yPlusX, b);
        Fe25519Ops.CMove(ref t._yMinusX, in u._yMinusX, b);
        Fe25519Ops.CMove(ref t._xy2D, in u._xy2D, b);
    }

    /// <summary>
    /// Constant-time 8-way select over a precomp lookup table. Sets
    /// <paramref name="t"/> to <c>±<paramref name="b"/></c>-th element of
    /// <paramref name="precomp"/> (with sign flip if negative). Port of
    /// <c>ge25519_cmov8</c> (:620-640).
    /// </summary>
    public static void CMove8Precomp(out GePrecomp t, ReadOnlySpan<GePrecomp> precomp, sbyte b)
    {
        int bneg = Negative(b);
        // Absolute value via sign-extended mask: babs = b - (-bneg & b) * 2.
        int babs = b - ((-bneg & b) * 2);

        PrecompZero(out t);
        // Make a local copy of `t` so CMovePrecomp can take it by ref. C# does
        // not allow `ref` on an `out` param directly across method calls.
        GePrecomp tt = t;
        CMovePrecomp(ref tt, in precomp[0], Equal((sbyte)babs, 1));
        CMovePrecomp(ref tt, in precomp[1], Equal((sbyte)babs, 2));
        CMovePrecomp(ref tt, in precomp[2], Equal((sbyte)babs, 3));
        CMovePrecomp(ref tt, in precomp[3], Equal((sbyte)babs, 4));
        CMovePrecomp(ref tt, in precomp[4], Equal((sbyte)babs, 5));
        CMovePrecomp(ref tt, in precomp[5], Equal((sbyte)babs, 6));
        CMovePrecomp(ref tt, in precomp[6], Equal((sbyte)babs, 7));
        CMovePrecomp(ref tt, in precomp[7], Equal((sbyte)babs, 8));

        // Negation: swap yplusx ↔ yminusx, negate xy2d.
        GePrecomp minust = default;
        minust._yPlusX = tt._yMinusX;
        minust._yMinusX = tt._yPlusX;
        Fe25519Ops.Neg(out minust._xy2D, in tt._xy2D);
        CMovePrecomp(ref tt, in minust, bneg);
        t = tt;
    }

    /// <summary>
    /// Conditional move of an entire cached point. Port of <c>ge25519_cmov_cached</c>
    /// (:611-618).
    /// </summary>
    public static void CMoveCached(ref GeCached t, in GeCached u, int b)
    {
        Fe25519Ops.CMove(ref t._yPlusX, in u._yPlusX, b);
        Fe25519Ops.CMove(ref t._yMinusX, in u._yMinusX, b);
        Fe25519Ops.CMove(ref t._z, in u._z, b);
        Fe25519Ops.CMove(ref t._t2D, in u._t2D, b);
    }

    /// <summary>
    /// Constant-time 8-way select over a cached lookup table. Port of
    /// <c>ge25519_cmov8_cached</c> (:655-676). Used by variable-base scalar mult.
    /// </summary>
    public static void CMove8Cached(out GeCached t, ReadOnlySpan<GeCached> cached, sbyte b)
    {
        int bneg = Negative(b);
        int babs = b - ((-bneg & b) * 2);

        CachedZero(out t);
        GeCached tt = t;
        CMoveCached(ref tt, in cached[0], Equal((sbyte)babs, 1));
        CMoveCached(ref tt, in cached[1], Equal((sbyte)babs, 2));
        CMoveCached(ref tt, in cached[2], Equal((sbyte)babs, 3));
        CMoveCached(ref tt, in cached[3], Equal((sbyte)babs, 4));
        CMoveCached(ref tt, in cached[4], Equal((sbyte)babs, 5));
        CMoveCached(ref tt, in cached[5], Equal((sbyte)babs, 6));
        CMoveCached(ref tt, in cached[6], Equal((sbyte)babs, 7));
        CMoveCached(ref tt, in cached[7], Equal((sbyte)babs, 8));

        // Negation: swap YplusX ↔ YminusX, keep Z, negate T2d.
        GeCached minust = default;
        minust._yPlusX = tt._yMinusX;
        minust._yMinusX = tt._yPlusX;
        minust._z = tt._z;
        Fe25519Ops.Neg(out minust._t2D, in tt._t2D);
        CMoveCached(ref tt, in minust, bneg);
        t = tt;
    }
}
