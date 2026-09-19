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

namespace LibSsh2CS.Crypto;

/// <summary>
/// Group-element representations for edwards25519 (the Edwards form of curve25519),
/// used by <see cref="Ge25519Ops"/> and <see cref="Ge25519ScalarMult"/>. Direct ports
/// of the <c>ge25519_p1p1</c> / <c>ge25519_p2</c> / <c>ge25519_p3</c> /
/// <c>ge25519_cached</c> / <c>ge25519_precomp</c> structs in libsodium's
/// <c>crypto_core/ed25519/ref10/ed25519_ref10.h</c>.
/// </summary>
/// <remarks>
/// <para>
/// Field elements use the shared <see cref="Fe"/> type (10 named <c>long</c> limbs,
/// radix-2^25.5). Each group element below is a value type holding its <see cref="Fe"/>
/// components inline — no <c>Fe[]</c>, no heap allocation.
/// </para>
/// <para>
/// <b>Representations</b> (libsodium convention, <c>ed25519_ref10.h:29-41</c>):
/// <list type="bullet">
/// <item><see cref="GeP2"/> (projective): <c>(X:Y:Z)</c> with <c>x=X/Z</c>, <c>y=Y/Z</c>.</item>
/// <item><see cref="GeP3"/> (extended): <c>(X:Y:Z:T)</c> with <c>x=X/Z</c>, <c>y=Y/Z</c>, <c>XY=ZT</c>.</item>
/// <item><see cref="GeP1P1"/> (completed): <c>((X:Z),(Y:T))</c> with <c>x=X/Z</c>, <c>y=Y/T</c>.</item>
/// <item><see cref="GePrecomp"/> (Duif): <c>(y+x, y-x, 2dxy)</c>.</item>
/// <item><see cref="GeCached"/>: <c>(Y+X, Y-X, Z, T2d)</c>.</item>
/// </list>
/// </para>
/// <para>
/// All operations in <see cref="Ge25519Ops"/> are constant-time on secret data:
/// conditional moves/swaps use the sign-extended-mask idiom from <see cref="Fe25519Ops"/>.
/// </para>
/// </remarks>

// edwards25519 group element — completed representation ((X:Z),(Y:T)).
// Port of libsodium's ge25519_p1p1 (ed25519_ref10.h:56-61). The output of every
// point-add/double operation; converted to GeP2/GeP3 via P1P1ToP2/P1P1ToP3.
internal struct GeP1P1
{
    internal Fe _x;
    internal Fe _y;
    internal Fe _z;
    internal Fe _t;
}

// edwards25519 group element — projective representation (X:Y:Z).
// Port of libsodium's ge25519_p2 (ed25519_ref10.h:43-47).
internal struct GeP2
{
    internal Fe _x;
    internal Fe _y;
    internal Fe _z;
}

// edwards25519 group element — extended representation (X:Y:Z:T) with XY=ZT.
// Port of libsodium's ge25519_p3 (ed25519_ref10.h:49-54). The "main" representation:
// points decoded from bytes live here; scalar-multiplication results are GeP3.
internal struct GeP3
{
    internal Fe _x;
    internal Fe _y;
    internal Fe _z;
    internal Fe _t;
}

// edwards25519 group element — Duif representation (y+x, y-x, 2dxy).
// Port of libsodium's ge25519_precomp (ed25519_ref10.h:63-67). Used by the
// basepoint table (32×8 constants) for fixed-base scalar multiplication.
internal struct GePrecomp
{
    internal Fe _yPlusX;
    internal Fe _yMinusX;
    internal Fe _xy2D;
}

// edwards25519 group element — cached representation (Y+X, Y-X, Z, T2d).
// Port of libsodium's ge25519_cached (ed25519_ref10.h:69-74). Used by variable-base
// scalar multiplication (Ge25519ScalarMult.ScalarMult).
internal struct GeCached
{
    internal Fe _yPlusX;
    internal Fe _yMinusX;
    internal Fe _z;
    internal Fe _t2D;
}
