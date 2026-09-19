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
/// A field element in GF(2^255 - 19), stored as 10 signed 64-bit limbs in the
/// standard ref10 radix-2^25.5 representation.
/// </summary>
/// <remarks>
/// <para>
/// Ported from libsodium's <c>crypto_core/ed25519/ref10/fe_25_5/</c>. The limbs
/// alternate between 26-bit and 25-bit windows of the field element, in little-endian
/// limb order:
/// </para>
/// <list type="table">
/// <item><term><c>_l0</c></term><description>bits 0–25  (26 bits), multiplier 2^0</description></item>
/// <item><term><c>_l1</c></term><description>bits 26–50 (25 bits), multiplier 2^26</description></item>
/// <item><term><c>_l2</c></term><description>bits 51–76 (26 bits), multiplier 2^51</description></item>
/// <item><term><c>_l3</c></term><description>bits 77–101 (25 bits), multiplier 2^77</description></item>
/// <item><term><c>_l4</c></term><description>bits 102–127 (26 bits), multiplier 2^102</description></item>
/// <item><term><c>_l5</c></term><description>bits 128–152 (25 bits), multiplier 2^128</description></item>
/// <item><term><c>_l6</c></term><description>bits 153–178 (26 bits), multiplier 2^153</description></item>
/// <item><term><c>_l7</c></term><description>bits 179–203 (25 bits), multiplier 2^179</description></item>
/// <item><term><c>_l8</c></term><description>bits 204–229 (26 bits), multiplier 2^204</description></item>
/// <item><term><c>_l9</c></term><description>bits 230–254 (25 bits), multiplier 2^230</description></item>
/// </list>
/// <para>
/// The carry chain in <see cref="Fe25519Ops"/> keeps limbs bounded to roughly
/// <c>[-2^25, 2^25]</c> after each operation. All operations are constant-time:
/// no branch ever depends on a secret-derived value, and conditional moves/swaps
/// use sign-extended bit masks (<c>-((long)bit)</c> => all-zeros or all-ones).
/// </para>
/// </remarks>
internal struct Fe
{
    internal long _l0;
    internal long _l1;
    internal long _l2;
    internal long _l3;
    internal long _l4;
    internal long _l5;
    internal long _l6;
    internal long _l7;
    internal long _l8;
    internal long _l9;
}
