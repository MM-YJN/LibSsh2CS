// Translated from libssh2 src/chacha.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * chacha-merged.c version 20080118
 * D. J. Bernstein
 * Public domain.
 * Copyright not intended 2024.
 *
 * SPDX-License-Identifier: SAX-PD-2.0
 */

using System.Buffers.Binary;

namespace LibSsh2CS.Crypto;

/// <summary>
/// Raw ChaCha20 stream cipher — 1:1 port of libssh2 <c>chacha.c</c>
/// (D. J. Bernstein's original, OpenBSD <c>chacha-merged.c</c> 20080118).
/// </summary>
/// <remarks>
/// <para>
/// This is the <b>Bernstein original</b> variant: an 8-byte nonce plus an
/// 8-byte counter, both little-endian loaded into <c>input[12..15]</c>. It is
/// <b>not</b> RFC 8439's IETF construction (4-byte counter + 12-byte nonce), so
/// no RFC 8439 keystream vector reproduces under this layout. The known-answer
/// test in <c>ChaCha20Tests</c> is a golden captured from the upstream
/// <c>chacha.c</c> itself (see <c>generate-goldens.sh</c>).
/// </para>
/// <para>
/// SSH uses this primitive only through the two-key AEAD in
/// <see cref="ChaChaPolySsh"/>; it is never used standalone on the wire. The
/// BCL <c>ChaCha20Poly1305</c> type is unusable here both because it is a
/// single-key AEAD (SSH splits the 64-byte key into main+header) and because
/// its nonce is the incompatible IETF 96-bit layout.
/// </para>
/// <para>
/// libssh2 C functions replaced: <c>chacha_keysetup</c> →
/// <see cref="KeySetup"/>, <c>chacha_ivsetup</c> → <see cref="IvSetup(ReadOnlySpan{byte})"/>,
/// <c>chacha_encrypt_bytes</c> → <see cref="EncryptBytes"/>. The mutable
/// <c>chacha_ctx.input[16]</c> state is this instance's <c>_input</c> field.
/// </para>
/// </remarks>
internal sealed class ChaCha20
{
    /// <summary>The ChaCha20 block size in bytes (16 × 32-bit words).</summary>
    public const int BlockSize = 64;

    // Mirrors C `struct chacha_ctx { u_int input[16]; }`. Mutable across keysetup
    // / ivsetup / encrypt_bytes. input[12..13] is the counter, input[14..15] the
    // nonce (both LE-loaded by IvSetup).
    private readonly uint[] _input = new uint[16];

    /// <summary>
    /// Loads the key (256-bit recommended) and the "expand 32-byte k" constants
    /// into the state. Port of <c>chacha_keysetup</c>.
    /// </summary>
    public void KeySetup(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("key must be exactly 32 bytes (256-bit)", nameof(key));
        }

        // The "expand 32-byte k" constant, little-endian per word:
        //   "expa" 0x61707865, "nd 3" 0x3320646e, "2-by" 0x79622d32, "te k" 0x6b206574.
        _input[0] = 0x61707865;
        _input[1] = 0x3320646e;
        _input[2] = 0x79622d32;
        _input[3] = 0x6b206574;

        _input[4] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
        _input[5] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
        _input[6] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
        _input[7] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));
        _input[8] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
        _input[9] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
        _input[10] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
        _input[11] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));
    }

    /// <summary>
    /// Sets the 8-byte nonce (<paramref name="iv"/>) and zeroes the counter
    /// (input[12..13]). Port of <c>chacha_ivsetup(x, iv, NULL)</c>.
    /// </summary>
    public void IvSetup(ReadOnlySpan<byte> iv)
        => IvSetupCore(iv, setCounter: false, default);

    /// <summary>
    /// Sets the 8-byte nonce (<paramref name="iv"/>) and the 8-byte initial
    /// <paramref name="counter"/>. Port of <c>chacha_ivsetup(x, iv, counter)</c>.
    /// </summary>
    public void IvSetup(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> counter)
        => IvSetupCore(iv, setCounter: true, counter);

    private void IvSetupCore(ReadOnlySpan<byte> iv, bool setCounter, ReadOnlySpan<byte> counter)
    {
        if (iv.Length != 8)
        {
            throw new ArgumentException("iv must be exactly 8 bytes", nameof(iv));
        }

        if (setCounter)
        {
            if (counter.Length != 8)
            {
                throw new ArgumentException("counter must be exactly 8 bytes", nameof(counter));
            }

            _input[12] = BinaryPrimitives.ReadUInt32LittleEndian(counter.Slice(0, 4));
            _input[13] = BinaryPrimitives.ReadUInt32LittleEndian(counter.Slice(4, 4));
        }
        else
        {
            _input[12] = 0;
            _input[13] = 0;
        }

        _input[14] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(0, 4));
        _input[15] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(4, 4));
    }

    /// <summary>
    /// XORs <paramref name="message"/> with the ChaCha20 keystream into
    /// <paramref name="cipher"/>. <paramref name="cipher"/> may equal
    /// <paramref name="message"/> (in-place encryption). Port of
    /// <c>chacha_encrypt_bytes</c>; the 20-round permutation, counter increment,
    /// and partial-final-block handling all mirror the C line-for-line.
    /// </summary>
    public void EncryptBytes(ReadOnlySpan<byte> message, Span<byte> cipher)
    {
        if (cipher.Length < message.Length)
        {
            throw new ArgumentException("cipher buffer is smaller than message", nameof(cipher));
        }

        if (message.Length == 0)
        {
            return;
        }

        unchecked
        {
            // j12/j13 are the only state mutated per block (the counter); they
            // are local here and persisted back into _input at the end. The
            // constant words (input[0..11] and the nonce input[14..15]) are read
            // fresh by EncryptBlock — they do not change during this call.
            uint j12 = _input[12];
            uint j13 = _input[13];

            int bytes = message.Length;
            int off = 0;

            // Full 64-byte blocks.
            while (bytes > 64)
            {
                EncryptBlock(message.Slice(off, 64), cipher.Slice(off, 64), ref j12, ref j13);
                off += 64;
                bytes -= 64;
            }

            // Final block (1..64 bytes). The C copies a short tail into a 64-byte
            // scratch, encrypts in place, then copies only `bytes` out. Passing
            // the same scratch as message and cipher to EncryptBlock is safe: it
            // reads all 16 input words into locals before writing any output word.
            Span<byte> tmp = stackalloc byte[64];
            message.Slice(off, bytes).CopyTo(tmp);
            if (bytes < 64)
            {
                tmp.Slice(bytes).Clear();
            }

            EncryptBlock(tmp, tmp, ref j12, ref j13);
            tmp.Slice(0, bytes).CopyTo(cipher.Slice(off, bytes));

            // Persist the advanced counter (chacha.c does input[12] = j12 ...).
            _input[12] = j12;
            _input[13] = j13;
        }
    }

    // One 64-byte ChaCha20 block: snapshot the state, run the 20-round
    // permutation, add the state back, XOR with the message, write the cipher,
    // then advance the counter (j12, j13 — passed by ref). Mirrors the body of
    // chacha.c's per-iteration block.
    private void EncryptBlock(ReadOnlySpan<byte> m, Span<byte> c, ref uint j12, ref uint j13)
    {
        unchecked
        {
            uint j0 = _input[0];
            uint j1 = _input[1];
            uint j2 = _input[2];
            uint j3 = _input[3];
            uint j4 = _input[4];
            uint j5 = _input[5];
            uint j6 = _input[6];
            uint j7 = _input[7];
            uint j8 = _input[8];
            uint j9 = _input[9];
            uint j10 = _input[10];
            uint j11 = _input[11];
            uint j14 = _input[14];
            uint j15 = _input[15];

            uint x0 = j0;
            uint x1 = j1;
            uint x2 = j2;
            uint x3 = j3;
            uint x4 = j4;
            uint x5 = j5;
            uint x6 = j6;
            uint x7 = j7;
            uint x8 = j8;
            uint x9 = j9;
            uint x10 = j10;
            uint x11 = j11;
            uint x12 = j12;
            uint x13 = j13;
            uint x14 = j14;
            uint x15 = j15;

            // 20 rounds = 10 double-rounds; identical column/diagonal order to
            // chacha.c.
            for (int i = 20; i > 0; i -= 2)
            {
                QuarterRound(ref x0, ref x4, ref x8, ref x12);
                QuarterRound(ref x1, ref x5, ref x9, ref x13);
                QuarterRound(ref x2, ref x6, ref x10, ref x14);
                QuarterRound(ref x3, ref x7, ref x11, ref x15);
                QuarterRound(ref x0, ref x5, ref x10, ref x15);
                QuarterRound(ref x1, ref x6, ref x11, ref x12);
                QuarterRound(ref x2, ref x7, ref x8, ref x13);
                QuarterRound(ref x3, ref x4, ref x9, ref x14);
            }

            x0 += j0;
            x1 += j1;
            x2 += j2;
            x3 += j3;
            x4 += j4;
            x5 += j5;
            x6 += j6;
            x7 += j7;
            x8 += j8;
            x9 += j9;
            x10 += j10;
            x11 += j11;
            x12 += j12;
            x13 += j13;
            x14 += j14;
            x15 += j15;

            x0 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(0, 4));
            x1 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(4, 4));
            x2 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(8, 4));
            x3 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(12, 4));
            x4 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(16, 4));
            x5 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(20, 4));
            x6 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(24, 4));
            x7 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(28, 4));
            x8 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(32, 4));
            x9 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(36, 4));
            x10 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(40, 4));
            x11 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(44, 4));
            x12 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(48, 4));
            x13 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(52, 4));
            x14 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(56, 4));
            x15 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(60, 4));

            // j12 = PLUSONE(j12); if(!j12) j13 = PLUSONE(j13);
            j12++;
            if (j12 == 0)
            {
                j13++;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(0, 4), x0);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(4, 4), x1);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(8, 4), x2);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(12, 4), x3);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(16, 4), x4);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(20, 4), x5);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(24, 4), x6);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(28, 4), x7);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(32, 4), x8);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(36, 4), x9);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(40, 4), x10);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(44, 4), x11);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(48, 4), x12);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(52, 4), x13);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(56, 4), x14);
            BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(60, 4), x15);
        }
    }

    // The chacha.c QUARTERROUND macro: a = PLUS(a,b); d = ROTATE(XOR(d,a),16);
    // c = PLUS(c,d); b = ROTATE(XOR(b,c),12); a = PLUS(a,b); d = ROTATE(XOR(d,a),8);
    // c = PLUS(c,d); b = ROTATE(XOR(b,c),7). uint wraps mod 2^32 (unchecked ctx).
    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        unchecked
        {
            a += b;
            d = RotateLeft(d ^ a, 16);
            c += d;
            b = RotateLeft(b ^ c, 12);
            a += b;
            d = RotateLeft(d ^ a, 8);
            c += d;
            b = RotateLeft(b ^ c, 7);
        }
    }

    // ROTL32(v, n) = U32V(v << n) | (v >> (32 - n)). n is always in 1..31 here.
    private static uint RotateLeft(uint v, int n) => unchecked((v << n) | (v >> (32 - n)));
}
