using System.Numerics;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Test-only BigInteger oracle for arithmetic in GF(2^255 - 19). Originally
/// the production field type (<c>source/LibSsh2CS/Crypto/Fe25519.cs</c>); moved
/// here in H.6 when <c>Ed25519.cs</c> was rewritten on the constant-time
/// <c>Fe</c>/<c>Fe25519Ops</c> types and the BigInteger version was no longer
/// on any production path.
/// </summary>
/// <remarks>
/// <para>
/// Used as the cross-check oracle by <c>Fe25519OpsTests</c>,
/// <c>Ge25519OpsTests</c>, and <c>Ge25519ScalarMultTests</c>. The BigInteger
/// math is itself validated by the RFC 7748/8032 known-answer tests
/// (<c>X25519Tests</c>, <c>Ed25519Tests</c>, <c>Ed25519SignTests</c>), so it is
/// a correct reference for the constant-time implementation.
/// </para>
/// <para>
/// <b>Not constant-time.</b> Do not use this type in production code. It lives
/// in the test project for that reason.
/// </para>
/// <para>
/// All encoding is little-endian, per RFC 7748 §5 and RFC 8032 §5.1.2.
/// </para>
/// </remarks>
internal static class Fe25519Oracle
{
    /// <summary>The field prime p = 2^255 - 19.</summary>
    public static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    /// <summary>
    /// Ed25519 curve constant d = -121665/121666 (mod p), per RFC 8032 §5.1.
    /// </summary>
    public static readonly BigInteger D = Mod(-121665 * Invert(121666));

    /// <summary>
    /// sqrt(-1) mod p = 2^((p-1)/4) mod p. Used by Ed25519 point decompression
    /// (RFC 8032 §5.1.3, the p = 5 mod 8 case).
    /// </summary>
    public static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

    /// <summary>
    /// Decodes an unsigned little-endian byte string to a field element. Mirrors
    /// Python's <c>int.from_bytes(b, "little")</c> (always non-negative).
    /// </summary>
    public static BigInteger FromBytesLE(ReadOnlySpan<byte> bytes)
    {
        // Append a zero high byte so two's-complement decoding stays positive
        // even when the most significant input bit is set (e.g. an unmasked
        // 32-byte value whose top byte >= 0x80).
        byte[] buf = new byte[bytes.Length + 1];
        bytes.CopyTo(buf);
        return new BigInteger(buf);
    }

    /// <summary>
    /// Reduces <paramref name="a"/> to the range [0, p). Handles negatives
    /// (e.g. the result of a subtraction) by adding p once.
    /// </summary>
    public static BigInteger Mod(BigInteger a)
    {
        BigInteger r = a % P;
        if (r.Sign < 0)
        {
            r += P;
        }

        return r;
    }

    /// <summary>Computes (a + b) mod p.</summary>
    public static BigInteger Add(BigInteger a, BigInteger b) => Mod(a + b);

    /// <summary>Computes (a - b) mod p.</summary>
    public static BigInteger Sub(BigInteger a, BigInteger b) => Mod(a - b);

    /// <summary>Computes (a * b) mod p.</summary>
    public static BigInteger Mul(BigInteger a, BigInteger b) => Mod(a * b);

    /// <summary>Computes a^2 mod p.</summary>
    public static BigInteger Sqr(BigInteger a) => Mod(a * a);

    /// <summary>Computes a^(-1) mod p = a^(p-2) mod p (Fermat, p prime).</summary>
    public static BigInteger Invert(BigInteger a) => BigInteger.ModPow(a, P - 2, P);

    /// <summary>Computes a^e mod p.</summary>
    public static BigInteger Pow(BigInteger a, BigInteger e) => BigInteger.ModPow(a, e, P);

    /// <summary>
    /// Encodes a field element as exactly 32 little-endian bytes. The value is
    /// reduced mod p first, so the output is the canonical [0, p) representation
    /// (top bit always clear, since p &lt; 2^255).
    /// </summary>
    public static byte[] ToBytesLE(BigInteger value)
    {
        BigInteger v = Mod(value);
        byte[] buf = new byte[32];
        // TryWriteBytes writes the minimal little-endian two's-complement form;
        // the remaining high bytes stay zero (buf is zero-initialized). Since
        // v is in [0, p) and p < 2^255, at most 32 bytes are written.
        _ = v.TryWriteBytes(buf, out int _);
        return buf;
    }
}
