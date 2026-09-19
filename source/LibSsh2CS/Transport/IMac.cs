namespace LibSsh2CS.Transport;

/// <summary>
/// The managed equivalent of libssh2's <c>struct _LIBSSH2_MAC_METHOD</c>
/// (<c>mac.c</c>): an SSH message authentication code. One instance handles every
/// packet in a single direction, keyed once via <see cref="Init"/> and reused —
/// mirroring libssh2's persistent <c>session-&gt;local.mac_abstract</c>.
/// </summary>
/// <remarks>
/// The MAC input is <c>BE32(seqno) ‖ packet</c> (<c>mac.c</c>:
/// <c>seqno</c> is appended first, then the packet bytes). The framing layer
/// decides whether <c>packet</c> is the ciphertext (ETM) or the plaintext
/// (Standard) — this type just computes the HMAC over whatever it is given.
/// </remarks>
internal interface IMac : IDisposable
{
    /// <summary>The SSH algorithm name (e.g. <c>hmac-sha2-256</c>).</summary>
    string Name { get; }

    /// <summary>MAC output length in bytes (20 for SHA1, 32 for SHA256, 64 for SHA512).</summary>
    int MacLen { get; }

    /// <summary>
    /// Encrypt-then-MAC (<c>-etm@openssh.com</c>): the MAC covers the ciphertext
    /// and the length field, verified before decryption. Port of the
    /// <c>etm</c> field on <c>LIBSSH2_MAC_METHOD</c>.
    /// </summary>
    bool IsEtm { get; }

    /// <summary>Keys the MAC. Port of <c>mac_method-&gt;init(session, key)</c>.</summary>
    void Init(ReadOnlySpan<byte> key);

    /// <summary>
    /// Computes the MAC over <c>BE32(seqno) ‖ <paramref name="data"/></c> into
    /// <paramref name="mac"/> (exactly <see cref="MacLen"/> bytes). Port of the
    /// <c>update(seqno) / update(packet) / final()</c> sequence.
    /// </summary>
    void Compute(uint seqno, ReadOnlySpan<byte> data, Span<byte> mac);

    /// <summary>
    /// Verifies <paramref name="mac"/> against a recomputed MAC using a
    /// constant-time comparison (port of <c>_libssh2_mac_verify</c>).
    /// </summary>
    bool Verify(uint seqno, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mac);
}
