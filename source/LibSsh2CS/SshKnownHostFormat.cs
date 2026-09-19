namespace LibSsh2CS;

/// <summary>
/// Hostname encoding format stored alongside each <see cref="SshKnownHostEntry"/>.
/// Mirrors the <c>LIBSSH2_KNOWNHOST_TYPE_MASK</c> (low 16 bits of the C
/// typemask) at <c>libssh2.h:1135-1138</c>.
/// </summary>
/// <remarks>
/// As with <see cref="SshKnownHostKeyType"/>, the C bit-encoded
/// <c>typemask &amp; LIBSSH2_KNOWNHOST_TYPE_MASK</c> is replaced by a named
/// field. The on-disk format dispatches on this value via the leading
/// <c>|1|</c> marker (<c>hostline:832</c>).
/// </remarks>
public enum SshKnownHostFormat
{
    /// <summary>
    /// Plaintext hostname (or comma-separated list, expanded into separate
    /// entries at parse time). Mirrors <c>LIBSSH2_KNOWNHOST_TYPE_PLAIN = 1</c>.
    /// </summary>
    Plain = 1,

    /// <summary>
    /// HMAC-SHA1 hashed hostname: <c>|1|&lt;base64-salt&gt;|&lt;base64-hash&gt;</c>.
    /// Mirrors <c>LIBSSH2_KNOWNHOST_TYPE_SHA1 = 2</c>. The hash is
    /// <c>HMAC-SHA1(salt, hostname)</c>; OpenSSH's <c>ssh-keygen -H</c>
    /// produces this format. <c>Check</c> accepts a plain hostname input and
    /// recomputes the HMAC; a hashed input is rejected (returns
    /// <see cref="SshKnownHostCheckStatus.Mismatch"/>, parity with
    /// <c>knownhost.c:367</c>).
    /// </summary>
    Sha1 = 2,

    /// <summary>
    /// Caller-supplied pre-hashed hostname (no salt; compared by string
    /// equality). Mirrors <c>LIBSSH2_KNOWNHOST_TYPE_CUSTOM = 3</c>. Allows
    /// callers to plug in alternative hashes without library support.
    /// </summary>
    Custom = 3,
}
