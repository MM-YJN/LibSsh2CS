namespace LibSsh2CS;

/// <summary>
/// Key-type discriminator stored alongside each <see cref="SshKnownHostEntry"/>.
/// Mirrors the <c>LIBSSH2_KNOWNHOST_KEY_*</c> constants in
/// <c>libssh2.h:1146-1154</c>.
/// </summary>
/// <remarks>
/// <para>
/// Distinct from <see cref="SshHostKeyType"/>: <c>HostKeyType</c> enumerates the
/// algorithms the transport may <em>negotiate</em> during key exchange
/// (including <c>rsa-sha2-256</c>/<c>rsa-sha2-512</c>), whereas
/// <c>KnownHostKeyType</c> enumerates the algorithms that may appear in a
/// known_hosts file. A stored RSA key is always <c>ssh-rsa</c> regardless of
/// which RSA-SHA2 variant signed the handshake — RFC 8332 §3.1 specifies the
/// wire keytype is invariant. <c>rsa-sha2-*</c> therefore has no equivalent
/// here.
/// </para>
/// <para>
/// Numeric values are sequential (1–7, plus <c>Unknown = 0</c>) rather than
/// the C bit-shifted <c>(n &lt;&lt; 18)</c> layout. The C typemask is an API
/// packing convention only — it never appears on the wire, on disk, or in the
/// in-memory representation. The C# port uses named fields on
/// <see cref="SshKnownHostEntry"/> and reconstructs no bitmask.
/// </para>
/// <para>
/// <see cref="Unknown"/> plays the role of the C
/// <c>LIBSSH2_KNOWNHOST_KEY_UNKNOWN = 15&lt;&lt;18</c>: a key whose type name
/// was not recognized at parse time. Per <c>knownhost.c:459</c>, an
/// <c>Unknown</c> entry never matches a <c>Check</c> request, regardless of
/// the key bytes.
/// </para>
/// </remarks>
public enum SshKnownHostKeyType
{
    /// <summary>
    /// Unrecognized key type name at parse time. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_UNKNOWN = 15&lt;&lt;18</c>. Such entries are
    /// stored (so they round-trip through <c>WriteLine</c>) but never match a
    /// <c>Check</c> request — parity with <c>knownhost.c:459</c>'s "never match
    /// on an unknown key type" rule.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// RSA1 (SSH1 legacy). Mirrors <c>LIBSSH2_KNOWNHOST_KEY_RSA1 = 1&lt;&lt;18</c>.
    /// Detected at parse time by a key whose first character is an ASCII digit
    /// (<c>0</c>–<c>9</c>) — see <c>hostline:761-771</c>. SSH1 is dead in
    /// practice (disabled in OpenSSH 7.6+) but the parsing path is preserved
    /// for parity with libssh2 1.11.
    /// </summary>
    Rsa1 = 1,

    /// <summary>
    /// <c>ssh-rsa</c> (RSA with SHA-1). Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_SSHRSA = 2&lt;&lt;18</c>.
    /// </summary>
    SshRsa = 2,

    /// <summary>
    /// <c>ssh-dss</c> (DSS / DSA). Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_SSHDSS = 3&lt;&lt;18</c>. Deprecated; included
    /// for parity with libssh2's <c>LIBSSH2_DSA</c> build.
    /// </summary>
    SshDss = 3,

    /// <summary>
    /// <c>ecdsa-sha2-nistp256</c>. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_ECDSA_256 = 4&lt;&lt;18</c>.
    /// </summary>
    Ecdsa256 = 4,

    /// <summary>
    /// <c>ecdsa-sha2-nistp384</c>. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_ECDSA_384 = 5&lt;&lt;18</c>.
    /// </summary>
    Ecdsa384 = 5,

    /// <summary>
    /// <c>ecdsa-sha2-nistp521</c>. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_ECDSA_521 = 6&lt;&lt;18</c>.
    /// </summary>
    Ecdsa521 = 6,

    /// <summary>
    /// <c>ssh-ed25519</c>. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_KEY_ED25519 = 7&lt;&lt;18</c>.
    /// </summary>
    Ed25519 = 7,
}
