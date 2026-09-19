namespace LibSsh2CS;

/// <summary>
/// The SSH key-type discriminator inferred from the OpenSSH-format private key
/// blob's <c>keytype</c> string. Drives <see cref="SshPemKey.Parse"/> dispatch.
/// Mirrors the <c>type_len</c>/<c>type</c> checks in
/// <c>_libssh2_pub_priv_openssh_keyfilememory</c> (<c>openssl.c:2389</c>).
/// </summary>
/// <remarks>
/// <c>ssh-rsa</c>, <c>rsa-sha2-256</c>, and <c>rsa-sha2-512</c> all parse as
/// <see cref="Rsa"/> — the wire keytype for an RSA private key is always
/// <c>ssh-rsa</c> (RFC 8332 §3.1); the signing algorithm is selected at
/// userauth time based on <c>server-sig-algs</c>, not the keytype string.
/// </remarks>
public enum SshKeyType
{
    /// <summary>Unknown / unrecognized keytype.</summary>
    Unknown = 0,

    /// <summary>
    /// <c>ssh-rsa</c> — an RSA private key. Signs as <c>ssh-rsa</c> (SHA-1),
    /// <c>rsa-sha2-256</c>, or <c>rsa-sha2-512</c> depending on
    /// <c>server-sig-algs</c> (see <c>UserAuth</c>'s RSA-SHA2 selection).
    /// </summary>
    Rsa = 1,

    /// <summary>
    /// <c>ecdsa-sha2-nistp256</c> / <c>ecdsa-sha2-nistp384</c> /
    /// <c>ecdsa-sha2-nistp521</c> — an ECDSA private key. The curve is carried
    /// in the private blob's <c>curve</c> string and cross-checked against the
    /// keytype.
    /// </summary>
    Ecdsa = 2,

    /// <summary><c>ssh-ed25519</c> — an Ed25519 private key.</summary>
    Ed25519 = 3,
}
