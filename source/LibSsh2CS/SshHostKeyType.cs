namespace LibSsh2CS;

/// <summary>
/// Host key algorithm types recognized by libssh2 1.11. Mirrors the
/// <c>LIBSSH2_KNOWNHOST_KEY_*</c> constants in <c>libssh2.h</c>.
/// </summary>
/// <remarks>
/// Wire name strings (registered in <c>hostkey.c</c>):
/// <c>ssh-rsa</c>, <c>rsa-sha2-256</c>, <c>rsa-sha2-512</c>,
/// <c>ecdsa-sha2-nistp256</c>, <c>ecdsa-sha2-nistp384</c>,
/// <c>ecdsa-sha2-nistp521</c>, <c>ssh-ed25519</c>, <c>ssh-dss</c> (deprecated).
/// Certificate variants (<c>*-cert-v01@openssh.com</c>) are deferred.
/// </remarks>
/// <remarks>
/// <b>Numeric identity note</b>: the values
/// follow the <c>KNOWNHOST_KEY_*</c> nibbles (RSA1=1 … ED25519=7), shared
/// with <see cref="SshKnownHostKeyType"/>. They do NOT mirror the separate
/// <c>LIBSSH2_HOSTKEY_TYPE_*</c> enum (libssh2.h:503-509), where every
/// non-Unknown value is one less (RSA=1, ECDSA_256=3, ED25519=6). The port
/// resolves hostkey types by wire name, so the difference is latent — do not
/// cast these values to C constants.
/// </remarks>
public enum SshHostKeyType
{
    /// <summary>Unknown / unrecognized key type.</summary>
    Unknown = 0,

    /// <summary>RSA1 (legacy SSH1) — not used in SSH2.</summary>
    Rsa1 = 1,

    /// <summary><c>ssh-rsa</c> (RSA with SHA-1). Deprecated in OpenSSH 8.2+.</summary>
    SshRsa = 2,

    /// <summary><c>ssh-dss</c> (DSS / DSA). Deprecated.</summary>
    SshDss = 3,

    /// <summary><c>ecdsa-sha2-nistp256</c>.</summary>
    Ecdsa256 = 4,

    /// <summary><c>ecdsa-sha2-nistp384</c>.</summary>
    Ecdsa384 = 5,

    /// <summary><c>ecdsa-sha2-nistp521</c>.</summary>
    Ecdsa521 = 6,

    /// <summary><c>ssh-ed25519</c>.</summary>
    Ed25519 = 7,

    /// <summary><c>rsa-sha2-256</c> (RSA with SHA-256).</summary>
    RsaSha256 = 8,

    /// <summary><c>rsa-sha2-512</c> (RSA with SHA-512).</summary>
    RsaSha512 = 9,
}
