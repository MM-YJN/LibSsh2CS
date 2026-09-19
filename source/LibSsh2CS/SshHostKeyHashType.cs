namespace LibSsh2CS;

/// <summary>
/// Host-key fingerprint hash algorithms. Mirrors
/// <c>LIBSSH2_HOSTKEY_HASH_*</c> constants in <c>libssh2.h:498-500</c>.
/// </summary>
/// <remarks>
/// MD5 (<c>LIBSSH2_HOSTKEY_HASH_MD5 = 1</c>) is omitted: MD5 is deprecated for
/// hostkey fingerprinting, no other code in this library uses MD5, and the
/// SHA-1 / SHA-256 fingerprints are the ones <c>libgit2</c>'s SSH transport
/// actually consults. The numeric values of the kept members match the C
/// constants exactly.
/// </remarks>
public enum SshHostKeyHashType
{
    /// <summary>
    /// <c>LIBSSH2_HOSTKEY_HASH_SHA1 = 2</c>. A 20-byte SHA-1 digest over the raw
    /// server host-key blob. SHA-1 is retained for hostkey fingerprinting parity
    /// (the fingerprint is a display/identification value, not a signature).
    /// </summary>
    Sha1 = 2,

    /// <summary>
    /// <c>LIBSSH2_HOSTKEY_HASH_SHA256 = 3</c>. A 32-byte SHA-256 digest over the
    /// raw server host-key blob.
    /// </summary>
    Sha256 = 3,
}
