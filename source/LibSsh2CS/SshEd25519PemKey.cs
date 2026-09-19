namespace LibSsh2CS;

/// <summary>
/// An Ed25519 private key parsed from the OpenSSH-format blob. The
/// <see cref="Seed"/> is the 32-byte RFC 8032 private-key seed (first half of
/// the OpenSSH 64-byte private blob); <see cref="PublicKey"/> is the matching
/// 32-byte encoded public point.
/// </summary>
public sealed record SshEd25519PemKey(
    byte[] Seed,           // 32-byte RFC 8032 private-key seed
    byte[] PublicKey)     // 32-byte encoded public point A
    : SshPemKey
{
    /// <inheritdoc/>
    public override SshKeyType KeyType => SshKeyType.Ed25519;
}
