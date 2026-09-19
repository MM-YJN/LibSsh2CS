using System.Security.Cryptography;

namespace LibSsh2CS;

/// <summary>
/// An ECDSA private key parsed from the OpenSSH-format blob. The private
/// scalar (<see cref="Exponent"/>) is a big-endian integer; the public point
/// (<see cref="Point"/>) is a SEC1 uncompressed point
/// (<c>0x04 ‖ X ‖ Y</c>).
/// </summary>
public sealed record SshEcdsaPemKey(
    ECCurve Curve,         // nistP256 / nistP384 / nistP521
    string CurveName,      // "nistp256" / "nistp384" / "nistp521"
    byte[] Point,          // SEC1 uncompressed public point
    byte[] Exponent)       // private scalar (big-endian)
    : SshPemKey
{
    /// <inheritdoc/>
    public override SshKeyType KeyType => SshKeyType.Ecdsa;
}
