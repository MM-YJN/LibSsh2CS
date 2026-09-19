namespace LibSsh2CS;

/// <summary>
/// An RSA private key parsed from the OpenSSH-format blob. The CRT parameters
/// (n, e, d, p, q, coeff) are stored as raw big-endian byte arrays (the SSH
/// wire form); the <c>SshSign</c> path imports them into a BCL
/// <see cref="System.Security.Cryptography.RSA"/> instance via
/// <see cref="System.Security.Cryptography.RSAParameters"/>.
/// </summary>
public sealed record RsaPemKey(
    byte[] Modulus,       // n (big-endian)
    byte[] PublicExponent, // e (big-endian)
    byte[] PrivateExponent, // d (big-endian)
    byte[] Coefficient,    // coeff = q^-1 mod p (big-endian)
    byte[] PrimeP,         // p (big-endian)
    byte[] PrimeQ)        // q (big-endian)
    : SshPemKey
{
    /// <inheritdoc/>
    public override SshKeyType KeyType => SshKeyType.Rsa;
}
