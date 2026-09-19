namespace LibSsh2CS;

/// <summary>
/// Result of parsing an OpenSSH-format private key file.
/// </summary>
/// <param name="CipherName">SSH cipher name string (e.g. <c>"none"</c>, <c>"aes256-ctr"</c>).</param>
/// <param name="KdfName">KDF name (e.g. <c>"none"</c>, <c>"bcrypt"</c>).</param>
/// <param name="PublicKeyBlob">Unencrypted SSH wire-format public key blob.</param>
/// <param name="PrivateKeyBlob">Decrypted SSH wire-format private key blob (starts with checkint1 || checkint2 || keytype).</param>
/// <param name="Comment">Key comment (may be empty).</param>
public sealed record OpenSshKey(
    string CipherName,
    string KdfName,
    byte[] PublicKeyBlob,
    byte[] PrivateKeyBlob,
    string Comment);
