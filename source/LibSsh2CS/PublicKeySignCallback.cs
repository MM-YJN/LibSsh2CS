namespace LibSsh2CS;

/// <summary>
/// A signing callback for publickey authentication when the private key is
/// held externally (SSH agent, HSM, PKCS#11 token, etc.). The callback receives
/// the pre-computed signed data and the algorithm name the library selected
/// (RSA-SHA2 selection consults <see cref="SshSession.ServerSignatureAlgorithms"/>
/// — parity with <c>_libssh2_key_sign_algorithm</c>). Returns the full SSH
/// signature blob <c>[string algoName][string rawSig]</c> — the same shape
/// <see cref="SshSign.Sign(SshPemKey, byte[], string)"/> returns. Replaces
/// libssh2's <c>LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC</c> (<c>userauth.h</c>).
/// </summary>
/// <param name="signedData">The data to sign: <c>session_id ‖ USERAUTH_REQUEST</c>.</param>
/// <param name="algorithmName">
/// The negotiated algorithm name (e.g. <c>"rsa-sha2-256"</c>, <c>"ssh-ed25519"</c>).
/// For an SSH agent, this is also the algorithm name to send in the
/// <c>SSH2_AGENTC_SIGN_REQUEST</c> message (and the source of the
/// <c>SSH_AGENT_RSA_SHA2_256/512</c> flag derivation).
/// </param>
/// <param name="cancellationToken">Cooperative cancellation.</param>
/// <returns>The full SSH signature blob <c>[string algoName][string rawSig]</c>.</returns>
public delegate Task<byte[]> PublicKeySignCallback(
    byte[] signedData,
    string algorithmName,
    CancellationToken cancellationToken);
