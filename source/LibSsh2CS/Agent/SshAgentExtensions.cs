namespace LibSsh2CS.Agent;

/// <summary>
/// Extension methods on <see cref="SshAgent"/> that wire the agent's
/// <see cref="SshAgent.SignAsync"/> into the publickey authentication flow on
/// <see cref="SshSession"/>. Mirrors <c>libssh2_agent_userauth</c>
/// (<c>agent.c:888-909</c>) — delegating to <c>_libssh2_userauth_publickey</c>
/// with an agent-backed sign callback.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a wrapper, not a separate auth method.</b> Uses the generic sign-callback overload of
/// <see cref="SshUserAuth.AuthenticateWithPublicKeyAsync(SshSession, string, byte[], PublicKeySignCallback, CancellationToken)"/>:
/// <c>(session, username, publicKeyBlob, signAsync, ct)</c>. The agent just
/// supplies a <see cref="PublicKeySignCallback"/> that forwards to its own
/// <see cref="SshAgent.SignAsync"/>. No new auth infrastructure is needed.
/// </para>
/// <para>
/// <b>Algorithm-name handling.</b> The signing algorithm is selected by
/// <see cref="SshUserAuth.SelectSigningAlgorithm(SshSession, byte[])"/> (RSA-SHA2
/// selection consults <see cref="SshSession.ServerSignatureAlgorithms"/> —
/// parity with <c>_libssh2_key_sign_algorithm</c>). The selected name is
/// passed to the callback at sign time, then mapped to
/// <see cref="SshAgentSignFlags"/> here:
/// <list type="bullet">
///   <item><c>"rsa-sha2-256"</c> → <see cref="SshAgentSignFlags.RsaSha256"/></item>
///   <item><c>"rsa-sha2-512"</c> → <see cref="SshAgentSignFlags.RsaSha512"/></item>
///   <item>otherwise → <see cref="SshAgentSignFlags.None"/></item>
/// </list>
/// This mirrors <c>agent_sign</c>'s flag-derivation switch
/// (<c>agent.c:488-503</c>).
/// </para>
/// <para>
/// <b>Algorithm-name verification.</b> The agent's sign response includes the
/// signing-method string; libssh2 verifies it matches the request
/// (<c>agent.c:541-555</c>). LibSsh2CS trusts the agent to return a correct
/// sig blob and surfaces it directly to the userauth flow — the SSH server
/// validates the signature server-side. A mismatch surfaces as
/// <see cref="SshErrorCode.PublicKeyUnverified"/> at the USERAUTH_REQUEST
/// step, not here.
/// </para>
/// </remarks>
public static class SshAgentExtensions
{
    /// <summary>
    /// Authenticates <paramref name="session"/> for <paramref name="username"/>
    /// using a loaded agent identity. The agent performs the signing; the
    /// publickey auth packets are built by <see cref="SshUserAuth"/>.
    /// </summary>
    /// <param name="agent">The connected SSH agent.</param>
    /// <param name="session">A handshaked SSH session (not yet authenticated).</param>
    /// <param name="username">The SSH username.</param>
    /// <param name="identity">
    /// An identity returned by <see cref="SshAgent.ListIdentitiesAsync"/>. Only
    /// the <see cref="SshAgentIdentity.Blob"/> field is used.
    /// </param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public static Task AuthenticateWithIdentityAsync(
        this SshAgent agent,
        SshSession session,
        string username,
        SshAgentIdentity identity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(identity);

        // Bind (agent, identity) into a closure; agent.Identity is consulted at
        // sign time. The algorithm name comes from the callback's `algoName`
        // argument (computed by UserAuth via SelectSigningAlgorithm), NOT from
        // a pre-computed value here.
        async Task<byte[]> SignAsync(byte[] data, string algorithmName, CancellationToken ct)
        {
            SshAgentSignFlags flags = AlgorithmNameToFlags(algorithmName);
            return await agent.SignAsync(identity, data, flags, ct).ConfigureAwait(false);
        }

        return session.AuthenticateWithPublicKeyAsync(
            username,
            identity.Blob,
            SignAsync,
            cancellationToken);
    }

    /// <summary>
    /// Maps an SSH signing algorithm name to agent sign-request flags. Parity
    /// with <c>agent_sign</c>'s flag-derivation logic
    /// (<c>agent.c:488-503</c>): the agent picks the signature algorithm
    /// based on the key type unless a flag is set; for RSA, we hint SHA-2.
    /// Non-RSA names return <see cref="SshAgentSignFlags.None"/> (the agent picks
    /// Ed25519 / ECDSA itself).
    /// </summary>
    /// <remarks>
    /// Internal so tests can verify the mapping without exercising the auth
    /// flow. The values come straight from
    /// <see cref="SshAgentSignFlags"/>/<see cref="AgentProtocol"/>.
    /// </remarks>
    internal static SshAgentSignFlags AlgorithmNameToFlags(string algorithmName)
    {
        // Strongest-first ordering in case both happen to be in the name
        // (defensive — should never happen).
        if (algorithmName == "rsa-sha2-512")
        {
            return SshAgentSignFlags.RsaSha512;
        }

        if (algorithmName == "rsa-sha2-256")
        {
            return SshAgentSignFlags.RsaSha256;
        }

        // ssh-rsa (SHA-1), ssh-ed25519, ecdsa-sha2-nistp* → no flag. The agent
        // uses the key type's default signature algorithm.
        return SshAgentSignFlags.None;
    }
}
