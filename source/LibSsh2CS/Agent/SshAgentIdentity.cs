namespace LibSsh2CS.Agent;

/// <summary>
/// A single SSH identity returned by <see cref="SshAgent.ListIdentitiesAsync"/>.
/// Parity with libssh2's <c>struct libssh2_agent_publickey</c>
/// (<c>libssh2.h:1338-1344</c>) — minus the C <c>magic</c> /
/// <c>node</c> handle fields (which become a list slot in C#).
/// </summary>
/// <remarks>
/// <see cref="Blob"/> is the SSH wire-format public key blob (e.g.
/// <c>[string "ssh-ed25519"][32-byte public point]</c>). Pass it as the
/// <c>publicKeyBlob</c> argument to the
/// <see cref="SshUserAuth.AuthenticateWithPublicKeyAsync(SshSession, string, byte[], PublicKeySignCallback, CancellationToken)"/>
/// overload that accepts a <see cref="PublicKeySignCallback"/>.
/// <see cref="Comment"/> is a human-readable comment from the agent
/// (e.g. <c>"user@host"</c>); it may be empty if the agent does not associate
/// a comment with the key.
/// </remarks>
public sealed record SshAgentIdentity
{
    /// <summary>The SSH wire-format public key blob.</summary>
    public required byte[] Blob { get; init; }

    /// <summary>Human-readable comment (may be empty).</summary>
    public required string Comment { get; init; }
}
