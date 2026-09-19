namespace LibSsh2CS.Agent;

/// <summary>
/// Flags for an <see cref="SshAgent.SignAsync"/> request. Passed as a 32-bit
/// bitfield in the agent wire message
/// (<c>SSH2_AGENTC_SIGN_REQUEST</c>), instructing the agent which RSA-SHA2
/// variant to use for RSA keys. Ignored for non-RSA keys. Parity with
/// <c>agent.c:107-108</c> (<c>SSH_AGENT_RSA_SHA2_256=2</c>,
/// <c>SSH_AGENT_RSA_SHA2_512=4</c>).
/// </summary>
/// <remarks>
/// The integer values MUST match the agent wire protocol; do not renumber.
/// </remarks>
[Flags]
public enum SshAgentSignFlags
{
    /// <summary>
    /// No flag. The agent picks a default signature algorithm (historically
    /// SHA-1 for RSA; modern agents default to SHA-2 if the key type allows).
    /// Use this when the caller has no preference.
    /// </summary>
    None = 0,

    /// <summary>
    /// Request RSA-SHA2-256 (RFC 8332 §3.1). Equivalent to the agent wire bit
    /// <c>SSH_AGENT_RSA_SHA2_256 = 2</c>.
    /// </summary>
    RsaSha256 = 2,

    /// <summary>
    /// Request RSA-SHA2-512 (RFC 8332 §3.1). Equivalent to the agent wire bit
    /// <c>SSH_AGENT_RSA_SHA2_512 = 4</c>.
    /// </summary>
    RsaSha512 = 4,
}
