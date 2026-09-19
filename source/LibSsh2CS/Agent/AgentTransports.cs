namespace LibSsh2CS.Agent;

/// <summary>
/// Static registry of available agent transports, following the
/// <c>CipherMethods</c> / <c>MacMethods</c> / <c>CompressionMethods</c>
/// pattern. Today: Unix domain socket only. Windows builds gain Pageant and
/// OpenSSH named-pipe entries here, each guarded by an OS check inside the
/// factory.
/// </summary>
/// <remarks>
/// <para>
/// Backends are tried in registration order until one succeeds at
/// <see cref="IAgentTransport.ConnectAsync"/> — parity with
/// <c>libssh2_agent_connect</c>'s loop over <c>supported_backends[]</c>
/// (<c>agent.c:815-826</c>). On Windows the order is Pageant → OpenSSH named
/// pipe; on POSIX the order is Unix only.
/// </para>
/// <para>
/// The factory delegate returns <c>null</c> when the backend is not available
/// on the current platform (e.g. Pageant on Linux). The first non-null
/// transport wins. A non-null return does not guarantee
/// <see cref="IAgentTransport.ConnectAsync"/> will succeed — it only promises
/// the backend could construct itself. The actual connect failure surfaces
/// when <c>ConnectAsync</c> is called.
/// </para>
/// </remarks>
internal static class AgentTransports
{
    // Future Windows entries (do NOT uncomment until the backends ship):
    //   static () => PageantAgentTransport.TryCreate(),
    //   static () => OpenSshNamedPipeAgentTransport.TryCreate(),
    private static readonly Func<IAgentTransport?>[] s_factories =
    [
        static () => new UnixSocketAgentTransport(),
    ];

    /// <summary>
    /// Returns a transport for the current platform. The first non-null factory
    /// wins. Throws <see cref="SshException"/> with
    /// <see cref="SshErrorCode.AgentProtocol"/> if no backend is available
    /// (should not happen on POSIX where the Unix backend is always constructible).
    /// </summary>
    public static IAgentTransport Create()
    {
        foreach (Func<IAgentTransport?> factory in s_factories)
        {
            IAgentTransport? t = factory();
            if (t is not null)
            {
                return t;
            }
        }

        throw new SshException(SshErrorCode.AgentProtocol,
            "No SSH agent backend available on this platform");
    }

    /// <summary>
    /// Returns a Unix-domain-socket transport bound to an explicit path. Used
    /// when the caller passes <c>new SshAgent(socketPath)</c> or sets
    /// <see cref="SshAgent.IdentityPath"/>. The path is honored at
    /// <see cref="UnixSocketAgentTransport.ConnectAsync"/> time.
    /// </summary>
    public static IAgentTransport Create(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        return new UnixSocketAgentTransport(socketPath);
    }
}
