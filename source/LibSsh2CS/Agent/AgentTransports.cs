using System.Runtime.ExceptionServices;

namespace LibSsh2CS.Agent;

/// <summary>
/// Static registry of available agent transports, following the
/// <c>CipherMethods</c> / <c>MacMethods</c> / <c>CompressionMethods</c>
/// pattern. Today: PuTTY Pageant on Windows and the Unix domain socket
/// everywhere.
/// </summary>
/// <remarks>
/// <para>
/// Backends are tried in registration order until one <b>connects</b> — parity
/// with <c>libssh2_agent_connect</c>'s loop over <c>supported_backends[]</c>
/// (<c>agent.c:815-826</c>), which puts Pageant before the Windows OpenSSH pipe
/// and before Unix. On Windows the order here is Pageant → Unix; on POSIX the
/// Pageant factory reports itself unavailable and only Unix remains.
/// </para>
/// <para>
/// A factory returns <c>null</c> when its backend cannot exist on the current
/// platform (Pageant off Windows). A non-null result does not mean the backend
/// is usable: the candidate is only adopted once
/// <see cref="IAgentTransport.ConnectAsync"/> succeeds, so a Windows machine
/// without a running Pageant still falls through to the Unix socket — and a
/// candidate that fails to connect is disposed before the next one is tried.
/// </para>
/// </remarks>
internal static class AgentTransports
{
    private static readonly Func<IAgentTransport?>[] s_factories =
    [
        static () => PageantAgentTransport.TryCreate(),
        static () => new UnixSocketAgentTransport(),
    ];

    /// <summary>
    /// Returns the factories for the current platform, in preference order.
    /// </summary>
    internal static IReadOnlyList<Func<IAgentTransport?>> GetFactories() => s_factories;

    /// <summary>
    /// Connects the highest-preference backend that answers.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The connected transport; the caller owns it.</returns>
    /// <exception cref="SshException">
    /// Thrown with <see cref="SshErrorCode.AgentProtocol"/> when no backend
    /// could connect, carrying the last failure as its inner exception.
    /// </exception>
    public static async Task<IAgentTransport> ConnectAsync(CancellationToken cancellationToken)
        => await ConnectAsync(s_factories, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Connects the first candidate in <paramref name="factories"/> that
    /// connects successfully, disposing every candidate that does not.
    /// </summary>
    /// <param name="factories">
    /// Candidate factories in preference order. A <c>null</c> result means the
    /// backend is unavailable on this platform and is skipped.
    /// </param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The connected transport; the caller owns it.</returns>
    /// <remarks>
    /// A canceled connect stops the search immediately instead of falling
    /// through: the caller asked to stop, not to try another backend. A
    /// non-cancellation failure falls through, because "Pageant is not running"
    /// and "the socket is missing" are both normal on a machine that has the
    /// other kind of agent.
    /// </remarks>
    internal static async Task<IAgentTransport> ConnectAsync(
        IReadOnlyList<Func<IAgentTransport?>> factories,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(factories);

        Exception? lastFailure = null;

        foreach (Func<IAgentTransport?> factory in factories)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IAgentTransport? candidate = factory();
            if (candidate is null)
            {
                continue;
            }

            Exception? failure = null;
            try
            {
                await candidate.ConnectAsync(cancellationToken).ConfigureAwait(false);
                return candidate;
            }
            catch (Exception ex)
            {
                failure = ex;
            }

            // A backend can fail after it has opened a socket, so a discarded
            // candidate is always released. Failures while releasing it are
            // swallowed: the connect error is what the caller needs to see.
            try
            {
                await candidate.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
            }

            // Cancellation means "stop", not "try the next backend"; any other
            // failure falls through, because "Pageant is not running" and "the
            // socket is missing" are both normal on a machine that has the
            // other kind of agent.
            if (failure is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                ExceptionDispatchInfo.Capture(failure).Throw();
            }

            lastFailure = failure;
        }

        throw lastFailure is null
            ? new SshException(SshErrorCode.AgentProtocol,
                "No SSH agent backend available on this platform")
            : new SshException(SshErrorCode.AgentProtocol,
                "Could not connect to any SSH agent backend", lastFailure);
    }

    /// <summary>
    /// Creates a Unix-domain-socket transport bound to an explicit path. Used
    /// when the caller passes <c>new SshAgent(socketPath)</c> or sets
    /// <see cref="SshAgent.IdentityPath"/>, which both mean "use this socket,
    /// do not auto-discover".
    /// </summary>
    /// <param name="socketPath">The Unix socket path (typically <c>$SSH_AUTH_SOCK</c>).</param>
    public static IAgentTransport Create(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        return new UnixSocketAgentTransport(socketPath);
    }
}
