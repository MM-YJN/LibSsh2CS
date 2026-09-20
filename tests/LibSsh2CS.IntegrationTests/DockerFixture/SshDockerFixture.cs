using System.Net.Sockets;

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Static facade for SSH-over-Docker integration tests: exposes the
/// in-container constants (<see cref="TestUser"/>, <see cref="TestPassword"/>,
/// <see cref="Host"/>) and the Docker-reachability gate
/// (<see cref="SkipIfDockerNotAvailable"/>). The build-vs-run split lives
/// in <see cref="SshImageFixtureBase"/> (one built image per variant,
/// shared across tests via its subclass assembly fixtures) and
/// <see cref="SshDockerContainer"/> (a fresh per-test container started
/// from a pre-built image).
/// </summary>
/// <remarks>
/// <para>
/// <b>Architecture.</b> Splitting image build (expensive: apt/apk install,
/// ssh-keygen, user creation) from container start (cheap: forks a new
/// sshd from the image) lets the assembly fixture prepare each requested variant
/// lazily, reuse images across runs, and start a fresh container per test. Each test
/// still gets a fresh sshd process with its own random host port, so tests
/// that mutate server state don't affect each other.
/// </para>
/// <para>
/// <b>Auth methods covered.</b> Password + publickey (ed25519 + rsa, file
/// + memory) + agent are exercised end-to-end against the Alpine
/// with-key image. Keyboard-interactive requires a PAM-linked sshd
/// (Alpine's <c>openssh-server</c> is built without libpam and ignores
/// <c>KbdInteractiveAuthentication yes</c>), so the kbdint test uses the
/// Debian variant. The transport-handshake-only test uses the no-auth
/// variant (auth disabled, no user created).
/// </para>
/// <para>
/// <b>Gating.</b> <see cref="ShouldRun"/> gates the tests — they skip when
/// a reachable Linux container engine is unavailable.
/// <see cref="SshImageFixtureBase.StartContainerAsync"/> calls
/// <see cref="SkipIfDockerNotAvailable"/> internally, so tests that start a
/// container don't need their own skip call. Tests that don't start a
/// container (e.g. the agent tests that only exercise the host-side agent)
/// call <see cref="SkipIfDockerNotAvailable"/> explicitly.
/// </para>
/// <para>
/// <b>Container host keys</b> are baked into the image at build time (via
/// <c>ssh-keygen -A</c> + extra ECDSA-384/521 keygen). Known_hosts tests
/// use <see cref="SshDockerContainer.GetHostKeyAsync"/> to fetch the real
/// key at runtime from the running container.
/// </para>
/// </remarks>
internal static class SshDockerFixture
{
    /// <summary>The test user created in the container.</summary>
    public const string TestUser = "testuser";

    /// <summary>The test user's password.</summary>
    public const string TestPassword = "testpass";

    /// <summary>Container host as seen from the test process (always loopback).</summary>
    public const string Host = "127.0.0.1";

    private static readonly Lazy<string?> s_dockerSkipReason = new(() =>
        DockerPrerequisite.ProbeAsync(DockerPrerequisite.CreateStartInfo(), TimeSpan.FromSeconds(10))
            .GetAwaiter().GetResult());

    /// <summary>True iff Docker reports a reachable Linux container engine.</summary>
    public static bool ShouldRun() => s_dockerSkipReason.Value is null;

    /// <summary>
    /// Skips the current test unless a Linux container engine is reachable.
    /// Image-build and container failures after this check remain failures.
    /// </summary>
    public static void SkipIfDockerNotAvailable()
    {
        if (s_dockerSkipReason.Value is string reason)
        {
            Assert.Skip(reason);
        }
    }

    /// <summary>
    /// Connects to <paramref name="host"/>:<paramref name="port"/>, performs
    /// the handshake via
    /// <see cref="SshSession.HandshakeAsync(Stream, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>,
    /// and returns the unauthenticated-but-handshaked session. Hostkey
    /// verification is skipped (the container's host keys are baked into
    /// the assembly image and not pre-known to the test).
    /// </summary>
    /// <remarks>
    /// The <see cref="TcpClient"/> is intentionally leaked: <see cref="SshSession.DisposeAsync"/>
    /// flushes the pipe but does NOT close the caller-owned socket; the
    /// socket is closed when the <see cref="TcpClient"/> is GC'd or the test
    /// process exits. Acceptable for a short-lived integration test.
    /// </remarks>
    public static async Task<SshSession> ConnectAsync(string host, int port, CancellationToken ct)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

        var session = new SshSession();
        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct)
            .ConfigureAwait(false);
        return session;
    }
}
