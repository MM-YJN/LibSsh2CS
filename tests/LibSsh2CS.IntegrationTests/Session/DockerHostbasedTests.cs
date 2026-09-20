using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration tests for <see cref="SshUserAuth.AuthenticateWithHostBasedAsync"/>:
/// runs a real OpenSSH server in Docker (via the shared
/// <see cref="AlpineHostbasedSshImageFixture"/> assembly fixture, whose
/// sshd config enables <c>HostbasedAuthentication yes</c> +
/// <c>HostbasedUsesNameFromPacketOnly yes</c> and bakes the test Ed25519
/// key into <c>/etc/ssh/ssh_known_hosts</c> under the claimed client
/// hostname) and exercises the full
/// <c>USERAUTH_REQUEST "hostbased"</c> flow end-to-end.
/// </summary>
/// <remarks>
/// <para>
/// <b>Host-based auth flow</b> (RFC 4252 §7): the client sends
/// <c>SSH_MSG_USERAUTH_REQUEST</c> with method <c>"hostbased"</c>,
/// carrying the client's host key + a signature over
/// <c>session_id ‖ USERAUTH_REQUEST</c> + the client hostname + the
/// local username on the client. The server checks the hostname against
/// <c>shosts.equiv</c> / <c>~/.shosts</c>, looks up the host key in
/// <c>ssh_known_hosts</c> / <c>~/.ssh/known_hosts</c>, and verifies the
/// signature. This test lights up
/// <see cref="SshUserAuth.AuthenticateWithHostBasedAsync"/> +
/// <see cref="SshUserAuth.BuildHostbasedRequest"/> + its async state
/// machine (all 0% before this test — ~45 lines).
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerHostbasedTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineHostbasedSshImageFixture _alpineHostbased;

    public DockerHostbasedTests(
        AlpineHostbasedSshImageFixture alpineHostbased,
        ITestOutputHelper testOutputHelper)
    {
        _alpineHostbased = alpineHostbased;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Host-based authentication with the test Ed25519 key succeeds against
    /// a live OpenSSH server configured to accept it. The client claims
    /// hostname <c>"testclient"</c> and local username <c>"testuser"</c>;
    /// the server's <c>shosts.equiv</c> + <c>ssh_known_hosts</c> (baked into
    /// the <see cref="AlpineHostbasedSshImageFixture"/> image) authorize
    /// that combination. Lights up
    /// <see cref="SshUserAuth.AuthenticateWithHostBasedAsync"/> +
    /// <see cref="SshUserAuth.BuildHostbasedRequest"/> (0% → covered).
    /// </summary>
    /// <remarks>
    /// After a successful hostbased auth, the test runs a trivial
    /// <c>echo</c> exec round-trip to prove the session is genuinely
    /// usable (not just that the auth reply was <c>USERAUTH_SUCCESS</c>).
    /// </remarks>
    [Fact]
    public async Task HostbasedAuth_WithEd25519Key_SucceedsAgainstLiveServer()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineHostbased.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);

        // Load the test Ed25519 private key — the same key whose public half
        // is baked into the server's /etc/ssh/ssh_known_hosts under
        // "testclient".
        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        OpenSshKey privateKey = SshPemParser.ParseOpenSshPrivateKey(keyBytes, passphrase: null);

        // Host-based auth: claim hostname="testclient" + localUsername="testuser".
        // The server's shosts.equiv authorizes "testclient testuser" and
        // ssh_known_hosts pins the client's Ed25519 key under "testclient".
        await session.AuthenticateWithHostBasedAsync(
            username: SshDockerFixture.TestUser,
            privateKey: privateKey,
            hostname: AlpineHostbasedSshImageFixture.ClientHostname,
            localUsername: SshDockerFixture.TestUser,
            cancellationToken: ct);

        Assert.True(session.IsAuthenticated);

        // Run a trivial exec to prove the session is genuinely usable after
        // hostbased auth (not just that USERAUTH_SUCCESS was received).
        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("echo hostbased-ok", ct);

        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        Assert.Equal(0, exit);
        Assert.Equal("hostbased-ok\n", System.Text.Encoding.UTF8.GetString(ms.ToArray()));
    }
}
