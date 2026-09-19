using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineHostbasedSshImageFixture as an assembly-wide fixture: xUnit
// v3 constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineHostbasedSshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image configured for
/// host-based (<c>hostbased</c>) SSH authentication on first use and retains it across
/// test runs. Used by
/// <see cref="Session.DockerHostbasedTests"/>, which exercises
/// <see cref="SshUserAuth.AuthenticateWithHostBasedAsync"/> end-to-end
/// against a live OpenSSH server.
/// </summary>
/// <remarks>
/// <para>
/// <b>Server-side setup.</b> Host-based authentication requires:
/// <list type="bullet">
/// <item><c>HostbasedAuthentication yes</c> + <c>HostbasedUsesNameFromPacketOnly yes</c>
/// (the latter skips the reverse-DNS check on the claimed client hostname,
/// which would fail in a Docker test environment where the connecting IP is
/// the Docker bridge gateway, not the claimed hostname).</item>
/// <item><c>HostbasedAcceptedAlgorithms ssh-ed25519</c> to accept the test
/// key's algorithm.</item>
/// <item>An <c>/etc/ssh/shosts.equiv</c> entry mapping the claimed client
/// hostname + username to an authorized login: <c>testclient testuser</c>.</item>
/// <item>The client's host key in <c>/etc/ssh/ssh_known_hosts</c> under the
/// claimed client hostname, so the server can verify the hostbased
/// signature.</item>
/// </list>
/// </para>
/// <para>
/// <b>Client side.</b> The test calls
/// <see cref="SshUserAuth.AuthenticateWithHostBasedAsync"/> with the test
/// Ed25519 private key, <c>hostname="testclient"</c>, and
/// <c>localUsername="testuser"</c>. The server matches the hostname against
/// <c>shosts.equiv</c>, looks up the key in <c>ssh_known_hosts</c>, and
/// verifies the signature over <c>session_id ‖ USERAUTH_REQUEST</c>.
/// </para>
/// <para>
/// <b>Why a dedicated variant.</b> The hostbased sshd config + shosts +
/// known_hosts setup is specific to this one auth method; baking it into the
/// shared <c>AlpineNoKeySshImageFixture</c> would pollute the image for
/// tests that don't use hostbased auth.
/// </para>
/// </remarks>
public sealed class AlpineHostbasedSshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    // The hostname the client claims in the hostbased USERAUTH_REQUEST.
    // The server's shosts.equiv + ssh_known_hosts must reference this name.
    internal const string ClientHostname = "testclient";

    // Host-based auth config: enable hostbased + skip the reverse-DNS check
    // on the claimed hostname (the Docker bridge gateway IP won't resolve to
    // "testclient") + accept ssh-ed25519 (the test key's algorithm).
    private const string SshdConfigHostbased =
        "PubkeyAuthentication yes\\n" +
        "PasswordAuthentication yes\\n" +
        "UsePAM no\\n" +
        "HostbasedAuthentication yes\\n" +
        "HostbasedUsesNameFromPacketOnly yes\\n" +
        "HostbasedAcceptedAlgorithms ssh-ed25519\\n";

    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server && ssh-keygen -A",
        // Create the test user + .ssh dir, then write shosts.equiv + ssh_known_hosts.
        // The shosts.equiv entry "testclient testuser" authorizes logins from
        // "testclient" for user "testuser". The ssh_known_hosts entry pins
        // the client's Ed25519 host key under "testclient" so the server can
        // verify the hostbased signature.
        CreateUserCmd: BuildCreateUserCmd(),
        AuthConfig: SshdConfigHostbased);

    /// <summary>
    /// Builds the user-creation + shosts + known_hosts Dockerfile commands.
    /// The client's public key (from the embedded fixture) is baked into
    /// <c>/etc/ssh/ssh_known_hosts</c> under <see cref="ClientHostname"/>.
    /// </summary>
    private static string BuildCreateUserCmd()
    {
        string pubKeyLine = FixtureLoader.LoadText("ed25519_plain_key.pub").TrimEnd();
        string knownHostsEntry = ClientHostname + " " + pubKeyLine;
        string b64KnownHosts = Convert.ToBase64String(Encoding.UTF8.GetBytes(knownHostsEntry));
        string b64Shosts = Convert.ToBase64String(Encoding.UTF8.GetBytes(ClientHostname + " " + SshDockerFixture.TestUser + "\n"));

        return
            "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd" +
            " && echo '" + b64Shosts + "' | base64 -d > /etc/ssh/shosts.equiv && chmod 644 /etc/ssh/shosts.equiv" +
            " && echo '" + b64KnownHosts + "' | base64 -d > /etc/ssh/ssh_known_hosts && chmod 644 /etc/ssh/ssh_known_hosts";
    }
}
