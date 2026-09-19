using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineNoKeySshImageFixture as an assembly-wide fixture: xUnit v3
// constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineNoKeySshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with no
/// <c>authorized_keys</c> entry (password + pubkey auth enabled) on first use and retains it across
/// test runs. Used by the majority of tests (exec, channel surface, forward,
/// session lifecycle, known-hosts, negotiation matrix, password auth). Test
/// classes receive it via constructor injection (xUnit v3
/// <c>AssemblyFixture</c>) and start a fresh per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class AlpineNoKeySshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // ssh-keygen -A generates one host key per family (rsa, ecdsa
        // nistp256, ed25519). Generate the extra ECDSA curves explicitly
        // so the hostkey-negotiation matrix tests can pin
        // ecdsa-sha2-nistp384 / nistp521 and find a matching host key.
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthAlpine);
}
