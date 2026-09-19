using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks DebianNoKeySshImageFixture as an assembly-wide fixture: xUnit v3
// constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(DebianNoKeySshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Debian 12 (bookworm) slim image
/// with a PAM-linked sshd (no <c>authorized_keys</c> entry) on first use and retains it across test runs.
/// Used by the keyboard-interactive auth test, which requires
/// <c>pam_unix.so</c> to drive the <c>USERAUTH_INFO_REQUEST</c> challenge
/// (Alpine's <c>openssh-server</c> is built without libpam and ignores
/// <c>KbdInteractiveAuthentication yes</c>). Test classes receive it via
/// constructor injection and start a fresh per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class DebianNoKeySshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM debian:12-slim",
        // /run/sshd must exist or Debian's sshd refuses to start with
        // "Missing privilege separation directory: /run/sshd". Same ECDSA
        // host-key generation as Alpine for the negotiation matrix.
        InstallAndKeygen:
            "RUN apt-get update && apt-get install -y --no-install-recommends openssh-server ca-certificates" +
            " && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        // Debian uses `useradd`; Alpine uses BusyBox `adduser -D`.
        CreateUserCmd: "RUN useradd -m -s /bin/sh " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthDebian);
}
