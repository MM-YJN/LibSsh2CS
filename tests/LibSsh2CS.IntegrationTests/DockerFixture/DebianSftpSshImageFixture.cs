using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks DebianSftpSshImageFixture as an assembly-wide fixture: xUnit v3
// constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(DebianSftpSshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds a Debian 12 (bookworm) slim image with
/// the SFTP subsystem enabled (the <c>Subsystem sftp /usr/lib/openssh/sftp-server</c>
/// directive in <c>sshd_config</c>). Used by
/// <see cref="Session.DockerSubsystemTests"/>, which exercises
/// <see cref="SshChannel.SubsystemAsync"/> against a live <c>sftp-server</c>
/// process. Prepared on first use and retained across test runs.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a dedicated variant.</b> <see cref="SshImageFixtureBase.SshdConfigBase"/>
/// overwrites <c>/etc/ssh/sshd_config</c> entirely, so Debian's default
/// <c>Subsystem sftp</c> line (shipped in <c>/etc/ssh/sshd_config</c>) is
/// dropped. Alpine's <c>openssh-server</c> package does not ship
/// <c>sftp-server</c> at all, so the Alpine variants cannot serve SFTP. This
/// variant uses Debian (which ships <c>/usr/lib/openssh/sftp-server</c>) and
/// re-adds the <c>Subsystem</c> directive via <see cref="SshImageSpec.AuthConfig"/>.
/// </para>
/// <para>
/// <b>Auth.</b> Identical to <see cref="DebianNoKeySshImageFixture"/>:
/// password + pubkey + kbdint enabled (PAM-linked sshd). The SFTP test only
/// uses password auth, but the full Debian auth set is harmless and keeps
/// the variant uniform with <see cref="DebianNoKeySshImageFixture"/>.
/// </para>
/// </remarks>
public sealed class DebianSftpSshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <summary>
    /// The Debian auth preamble (same as <see cref="SshImageFixtureBase.SshdConfigAuthDebian"/>)
    /// with the <c>Subsystem sftp</c> directive appended. The
    /// <c>SshImageFixtureBase</c> appends <see cref="SshImageSpec.AuthConfig"/>
    /// after the shared <c>SshdConfigBase</c>, so the <c>Subsystem</c> line
    /// lands in the final <c>sshd_config</c> alongside the auth directives.
    /// </summary>
    private const string SshdConfigSftp =
        SshdConfigAuthDebian +
        "Subsystem sftp /usr/lib/openssh/sftp-server\\n";

    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM debian:12-slim",
        // Same setup as DebianNoKeySshImageFixture: /run/sshd must exist or
        // Debian's sshd refuses to start. The extra ECDSA host keys keep the
        // variant uniform with the Alpine/DebianNoKey set (the SFTP test
        // doesn't pin hostkey algorithms, but the cost is negligible).
        InstallAndKeygen:
            "RUN apt-get update && apt-get install -y --no-install-recommends openssh-server ca-certificates" +
            " && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN useradd -m -s /bin/sh " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigSftp);
}
