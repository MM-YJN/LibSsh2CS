using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineStreamLocalSshImageFixture as an assembly-wide fixture: xUnit
// v3 constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineStreamLocalSshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with
/// <c>socat</c> installed (for Unix-domain socket listeners) on first use and retains it across test runs.
/// Used by <see cref="Session.DockerStreamLocalTests"/>, which exercises
/// <see cref="SshSession.OpenDirectStreamLocalAsync"/> against a live
/// <c>direct-streamlocal@openssh.com</c> channel by starting a
/// <c>socat UNIX-LISTEN</c> listener inside the container and reading the
/// data forwarded through the Unix-socket tunnel.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a dedicated variant.</b> The streamlocal test needs a Unix-domain
/// socket listener inside the container. BusyBox <c>nc</c> (built into
/// Alpine) does not support <c>-U</c> (Unix sockets); <c>socat</c> does.
/// Installing <c>socat</c> in the shared <c>AlpineNoKeySshImageFixture</c>
/// would add a package the other tests don't need; a dedicated variant keeps
/// the shared image lean.
/// </para>
/// <para>
/// <b>Auth.</b> Identical to <see cref="AlpineNoKeySshImageFixture"/>:
/// password + pubkey enabled, PAM disabled (kbdint unavailable on Alpine).
/// The streamlocal test only uses password auth.
/// </para>
/// <para>
/// <b>sshd config.</b> <c>AllowStreamLocalForwarding yes</c> is OpenSSH's
/// compiled-in default, so the <see cref="SshImageFixtureBase.SshdConfigBase"/>
/// (which does not set it) leaves it enabled — no extra directive is needed.
/// </para>
/// </remarks>
public sealed class AlpineStreamLocalSshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // Same hostkey generation as AlpineNoKey plus socat for the
        // Unix-socket listener the streamlocal test starts inside the
        // container.
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server socat && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthAlpine);
}
