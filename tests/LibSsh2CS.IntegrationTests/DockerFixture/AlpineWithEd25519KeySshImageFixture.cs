using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineWithEd25519KeySshImageFixture as an assembly-wide fixture:
// xUnit v3 constructs one instance before any test in the assembly runs
// (calling InitializeAsync) and disposes it after all tests complete. Test
// classes receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineWithEd25519KeySshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with the test
/// Ed25519 public key (<c>Fixtures/ed25519_plain_key.pub</c>) installed in
/// <c>authorized_keys</c> on first use and retains it across
/// test runs. Used by the Ed25519 publickey
/// auth test and the agent auth test (which both need the Ed25519 key in
/// authorized_keys). Test classes receive it via constructor injection
/// and start a fresh per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class AlpineWithEd25519KeySshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // Same hostkey generation as AlpineNoKey: the negotiation matrix
        // tests don't use this variant, but the extra ECDSA keys are
        // harmless and keep the variants uniform.
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthAlpine);

    /// <summary>
    /// The test Ed25519 public key, loaded from the embedded fixture
    /// resource at build time and baked into the image's
    /// <c>authorized_keys</c>.
    /// </summary>
    protected override string? AuthorizedKey => FixtureLoader.LoadText("ed25519_plain_key.pub");
}
