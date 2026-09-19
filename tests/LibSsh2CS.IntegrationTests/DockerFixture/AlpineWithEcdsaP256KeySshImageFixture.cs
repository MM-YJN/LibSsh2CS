using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineWithEcdsaP256KeySshImageFixture as an assembly-wide fixture:
// xUnit v3 constructs one instance before any test in the assembly runs
// (calling InitializeAsync) and disposes it after all tests complete. Test
// classes receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineWithEcdsaP256KeySshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with the test
/// ECDSA-P256 public key (<c>Fixtures/ecdsa_p256_plain_key.pub</c>) installed
/// in <c>authorized_keys</c> on first use and retains it across
/// test runs. Used by the ECDSA-P256 publickey
/// auth test (which exercises <see cref="SshSign.SignEcdsa"/> +
/// <see cref="SshEcdsaPemKey"/> + the ECDSA arm of
/// <c>SelectSigningAlgorithm</c> end-to-end against a live OpenSSH server).
/// Test classes receive it via constructor injection and start a fresh
/// per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class AlpineWithEcdsaP256KeySshImageFixture(IMessageSink messageSink)
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
    /// The test ECDSA-P256 public key, loaded from the embedded fixture
    /// resource at build time and baked into the image's
    /// <c>authorized_keys</c>.
    /// </summary>
    protected override string? AuthorizedKey => FixtureLoader.LoadText("ecdsa_p256_plain_key.pub");
}
