using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineWithEd25519EncKeySshImageFixture as an assembly-wide fixture:
// xUnit v3 constructs one instance before any test in the assembly runs
// (calling InitializeAsync) and disposes it after all tests complete. Test
// classes receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineWithEd25519EncKeySshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with the test
/// Ed25519 public key (<c>Fixtures/ed25519_enc_key.pub</c>) installed in
/// <c>authorized_keys</c> on first use and retains it across
/// test runs. Used by the bcrypt-encrypted Ed25519
/// publickey auth test: the encrypted private key
/// (<c>Fixtures/ed25519_enc_key</c>, aes256-ctr + bcrypt, passphrase
/// <c>"test123"</c>) is a DIFFERENT key pair from <c>ed25519_plain_key</c>,
/// so it needs its own authorized_keys entry. Test classes receive it via
/// constructor injection and start a fresh per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class AlpineWithEd25519EncKeySshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // Same hostkey generation as AlpineWithEd25519Key: the extra ECDSA
        // keys are harmless and keep the variants uniform.
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthAlpine);

    /// <summary>
    /// The test Ed25519 public key whose private counterpart is the
    /// bcrypt-encrypted <c>ed25519_enc_key</c> fixture, loaded from the
    /// embedded resource at build time and baked into the image's
    /// <c>authorized_keys</c>.
    /// </summary>
    protected override string? AuthorizedKey => FixtureLoader.LoadText("ed25519_enc_key.pub");
}
