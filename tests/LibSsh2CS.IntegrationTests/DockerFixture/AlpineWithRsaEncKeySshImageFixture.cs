using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineWithRsaEncKeySshImageFixture as an assembly-wide fixture: xUnit
// v3 constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineWithRsaEncKeySshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with the test
/// RSA public key (<c>Fixtures/rsa_enc_key.pub</c>) installed in
/// <c>authorized_keys</c> on first use and retains it across
/// test runs. Used by the bcrypt-encrypted RSA
/// publickey auth test: the encrypted private key
/// (<c>Fixtures/rsa_enc_key</c>, aes256-ctr + bcrypt, passphrase
/// <c>"test123"</c>) is a DIFFERENT key pair from <c>rsa_plain_key</c>, so
/// it needs its own authorized_keys entry. Test classes receive it via
/// constructor injection and start a fresh per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class AlpineWithRsaEncKeySshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // Same hostkey generation as AlpineWithRsaKey: the extra ECDSA keys
        // are harmless and keep the variants uniform.
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthAlpine);

    /// <summary>
    /// The test RSA public key whose private counterpart is the
    /// bcrypt-encrypted <c>rsa_enc_key</c> fixture, loaded from the embedded
    /// resource at build time and baked into the image's
    /// <c>authorized_keys</c>.
    /// </summary>
    protected override string? AuthorizedKey => FixtureLoader.LoadText("rsa_enc_key.pub");
}
