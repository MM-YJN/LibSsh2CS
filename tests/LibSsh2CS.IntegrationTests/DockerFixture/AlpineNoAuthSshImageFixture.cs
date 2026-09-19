using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineNoAuthSshImageFixture as an assembly-wide fixture: xUnit v3
// constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineNoAuthSshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with both
/// password and pubkey auth disabled (and no test user created) on first use and retains it across
/// test runs. Used by the transport-handshake-only test
/// (<c>DockerHandshakeTests</c>), which completes the SSH transport
/// handshake (banner → KEX → NEWKEYS → hostkey verify) but never reaches
/// userauth. The no-auth sshd config rejects any auth attempt, which the
/// handshake never reaches. Test classes receive it via constructor
/// injection and start a fresh per-test container via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </summary>
public sealed class AlpineNoAuthSshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // No extra ECDSA keygen here: the handshake test doesn't pin host
        // key algorithms (it negotiates the default), so the base
        // ssh-keygen -A host keys (rsa, ecdsa-256, ed25519) suffice.
        InstallAndKeygen: "RUN apk add --no-cache openssh-server && ssh-keygen -A",
        // Empty: no user created (auth is disabled anyway).
        CreateUserCmd: "",
        AuthConfig: SshdConfigNoAuth);
}
