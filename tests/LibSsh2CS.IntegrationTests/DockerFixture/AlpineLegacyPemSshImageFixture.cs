using LibSsh2CS.IntegrationTests.DockerFixture;

using Xunit.Sdk;

// Marks AlpineLegacyPemSshImageFixture as an assembly wide fixture: xUnit v3
// constructs one instance before any test in the assembly runs (calling
// InitializeAsync) and disposes it after all tests complete. Test classes
// receive it via constructor injection.
[assembly: AssemblyFixture(typeof(AlpineLegacyPemSshImageFixture))]

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Assembly-wide fixture that builds the Alpine 3.20 image with EVERY
/// legacy-PEM test public key (<c>Fixtures/legacy_pem/*.pub</c>) installed
/// in <c>authorized_keys</c> on first use and retains it across
/// test runs. A single combined image (instead of
/// one fixture per key) keeps the per-run image-build count at +1 while
/// letting each <see cref="Session.DockerPemAuthTests"/> case fork a fresh
/// cheap container (~1s) from it.
/// </summary>
/// <remarks>
/// <para>
/// The private halves live in the embedded fixtures
/// (<c>Fixtures/legacy_pem/*</c>): traditional PKCS#1 RSA
/// (<c>legacy_rsa</c> + <c>enc_rsa</c>, <c>Proc-Type: 4,ENCRYPTED</c> +
/// <c>DEK-Info</c>), PKCS#8 (<c>pkcs8*</c>, PBES2 with PBKDF2-HMAC-SHA1/256
/// + AES-CBC/DES-EDE3-CBC), SEC1 EC (<c>ec_sec1*</c>, nistp256/384/521),
/// PKCS#8 EC (<c>ec_pkcs8*</c>), and PKCS#8 Ed25519
/// (<c>ed25519_pkcs8*</c>). Encrypted fixtures use passphrase
/// <c>"testpass"</c>.
/// </para>
/// <para>
/// The server accepts all of these key types via the shared
/// <c>PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,
/// ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521</c> line in
/// <see cref="SshImageFixtureBase"/>'s sshd config.
/// </para>
/// </remarks>
public sealed class AlpineLegacyPemSshImageFixture(IMessageSink messageSink)
    : SshImageFixtureBase(messageSink)
{
    /// <summary>
    /// The <c>authorized_keys</c> entries (one .pub fixture per line) baked
    /// into the image. Order is irrelevant; OpenSSH tries each line against
    /// the offered public key.
    /// </summary>
    private static readonly string[] s_authorizedKeyFixtures =
    [
        "legacy_pem.legacy_rsa.pub",
        "legacy_pem.enc_rsa.pub",
        "legacy_pem.pkcs8.pub",
        "legacy_pem.pkcs8_enc.pub",
        "legacy_pem.pkcs8_enc_aes256.pub",
        "legacy_pem.pkcs8_enc_des3.pub",
        "legacy_pem.pkcs8_enc_sha1.pub",
        "legacy_pem.ec_sec1.pub",
        "legacy_pem.ec_sec1_384.pub",
        "legacy_pem.ec_sec1_521.pub",
        "legacy_pem.ec_sec1_enc.pub",
        "legacy_pem.ec_pkcs8.pub",
        "legacy_pem.ec_pkcs8_enc.pub",
        "legacy_pem.ed25519_pkcs8.pub",
        "legacy_pem.ed25519_pkcs8_enc.pub",
    ];

    /// <inheritdoc/>
    protected override SshImageSpec Spec => new(
        FromLine: "FROM alpine:3.20",
        // Same hostkey generation as AlpineNoKey: uniformity across the
        // variants (the PEM tests don't pin hostkey algorithms).
        InstallAndKeygen:
            "RUN apk add --no-cache openssh-server && ssh-keygen -A" +
            " && ssh-keygen -t ecdsa -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -N ''" +
            " && ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -N ''",
        CreateUserCmd: "RUN adduser -D " + SshDockerFixture.TestUser + " && echo '" + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestPassword + "' | chpasswd",
        AuthConfig: SshdConfigAuthAlpine);

    /// <summary>
    /// All legacy-PEM public keys joined with newlines — the base class
    /// base64-encodes the whole multi-line blob into a single Dockerfile RUN,
    /// so the joining needs no special quoting.
    /// </summary>
    protected override string? AuthorizedKey
        => string.Join("\n", s_authorizedKeyFixtures.Select(FixtureLoader.LoadText));
}
