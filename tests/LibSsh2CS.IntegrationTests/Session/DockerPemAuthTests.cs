using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live legacy-PEM auth integration tests: every key parsed by the
/// legacy-PEM reader (<c>-----BEGIN RSA PRIVATE KEY-----</c> PKCS#1,
/// <c>-----BEGIN PRIVATE KEY-----</c>/<c>ENCRYPTED PRIVATE KEY-----</c>
/// PKCS#8, <c>-----BEGIN EC PRIVATE KEY-----</c> SEC1) must drive a real
/// USERAUTH_REQUEST signature that a live OpenSSH server accepts.
/// </summary>
/// <remarks>
/// <para>
/// The unit suites (<c>LibSsh2CS.UnitTests.PemKey.*</c>) prove the parser
/// extracts blobs byte-identical to <c>ssh-keygen</c>'s and that
/// <c>SshSign</c> signatures verify against the .pub files — but that is
/// self-verification. Only a real sshd proves the derived key + signature
/// are accepted by an independent implementation: publickey auth succeeds
/// (<see cref="SshSession.IsAuthenticated"/>) only after the server
/// verified the client's signature over the session id.
/// </para>
/// <para>
/// <b>Container:</b> a single <see cref="AlpineLegacyPemSshImageFixture"/>
/// image (all 15 legacy-PEM .pub fixtures in <c>authorized_keys</c>); each
/// test case forks a fresh container (~1s) with its own random host port.
/// Encrypted fixtures use passphrase <c>"testpass"</c>.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerPemAuthTests : IDisposable
{
    private const string TestPassphrase = "testpass";

    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineLegacyPemSshImageFixture _fixture;

    public DockerPemAuthTests(
        AlpineLegacyPemSshImageFixture fixture,
        ITestOutputHelper testOutputHelper)
    {
        _fixture = fixture;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Every legacy-PEM key fixture (private-key resource name + passphrase;
    /// <c>null</c> for unencrypted). One theory row per key format:
    /// PKCS#1 RSA (plain + traditional-encrypted), PKCS#8 RSA (plain +
    /// PBES2 ×4 PRF/cipher combinations), SEC1 EC (nistp256/384/521 plain +
    /// encrypted), PKCS#8 EC (plain + encrypted), and PKCS#8 Ed25519
    /// (plain + encrypted).
    /// </summary>
    public static TheoryData<string, string?> LegacyPemKeys => new()
    {
        // PKCS#1 "RSA PRIVATE KEY" (ssh-keygen -m PEM).
        { "legacy_pem.legacy_rsa", null },
        { "legacy_pem.enc_rsa", TestPassphrase },

        // PKCS#8 PrivateKeyInfo / PBES2 EncryptedPrivateKeyInfo.
        { "legacy_pem.pkcs8.pem", null },
        { "legacy_pem.pkcs8_enc.pem", TestPassphrase },          // PBKDF2-HMAC-SHA256 + AES-128-CBC
        { "legacy_pem.pkcs8_enc_aes256.pem", TestPassphrase },   // PBKDF2-HMAC-SHA256 + AES-256-CBC
        { "legacy_pem.pkcs8_enc_des3.pem", TestPassphrase },     // PBKDF2-HMAC-SHA256 + DES-EDE3-CBC
        { "legacy_pem.pkcs8_enc_sha1.pem", TestPassphrase },     // absent PRF → HMAC-SHA1 default

        // SEC1 "EC PRIVATE KEY" (RFC 5915).
        { "legacy_pem.ec_sec1.pem", null },
        { "legacy_pem.ec_sec1_384.pem", null },
        { "legacy_pem.ec_sec1_521.pem", null },
        { "legacy_pem.ec_sec1_enc.pem", TestPassphrase },

        // PKCS#8 EC.
        { "legacy_pem.ec_pkcs8.pem", null },
        { "legacy_pem.ec_pkcs8_enc.pem", TestPassphrase },

        // PKCS#8 Ed25519 (RFC 8410).
        { "legacy_pem.ed25519_pkcs8.pem", null },
        { "legacy_pem.ed25519_pkcs8_enc.pem", TestPassphrase },
    };

    /// <summary>
    /// Public-key authentication with each legacy-PEM key format succeeds
    /// against a live OpenSSH server whose <c>authorized_keys</c> trusts
    /// the matching public key. Exercises the full pipeline end-to-end:
    /// legacy armor detection → DER/PKCS#8/SEC1 decode (+ passphrase KDF)
    /// → <c>SshPemKey.Parse</c> → <c>SshSign</c> → USERAUTH_REQUEST →
    /// server-side signature verification.
    /// </summary>
    [Theory]
    [MemberData(nameof(LegacyPemKeys))]
    public async Task Auth_LegacyPemKey_Succeeds(string fixtureName, string? passphrase)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _fixture.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, ct);

        byte[] keyBytes = FixtureLoader.LoadBytes(fixtureName);
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: passphrase, cancellationToken: ct);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// The session established with a legacy-PEM key is fully usable: after
    /// authenticating with the unencrypted PKCS#1 RSA fixture, an
    /// <c>exec</c> round-trip must complete with the expected output and
    /// exit status. Guards against an auth path that succeeds but leaves
    /// the session in a broken state.
    /// </summary>
    [Fact]
    public async Task Auth_LegacyRsaPkcs1_SupportsExecRoundTrip()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _fixture.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, ct);

        byte[] keyBytes = FixtureLoader.LoadBytes("legacy_pem.legacy_rsa");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: null, cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("echo legacy-pem-ok", ct);

        using var ms = new MemoryStream();
        byte[] buf = new byte[256];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        Assert.Equal(0, exit);
        Assert.Equal("legacy-pem-ok\n", Encoding.UTF8.GetString(ms.ToArray()));
    }

    /// <summary>
    /// The wrong passphrase for the traditionally-encrypted PKCS#1 RSA
    /// fixture fails at the parse stage with
    /// <see cref="SshErrorCode.KeyfileAuthFailed"/> before any auth traffic
    /// is sent — the same error surfaces through the public auth API as
    /// through the parser (unit-pinned in <c>LegacyPemTests</c>).
    /// </summary>
    [Fact]
    public async Task Auth_LegacyPemEncrypted_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _fixture.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, ct);

        byte[] keyBytes = FixtureLoader.LoadBytes("legacy_pem.enc_rsa");
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
                passphrase: "wrong-passphrase", cancellationToken: ct));
        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
        Assert.False(session.IsAuthenticated);
    }
}
