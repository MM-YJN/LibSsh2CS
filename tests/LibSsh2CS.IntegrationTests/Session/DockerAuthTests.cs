using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Phase 2 live auth integration tests: runs a real OpenSSH server in Docker
/// with password + publickey auth enabled (and kbdint on the Debian variant),
/// then exercises <see cref="SshSession.HandshakeAsync"/> + the
/// <see cref="SshUserAuth"/> methods against it. Extends the Phase 1
/// <c>DockerHandshakeTests</c> pattern (which only does the transport
/// handshake) with actual authentication flows.
/// </summary>
/// <remarks>
/// <para>
/// <b>Container:</b> started from one of four assembly-built images via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>. Each image is
/// prepared on first use and retained across runs; each test forks a fresh
/// container (~1s) with its own random host port.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// <para>
/// <b>Test user:</b> <c>testuser</c> with password <c>testpass</c>. The
/// authorized_keys entry is the Ed25519 key from the embedded fixture
/// (<c>ed25519_plain_key.pub</c>), the RSA key (<c>rsa_plain_key.pub</c>),
/// or their bcrypt-encrypted counterparts (<c>ed25519_enc_key.pub</c> /
/// <c>rsa_enc_key.pub</c> — distinct key pairs whose private halves are
/// aes256-ctr + bcrypt, passphrase <c>"test123"</c>).
/// </para>
/// <para>
/// <b>Keyboard-interactive uses the Debian variant.</b> Alpine's
/// <c>openssh-server</c> is built without libpam linkage and ignores
/// <c>KbdInteractiveAuthentication yes</c>, so the kbdint test uses the
/// <see cref="DebianNoKeySshImageFixture"/> (PAM-linked sshd).
/// </para>
/// </remarks>
public sealed class DockerAuthTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;
    private readonly AlpineWithEd25519KeySshImageFixture _alpineWithEd25519Key;
    private readonly AlpineWithRsaKeySshImageFixture _alpineWithRsaKey;
    private readonly AlpineWithEcdsaP256KeySshImageFixture _alpineWithEcdsaP256Key;
    private readonly AlpineWithEcdsaP384KeySshImageFixture _alpineWithEcdsaP384Key;
    private readonly AlpineWithEcdsaP521KeySshImageFixture _alpineWithEcdsaP521Key;
    private readonly AlpineWithEd25519EncKeySshImageFixture _alpineWithEd25519EncKey;
    private readonly AlpineWithRsaEncKeySshImageFixture _alpineWithRsaEncKey;
    private readonly DebianNoKeySshImageFixture _debianNoKey;

    public DockerAuthTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        AlpineWithEd25519KeySshImageFixture alpineWithEd25519Key,
        AlpineWithRsaKeySshImageFixture alpineWithRsaKey,
        AlpineWithEcdsaP256KeySshImageFixture alpineWithEcdsaP256Key,
        AlpineWithEcdsaP384KeySshImageFixture alpineWithEcdsaP384Key,
        AlpineWithEcdsaP521KeySshImageFixture alpineWithEcdsaP521Key,
        AlpineWithEd25519EncKeySshImageFixture alpineWithEd25519EncKey,
        AlpineWithRsaEncKeySshImageFixture alpineWithRsaEncKey,
        DebianNoKeySshImageFixture debianNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _alpineWithEd25519Key = alpineWithEd25519Key;
        _alpineWithRsaKey = alpineWithRsaKey;
        _alpineWithEcdsaP256Key = alpineWithEcdsaP256Key;
        _alpineWithEcdsaP384Key = alpineWithEcdsaP384Key;
        _alpineWithEcdsaP521Key = alpineWithEcdsaP521Key;
        _alpineWithEd25519EncKey = alpineWithEd25519EncKey;
        _alpineWithRsaEncKey = alpineWithRsaEncKey;
        _debianNoKey = debianNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Password authentication succeeds against a live OpenSSH server.
    /// </summary>
    [Fact]
    public async Task Auth_Password_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Wrong password → AuthenticationFailed. The session stays unauthenticated.
    /// </summary>
    [Fact]
    public async Task Auth_WrongPassword_ThrowsAuthenticationFailed()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, "wrongpassword",
                cancellationToken: cancellationToken));
        Assert.Equal(SshErrorCode.AuthenticationFailed, ex.ErrorCode);
        Assert.False(session.IsAuthenticated);
    }

    /// <summary>
    /// Public key authentication with the embedded Ed25519 key succeeds.
    /// </summary>
    [Fact]
    public async Task Auth_Ed25519PublicKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithEd25519Key.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: null, cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Public key authentication with the embedded RSA key succeeds. This
    /// exercises the RSA-SHA2 algorithm selection path: the server advertises
    /// <c>server-sig-algs</c> via EXT_INFO and the client picks rsa-sha2-256
    /// (or 512).
    /// </summary>
    [Fact]
    public async Task Auth_RsaPublicKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithRsaKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("rsa_plain_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: null, cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ECDSA publickey auth (ecdsa-sha2-nistp256/384/521). The Ed25519 + RSA
    // tests above cover those key types; these three light up the only
    // remaining 0% cluster in the client-auth path: SshSign.SignEcdsa +
    // ParseEcdsaDerSig + BuildEcdsaSshSigBody + ParseSec1Point (~50 lines in
    // SshSign.cs), SshEcdsaPemKey (0% → covered), the ECDSA arm of
    // SelectSigningAlgorithm (SshUserAuth.cs:603-610), and SshPemKey.ParseEcdsa
    // (SshPemKey.cs:75-118). Each test uses a distinct ssh-keygen-generated
    // ECDSA key pair whose public half is baked into authorized_keys by the
    // matching AlpineWithEcdsaXxxKeySshImageFixture.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Public key authentication with the embedded ECDSA-P256 key
    /// (<c>ecdsa_p256_plain_key</c>, unencrypted) succeeds against a live
    /// OpenSSH server. Exercises the full ECDSA-P256 client-auth pipeline
    /// end-to-end: <see cref="SshPemParser.ParseOpenSshPrivateKey"/> →
    /// <see cref="SshPemKey.Parse"/> (ECDSA-P256 branch) →
    /// <see cref="SshUserAuth.SelectSigningAlgorithm"/> (ECDSA arm, returns
    /// <c>"ecdsa-sha2-nistp256"</c>) → <see cref="SshSign.SignEcdsa"/> (SHA-256
    /// digest + BCL ECDsa.SignHash + DER→SSH-wire re-encode) → USERAUTH_REQUEST.
    /// The unit-test <c>PemKeyParseTests</c> pins the parse; this test proves
    /// the derived key drives a live ECDSA-P256 signature that OpenSSH
    /// accepts.
    /// </summary>
    [Fact]
    public async Task Auth_EcdsaP256PublicKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithEcdsaP256Key.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p256_plain_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: null, cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Public key authentication with the embedded ECDSA-P384 key
    /// (<c>ecdsa_p384_plain_key</c>, unencrypted) succeeds against a live
    /// OpenSSH server. Mirrors <see cref="Auth_EcdsaP256PublicKey_Succeeds"/>
    /// on the P-384 curve: lights up the <c>"ecdsa-sha2-nistp384"</c> arm of
    /// <see cref="SshUserAuth.SelectSigningAlgorithm"/> (SHA-384 digest,
    /// 48-byte coordinates) and the 48-byte <see cref="SshSign.ParseSec1Point"/>
    /// validation in <see cref="SshSign.SignEcdsa"/>.
    /// </summary>
    [Fact]
    public async Task Auth_EcdsaP384PublicKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithEcdsaP384Key.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p384_plain_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: null, cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Public key authentication with the embedded ECDSA-P521 key
    /// (<c>ecdsa_p521_plain_key</c>, unencrypted) succeeds against a live
    /// OpenSSH server. Mirrors <see cref="Auth_EcdsaP256PublicKey_Succeeds"/>
    /// on the P-521 curve: lights up the <c>"ecdsa-sha2-nistp521"</c> arm of
    /// <see cref="SshUserAuth.SelectSigningAlgorithm"/> (SHA-512 digest,
    /// 66-byte coordinates) and the 66-byte <see cref="SshSign.ParseSec1Point"/>
    /// validation in <see cref="SshSign.SignEcdsa"/>. P-521 is the largest
    /// in-scope ECDSA curve and the only one whose DER signature length
    /// exceeds 127 bytes (exercising the long-form SEQUENCE length branch in
    /// <see cref="SshSign.ParseEcdsaDerSig"/>, <c>lenBytes != 1</c>).
    /// </summary>
    [Fact]
    public async Task Auth_EcdsaP521PublicKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithEcdsaP521Key.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("ecdsa_p521_plain_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: null, cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// <c>GetAuthMethodsAsync</c> returns the server's advertised auth methods
    /// (at least "password" and "publickey").
    /// </summary>
    [Fact]
    public async Task GetAuthMethods_ReturnsPasswordAndPublicKey()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        string[] methods = await session.GetAuthMethodsAsync(SshDockerFixture.TestUser,
            cancellationToken: cancellationToken);
        Assert.Contains("password", methods);
        Assert.Contains("publickey", methods);
    }

    /// <summary>
    /// Keyboard-interactive authentication succeeds against a PAM-linked
    /// OpenSSH server. Uses the Debian image variant because Alpine's
    /// <c>openssh-server</c> is built without libpam linkage and ignores
    /// <c>KbdInteractiveAuthentication yes</c>.
    /// </summary>
    /// <remarks>
    /// The strict <c>promptCount &gt;= 1</c> assertion verifies the server
    /// actually drove the kbdint loop with at least one real challenge —
    /// without it, a regression that silently fell through to password auth
    /// (e.g. if kbdint were misconfigured server-side) would still pass the
    /// test. <c>pam_unix.so</c> sends one password prompt; other PAM modules
    /// in Debian's default <c>/etc/pam.d/sshd</c> may send additional
    /// informational INFO_REQUEST messages with 0 prompts (e.g. MOTD), so
    /// the count is cumulative across all callback invocations. A value of 0
    /// means no challenge was issued at all (silent fallthrough).
    /// </remarks>
    [Fact]
    public async Task Auth_KeyboardInteractive_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        // Debian variant: PAM-linked sshd drives a real USERAUTH_INFO_REQUEST.
        await using SshDockerContainer container = await _debianNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        // Cumulative prompt count: PAM may send multiple INFO_REQUESTs across
        // the auth + session stack (password prompt + MOTD/info). We want the
        // total number of *actual* prompts (pam_unix.so's "Password: " = 1).
        int promptCount = 0;
        await session.AuthenticateWithKeyboardInteractiveAsync(
            SshDockerFixture.TestUser,
            (_, _, prompts, _) =>
            {
                promptCount += prompts.Length;
                string[] answers = new string[prompts.Length];
                Array.Fill(answers, SshDockerFixture.TestPassword);
                return Task.FromResult(answers);
            },
            cancellationToken: cancellationToken);

        Assert.True(session.IsAuthenticated);

        // Strict: confirms the server actually challenged us with at least
        // one prompt. pam_unix.so sends exactly one ("Password: ").
        Assert.True(promptCount >= 1, $"expected >= 1 kbdint prompt, got {promptCount}");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Bcrypt-encrypted private-key auth. The plain-key tests above pass
    // `passphrase: null` to AuthenticateWithPublicKeyAsync because the
    // plain fixtures use the "none" KDF; these tests pass the "test123"
    // passphrase required by the aes256-ctr+bcrypt fixtures
    // (ed25519_enc_key / rsa_enc_key). This lights up the largest 0%
    // coverage cluster in the integration run: BcryptPbkdf.Derive
    // (BcryptPbkdf.cs), BlowfishContext (Blowfish.cs), and the
    // SshPemParser decrypt path (DecryptOpenSshPrivateKey /
    // GetCipherParameters / AesCbcDecrypt) — ~1100 lines that the plain-key
    // tests never touch because SshPemParser short-circuits at the "none"
    // KDF branch.
    //
    // The enc fixtures are DISTINCT key pairs from the plain ones (different
    // comments + public blobs), so each needs its own authorized_keys entry,
    // provided by the AlpineWithEd25519EncKey / AlpineWithRsaEncKey image
    // fixtures.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Public-key authentication with the bcrypt-encrypted Ed25519 key
    /// (<c>ed25519_enc_key</c>, aes256-ctr + bcrypt, passphrase
    /// <c>"test123"</c>) succeeds against a live OpenSSH server whose
    /// <c>authorized_keys</c> trusts the matching public key. Exercises the
    /// full encrypted-key pipeline end-to-end:
    /// <see cref="SshPemParser.ParseOpenSshPrivateKey(byte[], string?)"/>
    /// → bcrypt-pbkdf key/IV derivation (<see cref="BcryptPbkdf"/> +
    /// <see cref="BlowfishContext"/>) → AES-256-CTR decrypt →
    /// <see cref="SshPemKey.Parse(OpenSshKey)"/> →
    /// <see cref="SshSign"/> → USERAUTH_REQUEST. The unit-test
    /// <c>PemParserTests.ParseOpenSshPrivateKey_Ed25519EncryptedCorrectPassphrase_ExtractsMatchingPublicKey</c>
    /// pins the parse; this test proves the derived key actually drives a
    /// live signature that the server accepts.
    /// </summary>
    [Fact]
    public async Task Auth_Ed25519EncryptedKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithEd25519EncKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_enc_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: "test123", cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Public-key authentication with the bcrypt-encrypted RSA key
    /// (<c>rsa_enc_key</c>, aes256-ctr + bcrypt, passphrase
    /// <c>"test123"</c>) succeeds against a live OpenSSH server. RSA keys
    /// span more AES blocks than Ed25519 keys, exercising the CTR-mode
    /// counter-rollover path in <c>AesCtrCipher</c> over real decrypted
    /// bytes. Also drives the RSA-SHA2 algorithm selection
    /// (<see cref="SshUserAuth"/>) on top of the encrypted-key parse — the
    /// server advertises <c>server-sig-algs</c> via EXT_INFO and the client
    /// picks rsa-sha2-256 (or 512) for the live signature.
    /// </summary>
    [Fact]
    public async Task Auth_RsaEncryptedKey_Succeeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithRsaEncKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("rsa_enc_key");
        await session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
            passphrase: "test123", cancellationToken: cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Supplying the wrong passphrase to the encrypted Ed25519 key fails at
    /// the parse stage (<c>check1 != check2</c> in
    /// <see cref="SshPemParser"/>) with
    /// <see cref="SshErrorCode.KeyfileAuthFailed"/> BEFORE any network
    /// traffic is sent. Verifies the failure surfaces as a synchronous
    /// <see cref="SshException"/> from
    /// <see cref="SshUserAuth.AuthenticateWithPublicKeyAsync(string, byte[]?, byte[], string?, CancellationToken)"/>
    /// and that the session stays unauthenticated. The unit test
    /// <c>PemParserTests.ParseOpenSshPrivateKey_Ed25519EncryptedWrongPassphrase_ThrowsKeyfileAuthFailed</c>
    /// pins the parse error; this test confirms the same error propagates
    /// through the public auth API the way a caller would invoke it.
    /// </summary>
    [Fact]
    public async Task Auth_Ed25519EncryptedKey_WrongPassphrase_ThrowsKeyfileAuthFailed()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineWithEd25519EncKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        byte[] keyBytes = FixtureLoader.LoadBytes("ed25519_enc_key");
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.AuthenticateWithPublicKeyAsync(SshDockerFixture.TestUser, publicKeyBlob: null, privateKeyData: keyBytes,
                passphrase: "wrong-passphrase", cancellationToken: cancellationToken));
        Assert.Equal(SshErrorCode.KeyfileAuthFailed, ex.ErrorCode);
        Assert.False(session.IsAuthenticated);
    }
}
