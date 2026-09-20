using System.Net.Sockets;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.Session;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Transport;

/// <summary>
/// Phase 8 negotiation-matrix live integration tests: pins the client side
/// to a single algorithm (via <see cref="SshSession"/>'s
/// <c>this[SshMethodType.*]</c> indexer — libssh2's
/// <c>libssh2_session_method_pref</c> semantics) and verifies the full
/// handshake + a small exec round-trip succeeds against a real OpenSSH
/// server that also offers that algorithm. The shared
/// <see cref="AlpineNoKeySshImageFixture"/> assembly fixture's sshd config
/// advertises the full in-scope algorithm matrix (all cipher/kex/mac/
/// hostkey/compression variants) so each test only needs to pin the client
/// side.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why pin-and-handshake is sufficient.</b> libssh2 (and this port) offers
/// only the algorithms in the user's pref list when one is set; if the
/// server doesn't offer a match, <c>KeyExchange.Negotiate</c> throws
/// <see cref="SshErrorCode.KexFailure"/>. So a successful handshake with a
/// single-algorithm client pref is proof the algorithm was negotiated and
/// installed. The follow-up <c>echo</c> exec + read proves the derived keys
/// actually decrypt/encrypt real traffic in both directions.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerNegotiationTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerNegotiationTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    // ════════════════════════════════════════════════════════════════════════
    // Ciphers — each test pins CryptCs/CryptSc to a single cipher so the
    // client offers only that one. The server (SshImageFixtureBase.SshdConfigBase)
    // offers the full in-scope matrix, so the handshake succeeds iff the
    // pinned cipher was negotiated. The exec round-trip exercises the cipher's
    // encrypt (outbound) + decrypt (inbound) paths over real traffic.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// <c>chacha20-poly1305@openssh.com</c> — the AEAD stream cipher. Lights
    /// up <c>Crypto/ChaCha20.cs</c>, <c>Crypto/Poly1305.cs</c>,
    /// <c>Crypto/ChaChaPolySsh.cs</c>, and <c>Transport/ChaChaPolyCipher.cs</c>
    /// (the largest single 0%-coverage cluster before this group).
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_ChaCha20Poly1305_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "chacha20-poly1305@openssh.com";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes256-gcm@openssh.com</c> — 256-bit AES-GCM AEAD. Already exercised
    /// by the default-negotiation tests (it's the client's 2nd pref), but
    /// pinned here for explicit matrix coverage of the GCM path + the
    /// <c>_libssh2_mac_override</c> no-op MAC selection.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes256Gcm_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes256-gcm@openssh.com";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes128-gcm@openssh.com</c> — 128-bit AES-GCM AEAD. Lights up the
    /// 128-bit branch of <c>AesGcmCipher</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes128Gcm_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes128-gcm@openssh.com";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes256-ctr</c> — AES-256 in CTR mode with a separate MAC. Lights up
    /// <c>Transport/AesCtrCipher.cs</c> + <c>Transport/AesCtrMode.cs</c> (the
    /// CTR-mode key stream) and the non-AEAD MAC path in
    /// <c>Transport/HmacMac.cs</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes256Ctr_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes256-ctr";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes192-ctr</c> — AES-192 in CTR mode. Lights up the 192-bit branch of
    /// <c>AesCtrCipher</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes192Ctr_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes192-ctr";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes128-ctr</c> — AES-128 in CTR mode. Lights up the 128-bit branch of
    /// <c>AesCtrCipher</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes128Ctr_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes128-ctr";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes256-cbc</c> — AES-256 in CBC mode (block cipher, no AEAD). Lights
    /// up <c>Transport/AesCbcCipher.cs</c> (0% before this group).
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes256Cbc_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes256-cbc";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes192-cbc</c> — AES-192 in CBC mode. Lights up the 192-bit branch of
    /// <c>AesCbcCipher</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes192Cbc_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes192-cbc";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>aes128-cbc</c> — AES-128 in CBC mode. Lights up the 128-bit branch of
    /// <c>AesCbcCipher</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_Cipher_Aes128Cbc_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        const string cipher = "aes128-cbc";
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port, cryptCs: cipher, cryptSc: cipher, ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    // ════════════════════════════════════════════════════════════════════════
    // MACs — pinned alongside a non-AEAD cipher (aes256-ctr) so a real MAC is
    // negotiated (the AES-GCM no-op override path is skipped). Lights up the
    // matching branches of HmacMac + the non-AEAD MAC verify path.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// <c>hmac-sha2-256</c> — already the server default, but pinned here with
    /// <c>aes256-ctr</c> (non-AEAD) so the real MAC code path runs (the
    /// default-negotiation tests use AES-GCM which collapses the MAC to
    /// no-op).
    /// </summary>
    [Fact]
    public async Task Handshake_Mac_HmacSha2_256_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            cryptCs: "aes256-ctr", cryptSc: "aes256-ctr",
            macCs: "hmac-sha2-256", macSc: "hmac-sha2-256",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>hmac-sha2-512</c> — the 512-bit HMAC variant. Lights up the
    /// <c>HmacMac</c> 512-bit branch and the non-ETM verify path.
    /// </summary>
    [Fact]
    public async Task Handshake_Mac_HmacSha2_512_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            cryptCs: "aes256-ctr", cryptSc: "aes256-ctr",
            macCs: "hmac-sha2-512", macSc: "hmac-sha2-512",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    // ════════════════════════════════════════════════════════════════════════
    // KEX algorithms — pin Kex to a single method so the client offers only
    // it; the server offers the full in-scope set. Lights up the matching
    // KEX math (EcdhNistP / DhGroup14).
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// <c>curve25519-sha256</c> — the default KEX. Already covered by the
    /// default-negotiation tests but pinned here for explicit matrix coverage.
    /// </summary>
    [Fact]
    public async Task Handshake_Kex_Curve25519Sha256_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            kex: "curve25519-sha256",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ecdh-sha2-nistp256</c> — ECDH on the NIST P-256 curve. Lights up
    /// <c>Transport/EcdhNistP.cs</c> for the 256-bit curve.
    /// </summary>
    [Fact]
    public async Task Handshake_Kex_EcdhNistP256_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            kex: "ecdh-sha2-nistp256",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ecdh-sha2-nistp384</c> — ECDH on the NIST P-384 curve. Lights up
    /// <c>Transport/EcdhNistP.cs</c> for the 384-bit curve (0% before this
    /// group).
    /// </summary>
    [Fact]
    public async Task Handshake_Kex_EcdhNistP384_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            kex: "ecdh-sha2-nistp384",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ecdh-sha2-nistp521</c> — ECDH on the NIST P-521 curve. Lights up
    /// <c>Transport/EcdhNistP.cs</c> for the 521-bit curve (0% before this
    /// group).
    /// </summary>
    [Fact]
    public async Task Handshake_Kex_EcdhNistP521_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            kex: "ecdh-sha2-nistp521",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>diffie-hellman-group14-sha256</c> — the modular-exponentiation KEX
    /// (Oakley Group 14, SHA-256). Lights up <c>Transport/DhGroup14.cs</c>
    /// (0% before this group).
    /// </summary>
    [Fact]
    public async Task Handshake_Kex_DhGroup14Sha256_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            kex: "diffie-hellman-group14-sha256",
            ct: ct);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Host-key algorithms — pin HostKey to a single method. Lights up the
    // matching verify branch in Transport/HostKeyVerifier.cs (RSA-SHA2 /
    // ECDSA-P256/P384/P521 / Ed25519). The negotiated host-key name is
    // exposed via SshSession.HostKeyAlgorithm and asserted to make the test
    // self-checking (a regression that fell back to a different hostkey
    // would fail the assertion, not silently pass).
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// <c>ssh-ed25519</c> host key. Lights up the Ed25519 verify branch of
    /// <c>HostKeyVerifier.Verify</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_Ed25519_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "ssh-ed25519",
            ct: ct);
        Assert.Equal("ssh-ed25519", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>rsa-sha2-512</c> host key — RSA with SHA-512 (the strongest RSA
    /// variant). Lights up the RSA-SHA-512 verify branch of
    /// <c>HostKeyVerifier.Verify</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_RsaSha2_512_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "rsa-sha2-512",
            ct: ct);
        Assert.Equal("rsa-sha2-512", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>rsa-sha2-256</c> host key — RSA with SHA-256. Lights up the
    /// RSA-SHA-256 verify branch of <c>HostKeyVerifier.Verify</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_RsaSha2_256_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "rsa-sha2-256",
            ct: ct);
        Assert.Equal("rsa-sha2-256", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ssh-rsa</c> host key — RSA with SHA-1 (legacy). Lights up the SHA-1
    /// verify branch of <c>HostKeyVerifier.Verify</c>. Re-enabled on the
    /// server via <c>HostKeyAlgorithms +ssh-rsa</c> (modern OpenSSH disables
    /// SHA-1 by default).
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_SshRsa_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "ssh-rsa",
            ct: ct);
        Assert.Equal("ssh-rsa", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ecdsa-sha2-nistp256</c> host key. Lights up the ECDSA-P256 verify
    /// branch of <c>HostKeyVerifier.Verify</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_EcdsaNistP256_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "ecdsa-sha2-nistp256",
            ct: ct);
        Assert.Equal("ecdsa-sha2-nistp256", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ecdsa-sha2-nistp384</c> host key. Lights up the ECDSA-P384 verify
    /// branch of <c>HostKeyVerifier.Verify</c>. Requires the container to
    /// have generated a P-384 ECDSA host key (the fixture does so via an
    /// extra <c>ssh-keygen -t ecdsa -b 384</c> in its Dockerfile).
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_EcdsaNistP384_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "ecdsa-sha2-nistp384",
            ct: ct);
        Assert.Equal("ecdsa-sha2-nistp384", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    /// <summary>
    /// <c>ecdsa-sha2-nistp521</c> host key. Lights up the ECDSA-P521 verify
    /// branch of <c>HostKeyVerifier.Verify</c>. Requires the container to
    /// have generated a P-521 ECDSA host key (the fixture does so via an
    /// extra <c>ssh-keygen -t ecdsa -b 521</c> in its Dockerfile).
    /// </summary>
    [Fact]
    public async Task Handshake_HostKey_EcdsaNistP521_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectWithPrefsAsync(
            SshDockerFixture.Host, container.Port,
            hostKey: "ecdsa-sha2-nistp521",
            ct: ct);
        Assert.Equal("ecdsa-sha2-nistp521", session.HostKeyAlgorithm);
        await AuthenticateAndExecEchoAsync(session, ct);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Compression — set SshFlag.Compress before handshake so the client's
    // compression name-list includes zlib@openssh.com (without the flag,
    // BuildKexInitWithCompressFilter forces it to "none"). The server offers
    // "Compression yes" so both sides negotiate zlib@openssh.com.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// <c>SshFlag.Compress</c> set before handshake → the client offers
    /// <c>zlib@openssh.com</c>; the server offers <c>Compression yes</c>; the
    /// negotiated compression is <c>zlib@openssh.com</c>. Lights up
    /// <c>Transport/ZlibCompression.cs</c> (0% before this group). The exec
    /// round-trip exercises the compressor (outbound) + decompressor
    /// (inbound) over real traffic.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Live-server gate for the <c>zlib@openssh.com</c> delayed-compression
    /// path. The compressor is installed inert at NEWKEYS (because
    /// <c>use_in_auth=false</c>) and activated only after auth by
    /// <see cref="SshSession.MarkAuthenticated"/>; the post-auth exec
    /// round-trip then exercises both the outbound compressor and the inbound
    /// decompressor against a real OpenSSH server.
    /// </para>
    /// <para>
    /// Historically skipped (the activation hook was missing, so the inbound
    /// stream desynced with <c>Pipe completed before a full packet arrived</c>
    /// immediately after auth). The fix added
    /// <see cref="PacketWriter.ActivateDelayedCompression"/> /
    /// <see cref="PacketReader.ActivateDelayedCompression"/> and wired them
    /// from <see cref="SshSession.MarkAuthenticated"/>;
    /// <c>DelayedCompressionActivationTests</c> covers the unit-level
    /// contract, and this test is the live-server confirmation.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Handshake_Compression_ZlibOpenSsh_NegotiatesAndExecRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);

        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await using var session = new SshSession();
        // The Compress flag must be set before handshake so
        // BuildKexInitWithCompressFilter includes zlib in the name-list.
        session.SetFlag(SshFlag.Compress, true);
        // Pin compression to a single algorithm so we know exactly which one
        // was negotiated (otherwise the client pref order would pick
        // zlib@openssh.com first anyway, but pinning removes the ambiguity).
        session[SshMethodType.CompCs] = "zlib@openssh.com";
        session[SshMethodType.CompSc] = "zlib@openssh.com";
        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);

        await AuthenticateAndExecEchoAsync(session, ct);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Negative: an algorithm the client pins but the server does NOT offer
    // must fail with KexFailure. Sanity check that the pinning mechanism
    // really constrains the client offer (otherwise the matrix tests above
    // would pass even if negotiation silently fell back to a default).
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Pinning the client cipher to a name the server does NOT offer must
    /// produce <see cref="SshErrorCode.KexFailure"/>. This is the control
    /// test for the matrix: it proves the pinning actually constrains the
    /// client offer, so the positive tests' success implies real negotiation
    /// of the pinned algorithm.
    /// </summary>
    /// <remarks>
    /// The pinned name is <c>rijndael-cbc@lysator.liu.se</c> — the wire
    /// equivalent of <c>aes256-cbc</c>, IN the port's in-scope cipher registry
    /// (so the set-time preference filter, kex.c:4283-4315 parity, keeps it),
    /// but NOT in the fixture sshd's <c>Ciphers</c> list — so negotiation
    /// finds no overlap and the handshake fails with
    /// <see cref="SshErrorCode.KexFailure"/>. A name outside the registry
    /// (e.g. <c>3des-cbc</c>) can no longer be pinned: the setter strips it
    /// and throws <see cref="SshErrorCode.MethodNotSupported"/> immediately
    /// (the port's in-scope subset consequence of the C's set-time
    /// validation) — covered at unit level by <c>PrefFilterTests</c>.
    /// </remarks>
    [Fact]
    public async Task Handshake_Cipher_UnsupportedByServer_ThrowsKexFailure()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);

        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await using var session = new SshSession();
        session[SshMethodType.CryptCs] = "rijndael-cbc@lysator.liu.se";
        session[SshMethodType.CryptSc] = "rijndael-cbc@lysator.liu.se";

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct));
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Opens a TCP connection to <c>(host, port)</c>, sets the requested
    /// per-category algorithm preferences on a fresh <see cref="SshSession"/>,
    /// and runs the handshake. Returns the handed-shook session (NOT yet
    /// authenticated) for the caller to pass to
    /// <see cref="AuthenticateAndExecEchoAsync"/>.
    /// </summary>
    /// <param name="host">The container host (always loopback from the test
    /// process).</param>
    /// <param name="port">The mapped host port from the started
    /// <see cref="SshDockerContainer"/>.</param>
    /// <param name="kex">Optional single KEX algorithm to pin.</param>
    /// <param name="hostKey">Optional single host-key algorithm to pin.</param>
    /// <param name="cryptCs">Optional client→server cipher to pin.</param>
    /// <param name="cryptSc">Optional server→client cipher to pin.</param>
    /// <param name="macCs">Optional client→server MAC to pin.</param>
    /// <param name="macSc">Optional server→client MAC to pin.</param>
    /// <param name="ct">Cooperative cancellation.</param>
    /// <remarks>
    /// The caller owns the <see cref="SshDockerContainer"/> (via <c>await
    /// using</c>) so the container stays up for the duration of the test;
    /// this helper only owns the <see cref="SshSession"/> + the leaked
    /// <see cref="TcpClient"/> (the socket is closed when the test process
    /// tears the session down).
    /// </remarks>
    private static async Task<SshSession> ConnectWithPrefsAsync(
        string host,
        int port,
        string? kex = null,
        string? hostKey = null,
        string? cryptCs = null,
        string? cryptSc = null,
        string? macCs = null,
        string? macSc = null,
        CancellationToken ct = default)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port, ct);
        var session = new SshSession();
        if (kex is not null)
        {
            session[SshMethodType.Kex] = kex;
        }

        if (hostKey is not null)
        {
            session[SshMethodType.HostKey] = hostKey;
        }

        if (cryptCs is not null)
        {
            session[SshMethodType.CryptCs] = cryptCs;
        }

        if (cryptSc is not null)
        {
            session[SshMethodType.CryptSc] = cryptSc;
        }

        if (macCs is not null)
        {
            session[SshMethodType.MacCs] = macCs;
        }

        if (macSc is not null)
        {
            session[SshMethodType.MacSc] = macSc;
        }

        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        return session;
    }

    /// <summary>
    /// Authenticates with the test password and runs <c>echo hello</c> via an
    /// exec channel, asserting stdout is <c>"hello\n"</c> and exit status is
    /// 0. The round-trip proves the derived cipher/MAC/compression keys
    /// actually encrypt + decrypt real traffic in both directions (a
    /// handshake-only test would pass even if the post-NEWKEYS key
    /// installation was broken).
    /// </summary>
    private static async Task AuthenticateAndExecEchoAsync(SshSession session, CancellationToken ct)
    {
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("echo hello", ct);

        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        Assert.Equal(0, exit);
        Assert.Equal("hello\n", Encoding.UTF8.GetString(ms.ToArray()));
    }
}
