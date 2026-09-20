using System.Net.Sockets;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;
using LibSsh2CS.Transport;
using LibSsh2CS.Util;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Transport;

/// <summary>
/// Increment-8 end-to-end gate: a real SSH transport handshake against a live
/// OpenSSH server in Docker. Exercises the full transport stack — banner
/// exchange, KEXINIT build/parse/negotiate, <see cref="KeyExchange.RunExchangeAsync"/>,
/// and <see cref="HostKeyVerifier"/> — against an unmodified sshd. This is the
/// live cross-check for the captured-fixture KATs (the unit tests pin bytes; this
/// test proves interoperability with a real peer).
/// </summary>
/// <remarks>
/// <para>
/// The test completes the SSH <em>transport</em> handshake only (banner → KEX →
/// NEWKEYS → hostkey verify). It does NOT perform userauth or open a channel —
/// that is Phase 2/3 scope. The handshake ends as soon as the derived keys are
/// installed and the hostkey signature is verified, then disconnects.
/// </para>
/// <para>
/// <b>Container:</b> started from the <see cref="AlpineNoAuthSshImageFixture"/>
/// assembly fixture (Alpine 3.20 with password + pubkey auth disabled and no
/// test user created — auth is irrelevant since the handshake never reaches
/// userauth). The image is built once for the whole assembly run.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so the test skips (not fails) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerHandshakeTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoAuthSshImageFixture _alpineNoAuth;

    private const string ClientBanner = "SSH-2.0-LibSsh2CS_1.0";

    public DockerHandshakeTests(
        AlpineNoAuthSshImageFixture alpineNoAuth,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoAuth = alpineNoAuth;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    private ILogger CreateLogger() => _loggerFactory.CreateLogger<DockerHandshakeTests>();

    [Fact]
    public async Task Handshake_AgainstOpenSSH_VerifiesHostKey()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoAuth.StartContainerAsync(_loggerFactory, cancellationToken);

        (NegotiatedMethods neg, KeyExchange.KexExchangeResult result) = await HandshakeAndVerifyAsync(
            SshDockerFixture.Host, container.Port, cancellationToken, hostKeyPref: null)
            .ConfigureAwait(false);

        // The default negotiation picks ECDSA-P256 (the first hostkey the
        // server offers), so VerifyEcdsa is the branch exercised here. The
        // Ed25519/RSA branches are exercised by the pinned tests below.
        Assert.Equal(SshHostKeyType.Ecdsa256, neg.HostKey);
        AssertHostKeyResult(result);
    }

    /// <summary>
    /// Pins the client's host-key preference to <c>ssh-ed25519</c> and runs
    /// the full transport handshake with a real <see cref="HostKeyVerifier.Verify"/>
    /// callback. The server (AlpineNoAuth fixture) generates an Ed25519 host
    /// key via <c>ssh-keygen -A</c>, so negotiation lands on
    /// <c>ssh-ed25519</c> and the verify callback dispatches to
    /// <see cref="HostKeyVerifier"/>'s Ed25519 branch
    /// (<c>VerifyEd25519</c>, 0% before this test). Asserts the negotiated
    /// host-key type and that the signature validates.
    /// </summary>
    [Fact]
    public async Task Handshake_HostKeyEd25519_VerifiesViaHostKeyVerifier()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoAuth.StartContainerAsync(_loggerFactory, cancellationToken);

        (NegotiatedMethods neg, KeyExchange.KexExchangeResult result) = await HandshakeAndVerifyAsync(
            SshDockerFixture.Host, container.Port, cancellationToken, hostKeyPref: "ssh-ed25519")
            .ConfigureAwait(false);

        Assert.Equal(SshHostKeyType.Ed25519, neg.HostKey);
        AssertHostKeyResult(result);
    }

    /// <summary>
    /// Pins the client's host-key preference to <c>rsa-sha2-256</c> and runs
    /// the full transport handshake with a real <see cref="HostKeyVerifier.Verify"/>
    /// callback. The server (AlpineNoAuth fixture) generates an RSA host key
    /// via <c>ssh-keygen -A</c>, so negotiation lands on
    /// <c>rsa-sha2-256</c> and the verify callback dispatches to
    /// <see cref="HostKeyVerifier"/>'s RSA-SHA-256 branch
    /// (<c>VerifyRsa</c> + <c>RsaHash</c> + <c>IsRsaName</c>, 0% before this
    /// test). Asserts the negotiated host-key type and that the signature
    /// validates.
    /// </summary>
    /// <remarks>
    /// <c>rsa-sha2-512</c> is not tested separately because it shares the
    /// same <c>VerifyRsa</c> body (only the <see cref="HashAlgorithmName"/>
    /// differs); the SHA-512 branch of <c>RsaHash</c> is reached via the
    /// <c>DockerNegotiationTests.Handshake_HostKey_RsaSha2_512</c> pinned
    /// negotiation test, and a single RSA verify test is sufficient to light
    /// up the RSA verify body.
    /// </remarks>
    [Fact]
    public async Task Handshake_HostKeyRsaSha2_256_VerifiesViaHostKeyVerifier()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoAuth.StartContainerAsync(_loggerFactory, cancellationToken);

        (NegotiatedMethods neg, KeyExchange.KexExchangeResult result) = await HandshakeAndVerifyAsync(
            SshDockerFixture.Host, container.Port, cancellationToken, hostKeyPref: "rsa-sha2-256")
            .ConfigureAwait(false);

        Assert.Equal(SshHostKeyType.RsaSha256, neg.HostKey);
        AssertHostKeyResult(result);
    }

    /// <summary>
    /// Pins the client's host-key preference to <c>ssh-rsa</c> (RSA with
    /// SHA-1, the legacy variant) and runs the full transport handshake with
    /// a real <see cref="HostKeyVerifier.Verify"/> callback. Lights up the
    /// SHA-1 branch of <see cref="HostKeyVerifier"/>'s
    /// <c>HashData</c> + <c>RsaHash</c> (<c>SshHostKeyType.SshRsa</c> →
    /// <c>HashAlgorithmName.SHA1</c>), which is otherwise dark because the
    /// default negotiation picks ECDSA-P256. The server re-enables
    /// <c>ssh-rsa</c> via <c>HostKeyAlgorithms +ssh-rsa</c> in
    /// <c>SshImageFixtureBase.SshdConfigBase</c>.
    /// </summary>
    [Fact]
    public async Task Handshake_HostKeySshRsa_VerifiesViaHostKeyVerifier()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoAuth.StartContainerAsync(_loggerFactory, cancellationToken);

        (NegotiatedMethods neg, KeyExchange.KexExchangeResult result) = await HandshakeAndVerifyAsync(
            SshDockerFixture.Host, container.Port, cancellationToken, hostKeyPref: "ssh-rsa")
            .ConfigureAwait(false);

        Assert.Equal(SshHostKeyType.SshRsa, neg.HostKey);
        AssertHostKeyResult(result);
    }

    /// <summary>
    /// Asserts the <see cref="KeyExchange.KexExchangeResult"/> carries
    /// non-empty exchange hash / session id / hostkey / signature — the
    /// invariants that hold when <see cref="HostKeyVerifier.Verify"/>
    /// returned <c>true</c> inside <see cref="KeyExchange.RunExchangeAsync"/>.
    /// </summary>
    private static void AssertHostKeyResult(KeyExchange.KexExchangeResult result)
    {
        Assert.True(result.ExchangeHash.Length > 0, "exchange hash must be non-empty");
        Assert.True(result.SessionId.Length > 0, "session id must be non-empty");
        Assert.True(result.HostKey.Length > 0, "server hostkey must be non-empty");
        Assert.True(result.Signature.Length > 0, "hostkey signature must be non-empty");
    }

    /// <summary>
    /// Runs a full SSH transport handshake against <paramref name="host"/>:<paramref name="port"/>,
    /// verifying the server host key via <see cref="HostKeyVerifier"/>. Asserts the
    /// exchange completes and the hostkey signature validates. When
    /// <paramref name="hostKeyPref"/> is non-null, the client's KEXINIT is
    /// built with that single host-key algorithm pinned so the negotiation
    /// lands on it (driving the matching <see cref="HostKeyVerifier"/> verify
    /// branch); otherwise the client offers the full default set and the
    /// server picks.
    /// </summary>
    /// <param name="host">The container host (always loopback from the test process).</param>
    /// <param name="port">The mapped host port from the started container.</param>
    /// <param name="ct">Cooperative cancellation.</param>
    /// <param name="hostKeyPref">Optional single host-key algorithm to pin
    /// (e.g. <c>"ssh-ed25519"</c>, <c>"rsa-sha2-256"</c>, <c>"ssh-rsa"</c>);
    /// <c>null</c> to offer the default set.</param>
    /// <returns>The negotiated methods (so the caller can assert the
    /// host-key type) and the KEX exchange result (carrying the hostkey,
    /// exchange hash, session id, and signature).</returns>
    private static async Task<(NegotiatedMethods Neg, KeyExchange.KexExchangeResult Result)> HandshakeAndVerifyAsync(
        string host, int port, CancellationToken ct, string? hostKeyPref = null)
    {
        // The container's wait strategy (UntilInternalTcpPortIsAvailable) guarantees
        // sshd is accepting on port 22 before StartAsync returns, so a single connect
        // suffices — no poll loop.
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

        NetworkStream stream = tcp.GetStream();

        // ── Banner exchange (raw, pre-packet) ──────────────────────────────
        // Read the server banner line byte-by-byte (no StreamReader buffering so the
        // subsequent pipe sees the exact stream position at the first packet).
        string serverBanner = ReadLine(stream);
        byte[] cb = Encoding.ASCII.GetBytes(ClientBanner + "\r\n");
        await stream.WriteAsync(cb, ct).ConfigureAwait(false);

        // ── Packet I/O via IDuplexPipe over the NetworkStream ──────────────
        var duplex = new StreamDuplexPipe(stream);
        var writer = new PacketWriter(duplex.Output);
        var queue = new PacketQueue(new PacketReader(duplex.Input));

        // Client KEXINIT (BuildKexInit prepends ext-info-c + kex-strict-c).
        // Pin the host-key name-list to a single algorithm when requested so
        // the negotiation lands on it and the verify callback dispatches to
        // the matching HostKeyVerifier branch.
        var prefs = new MethodPreferences();
        if (hostKeyPref is not null)
        {
            prefs[SshMethodType.HostKey] = hostKeyPref;
        }

        byte[] clientKexInit = KeyExchange.BuildKexInit(prefs);
        await writer.WritePacketAsync(PacketType.KexInit, clientKexInit, ct).ConfigureAwait(false);

        // Server KEXINIT.
        RawPacket serverKexInitPkt = await queue.WaitForTypeAsync(PacketType.KexInit, ct)
            .ConfigureAwait(false);
        byte[] serverKexInit = serverKexInitPkt.Payload;   // includes the type byte

        KexInit clientInit = KeyExchange.ParseKexInit(clientKexInit);
        KexInit serverInit = KeyExchange.ParseKexInit(serverKexInit);
        NegotiatedMethods neg = KeyExchange.Negotiate(clientInit, serverInit);

        // ── KEX + hostkey verify (the verify callback closes over neg.HostKey) ──
        KeyExchange.KexExchangeResult result = await KeyExchange.RunExchangeAsync(
            writer, queue, neg,
            ClientBanner, serverBanner,
            clientKexInit, serverKexInit,
            verifyAsync: (hostKey, h, sig, ct2) =>
                Task.FromResult(HostKeyVerifier.Verify(hostKey, h, sig, neg.HostKey)),
            cancellationToken: ct).ConfigureAwait(false);

        return (neg, result);
    }

    /// <summary>Reads a CR/LF-terminated line from a stream one byte at a time (no buffering).</summary>
    private static string ReadLine(Stream s)
    {
        var sb = new StringBuilder();
        while (true)
        {
            int b = s.ReadByte();
            if (b == -1)
            {
                throw new EndOfStreamException("EOF reading SSH banner");
            }

            char c = (char)b;
            sb.Append(c);
            if (c == '\n')
            {
                break;
            }
        }

        return sb.ToString().TrimEnd('\r', '\n');
    }
}
