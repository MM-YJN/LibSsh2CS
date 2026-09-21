using System.IO.Pipelines;
using System.Security.Cryptography;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Session;

public class HostTrustTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task NullCallback_DoesNotTouchTransportOrConsumeSession(bool stream)
    {
        await using var session = new SshSession();
        ArgumentNullException ex = await Assert.ThrowsAsync<ArgumentNullException>(() => stream
            ? session.HandshakeAsync(Stream.Null, null!, TestContext.Current.CancellationToken)
            : session.HandshakeAsync(new UntouchablePipe(), null!, TestContext.Current.CancellationToken));
        Assert.Equal("verifyHostKeyAsync", ex.ParamName);
        using var mock = new MockSshServer();
        CancellationToken ct = TestContext.Current.CancellationToken;
        Task server = mock.RunAsync("SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            (_, _, _) => Task.FromResult(true), ct);
        await server;
    }

    [Theory]
    [InlineData("accept")]
    [InlineData("reject")]
    [InlineData("throw")]
    [InlineData("cancel")]
    [InlineData("bad-signature")]
    public async Task Callback_EnforcesInitialTrustAfterSignature(string mode)
    {
        using var mock = new MockSshServer { CorruptSignature = mode == "bad-signature" };
        await using var session = new SshSession();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        Task server = mock.RunAsync("SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cts.Token);
        int calls = 0;
        var expected = new InvalidOperationException("trust lookup failed");
        Task handshake = session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            async (key, hash, ct) =>
            {
                calls++;
                Assert.Equal(mock.HostKeyBlob, key);
                Assert.Equal(mock.ExchangeHash, hash);
                Assert.Equal(cts.Token, ct);
                if (mode == "throw")
                {
                    throw expected;
                }

                if (mode == "cancel")
                {
                    await cts.CancelAsync();
                    ct.ThrowIfCancellationRequested();
                }

                return mode == "accept";
            }, cts.Token);
        if (mode == "accept")
        {
            await handshake;
            await server;
        }
        else
        {
            if (mode == "throw")
            {
                Assert.Same(expected, await Assert.ThrowsAsync<InvalidOperationException>(() => handshake));
            }
            else if (mode == "cancel")
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => handshake);
            }
            else
            {
                SshException ex = await Assert.ThrowsAsync<SshException>(() => handshake);
                Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
            }

            await cts.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => server);
        }

        Assert.Equal(mode == "bad-signature" ? 0 : 1, calls);
    }

    [Theory]
    [InlineData("match", 22)]
    [InlineData("match", 2222)]
    [InlineData("mismatch", 22)]
    [InlineData("unknown", 22)]
    public async Task TrustedFile_OnlyMatchAllowsHandshake(string outcome, int port)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var mock = new MockSshServer();
        await using var session = new SshSession();
        session[SshMethodType.HostKey] = "ssh-ed25519";
        Task server = mock.RunAsync("SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cts.Token);
        // RunAsync generates the host seed before its first transport await.
        byte[] pub = LibSsh2CS.Crypto.Ed25519.GetPublicKey(mock.HostKeySeed);
        byte[] blob = [.. Convert.FromHexString("0000000b7373682d6564323535313900000020"), .. pub];
        if (outcome == "mismatch")
        {
            blob[^1] ^= 1;
        }

        string host = outcome == "unknown" ? "other.example" : "server.example";
        string entry = port == 22 ? host : $"[{host}]:{port}";
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, $"{entry} ssh-ed25519 {Convert.ToBase64String(blob)}\n", ct);
            using var knownHosts = new SshKnownHosts();
            await knownHosts.ReadFileAsync(path, cancellationToken: ct);
            Task handshake = session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
                (key, _, token) =>
                {
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult(knownHosts.Check("server.example", port, key,
                        SshKnownHostKeyType.Ed25519).Status == SshKnownHostCheckStatus.Match);
                }, cts.Token);
            if (outcome == "match")
            {
                await handshake;
                await server;
            }
            else
            {
                SshException ex = await Assert.ThrowsAsync<SshException>(() => handshake);
                Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
                await cts.CancelAsync();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => server);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>
    /// The trust callback receives copies of <c>K_S</c> and <c>H</c>: a
    /// callback that mutates its arguments must not corrupt the session's
    /// stored host key, session id, or fingerprint.
    /// </summary>
    /// <remarks>
    /// Before the fix the callback saw the KEX layer's live arrays — the same
    /// instances kept for key derivation and stored in the session — so writing
    /// to them changed <see cref="SshSession.HostKey"/>,
    /// <see cref="SshSession.SessionId"/>, and
    /// <see cref="SshSession.HostKeyHash"/>.
    /// </remarks>
    [Fact]
    public async Task Callback_MutatingArguments_DoesNotCorruptSessionState()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        await using var session = new SshSession();

        Task server = mock.RunAsync("SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            (key, hash, _) =>
            {
                // Mutate every byte the callback was handed.
                key.AsSpan().Fill(0xAA);
                hash.AsSpan().Fill(0xBB);
                return Task.FromResult(true);
            }, ct);
        await server;

        Assert.Equal(mock.HostKeyBlob, session.HostKey.ToArray());
        Assert.Equal(mock.ExchangeHash, session.SessionId.ToArray());

        string expectedFingerprint =
            Convert.ToHexString(SHA256.HashData(mock.HostKeyBlob)).ToLowerInvariant();
        Assert.Equal(expectedFingerprint, session.HostKeyHash(SshHostKeyHashType.Sha256));
    }

    /// <summary>
    /// A handshake that fails after the KEX has produced <c>K_S</c>/<c>H</c>
    /// must leave the session's handshake state cleared: the public surface has
    /// to report "not available" rather than a partial handshake.
    /// </summary>
    /// <remarks>
    /// The mock answers SERVICE_REQUEST with a mismatched service name, so the
    /// client throws <see cref="SshErrorCode.Proto"/> after
    /// <c>_hostKey</c>/<c>_sessionId</c> were populated by the KEX.
    /// </remarks>
    [Fact]
    public async Task FailedHandshakeAfterKex_ClearsHandshakeState()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var mock = new MockSshServer { ServiceAcceptOverride = "ssh-not-userauth" };
        await using var session = new SshSession();

        Task server = mock.RunAsync("SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cts.Token);
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
                (_, _, _) => Task.FromResult(true), cts.Token));

        Assert.Equal(SshErrorCode.Proto, ex.ErrorCode);
        Assert.True(session.HostKey.IsEmpty);
        Assert.True(session.SessionId.IsEmpty);
        Assert.Null(session.ServerSignatureAlgorithms);
        Assert.Null(session.ServerBanner);
        Assert.Throws<InvalidOperationException>(() => session.HostKeyHash(SshHostKeyHashType.Sha256));

        await server;
    }

    private sealed class UntouchablePipe : IDuplexPipe
    {
        public PipeReader Input => throw new InvalidOperationException("Transport accessed");
        public PipeWriter Output => throw new InvalidOperationException("Transport accessed");
    }
}
