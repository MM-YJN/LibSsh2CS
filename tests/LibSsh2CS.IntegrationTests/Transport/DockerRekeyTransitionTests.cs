using System.Net.Sockets;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Transport;

/// <summary>
/// Live NEWKEYS transition tests against a real OpenSSH server. Each test pins
/// <c>chacha20-poly1305@openssh.com</c> for both directions and
/// <c>curve25519-sha256</c> so the strict-KEX sequence reset is exercised, then
/// forces a rekey through a supported trigger (time-based at a channel open,
/// byte-threshold during a bulk write, and byte-threshold across two concurrent
/// writers). The deterministic writer-barrier regression lives in the unit
/// suite; these tests validate the same transition over a real encrypted socket.
/// </summary>
/// <remarks>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/> calls
/// <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally, so
/// tests skip (not fail) when Docker is not reachable.
/// </remarks>
public sealed class DockerRekeyTransitionTests : IDisposable
{
    private const string ChaChaPoly1305 = "chacha20-poly1305@openssh.com";

    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerRekeyTransitionTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// The time-based rekey trigger fires on the first channel operation after
    /// the interval. With ChaCha20-Poly1305 and strict KEX pinned, the channel
    /// open pumps the transport and runs the NEWKEYS transition inline; the
    /// exec that follows must round-trip on the installed keys.
    /// </summary>
    [Fact]
    public async Task TimeTriggeredRekey_AtChannelOpen_ChaChaStrictKex_Completes()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectAndAuthenticateAsync(
            container.Port,
            new RekeyPolicy
            {
                MaxBytes = long.MaxValue,
                MaxPackets = long.MaxValue,
                MaxInterval = TimeSpan.FromSeconds(2),
            },
            ct);

        AssertStrictKex(session);
        byte[] hostKeyBefore = session.HostKey.ToArray();
        Assert.Equal(0, session.RekeyCount);

        // The time check runs at channel-op boundaries; sleep past the interval
        // so the next pump (the channel open) fires RekeyAsync inline.
        await Task.Delay(TimeSpan.FromSeconds(3), ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        (string stdout, int exit) = await ExecAndDrainAsync(channel, "echo after-time-rekey", ct);

        Assert.Equal(0, exit);
        Assert.Equal("after-time-rekey\n", stdout);
        Assert.True(session.RekeyCount >= 1,
            $"the time-triggered rekey did not fire; RekeyCount={session.RekeyCount}");
        Assert.Equal(hostKeyBefore, session.HostKey);
    }

    /// <summary>
    /// A bulk client write with a tiny byte-based rekey threshold. The
    /// auto-trigger fires at write-pump boundaries, so application packets must
    /// wait behind each NEWKEYS transition. The remote side stores the bytes and
    /// reports their count after EOF; a lost or reordered packet would change
    /// that count.
    /// </summary>
    [Fact]
    public async Task AutoRekey_WhileWriting_ChaChaStrictKex_AllBytesArrive()
    {
        const int TotalBytes = 64 * 1024;
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectAndAuthenticateAsync(
            container.Port,
            new RekeyPolicy { MaxBytes = 4096, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            ct);

        AssertStrictKex(session);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync(
            "sh -c 'cat > /tmp/rekey-write.bin; wc -c < /tmp/rekey-write.bin'", ct);

        byte[] payload = CreatePayload(TotalBytes, 251);
        await WriteAllAsync(channel, payload, ct);

        string stdout = await ReadToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);

        Assert.Equal(0, exit);
        Assert.Equal(TotalBytes.ToString(), stdout.Trim());
        Assert.True(session.RekeyCount >= 1,
            $"expected a rekey during the bulk write; RekeyCount={session.RekeyCount}");

        await using SshChannel second = await session.OpenSessionAsync(ct);
        (string secondStdout, int secondExit) = await ExecAndDrainAsync(second, "echo still-usable", ct);
        Assert.Equal(0, secondExit);
        Assert.Equal("still-usable\n", secondStdout);
    }

    /// <summary>
    /// Two channels write concurrently while a tiny rekey policy fires NEWKEYS
    /// transitions from either channel's pump. This is the live multi-writer
    /// version of the transition race: the writer barrier must keep both
    /// streams intact across the rekeys.
    /// </summary>
    [Fact]
    public async Task AutoRekey_TwoConcurrentWriters_ChaChaStrictKex_BothComplete()
    {
        const int TotalBytes = 32 * 1024;
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await ConnectAndAuthenticateAsync(
            container.Port,
            new RekeyPolicy { MaxBytes = 2048, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            ct);

        AssertStrictKex(session);

        await using SshChannel channelA = await session.OpenSessionAsync(ct);
        await using SshChannel channelB = await session.OpenSessionAsync(ct);
        await channelA.ExecAsync(
            "sh -c 'cat > /tmp/rekey-a.bin; wc -c < /tmp/rekey-a.bin'", ct);
        await channelB.ExecAsync(
            "sh -c 'cat > /tmp/rekey-b.bin; wc -c < /tmp/rekey-b.bin'", ct);

        byte[] payloadA = CreatePayload(TotalBytes, 191);
        byte[] payloadB = CreatePayload(TotalBytes, 193);

        // Concurrent writers on two channels; each write pump may trigger a
        // rekey, and the other writer must wait behind the NEWKEYS barrier.
        var writeA = Task.Run(() => WriteAllAsync(channelA, payloadA, ct), ct);
        var writeB = Task.Run(() => WriteAllAsync(channelB, payloadB, ct), ct);
        await Task.WhenAll(writeA, writeB);

        Task<string> readA = ReadToEndAsync(channelA, ct);
        Task<string> readB = ReadToEndAsync(channelB, ct);
        string[] counts = await Task.WhenAll(readA, readB);
        int exitA = await channelA.GetExitStatusAsync(ct);
        int exitB = await channelB.GetExitStatusAsync(ct);

        Assert.Equal(0, exitA);
        Assert.Equal(0, exitB);
        Assert.Equal(TotalBytes.ToString(), counts[0].Trim());
        Assert.Equal(TotalBytes.ToString(), counts[1].Trim());
        Assert.True(session.RekeyCount >= 1,
            $"expected a rekey across the concurrent writers; RekeyCount={session.RekeyCount}");
    }

    /// <summary>
    /// Opens a TCP connection, pins the strict-KEX ChaCha suite, applies the
    /// rekey policy before handshake (the router captures it at handshake
    /// completion), and authenticates. The <see cref="TcpClient"/> is
    /// intentionally leaked, matching the other Docker helpers: the session does
    /// not own the caller's socket, and the test process is short-lived.
    /// </summary>
    private static async Task<SshSession> ConnectAndAuthenticateAsync(
        int port, RekeyPolicy policy, CancellationToken ct)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, port, ct);

        var session = new SshSession { RekeyPolicy = policy };
        session[SshMethodType.Kex] = "curve25519-sha256";
        session[SshMethodType.HostKey] = "ssh-ed25519";
        session[SshMethodType.CryptCs] = ChaChaPoly1305;
        session[SshMethodType.CryptSc] = ChaChaPoly1305;

        await session.HandshakeAsync(
            tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword, cancellationToken: ct);
        return session;
    }

    /// <summary>
    /// Asserts that the connection actually negotiated strict KEX. The pinned
    /// Alpine/OpenSSH image advertises it by default; failing here means the
    /// tests no longer cover the seqno-reset path they were written for.
    /// </summary>
    private static void AssertStrictKex(SshSession session)
    {
        Assert.NotNull(session.Queue);
        Assert.True(session.Queue!.StrictKex,
            "strict KEX was not negotiated; the NEWKEYS seqno-reset transition is not covered");
    }

    /// <summary>
    /// Writes the whole payload in fixed slices, then sends EOF. The write pump
    /// checks the rekey thresholds between slices, so a tiny threshold fires
    /// rekeys while this loop is running.
    /// </summary>
    private static async Task WriteAllAsync(SshChannel channel, byte[] payload, CancellationToken ct)
    {
        const int SliceSize = 4096;
        for (int offset = 0; offset < payload.Length; offset += SliceSize)
        {
            await channel.WriteAsync(
                payload.AsMemory(offset, Math.Min(SliceSize, payload.Length - offset)), ct);
        }

        await channel.SendEofAsync(ct);
    }

    /// <summary>Drains a channel's stdout until peer EOF.</summary>
    private static async Task<string> ReadToEndAsync(SshChannel channel, CancellationToken ct)
    {
        using var stdout = new MemoryStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = await channel.ReadAsync(buffer, ct)) > 0)
        {
            stdout.Write(buffer.AsSpan(0, read));
        }

        return Encoding.UTF8.GetString(stdout.ToArray());
    }

    /// <summary>Runs a command, drains stdout, and returns the text plus exit status.</summary>
    private static async Task<(string Stdout, int Exit)> ExecAndDrainAsync(
        SshChannel channel, string command, CancellationToken ct)
    {
        await channel.ExecAsync(command, ct);
        string stdout = await ReadToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);
        return (stdout, exit);
    }

    /// <summary>Builds a deterministic, compressible test payload.</summary>
    private static byte[] CreatePayload(int length, int modulus)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i % modulus);
        }

        return payload;
    }
}
