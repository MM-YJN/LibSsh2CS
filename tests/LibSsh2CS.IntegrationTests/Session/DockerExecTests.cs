using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Phase 3.5 live exec integration tests: runs a real OpenSSH server in Docker
/// (via the shared <see cref="AlpineNoKeySshImageFixture"/> assembly fixture)
/// and exercises the full channel lifecycle — <see cref="SshSession.OpenSessionAsync"/>,
/// <see cref="SshChannel.ExecAsync"/>, <see cref="SshChannel.ReadAsync"/>,
/// <see cref="SshChannel.GetExitStatusAsync"/>, and the close handshake — over
/// a real encrypted transport.
/// </summary>
/// <remarks>
/// <para>
/// The cleartext mock-pipe tests in <c>Channel/</c> (increments 3.2/3.3) cover
/// the channel protocol byte-exactly against canned fixtures; these tests
/// confirm wire parity against a live OpenSSH server, including the read-loop
/// + automatic inbound window-adjust across multiple <c>CHANNEL_DATA</c>
/// packets, the <see cref="SshChannel.WriteAsync"/> outbound path, and (in the
/// rekey variant) the increment-3.4 auto-trigger firing mid-transfer.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerExecTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerExecTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// <c>echo hello</c> → stdout is <c>"hello\n"</c>, exit status is 0.
    /// Core happy path: open → exec → read → exit → close.
    /// </summary>
    [Fact]
    public async Task Exec_EchoCommand_ReturnsExpectedOutputAndExitStatus()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        await using SshChannel channel = await session.OpenSessionAsync(cancellationToken);
        (string? stdout, int exit) = await ExecAndDrainAsync(channel, "echo hello", cancellationToken);

        Assert.Equal("hello\n", stdout);
        Assert.Equal(0, exit);
    }

    /// <summary>
    /// <c>sh -c 'exit 7'</c> → exit status is 7, stdout is empty. Exercises the
    /// non-zero exit-status path.
    /// </summary>
    [Fact]
    public async Task Exec_NonZeroExit_ReturnsExitStatus()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        await using SshChannel channel = await session.OpenSessionAsync(cancellationToken);
        (string? stdout, int exit) = await ExecAndDrainAsync(channel, "sh -c 'exit 7'", cancellationToken);

        Assert.Equal(string.Empty, stdout);
        Assert.Equal(7, exit);
    }

    /// <summary>
    /// <c>seq 1 1000</c> (~3.9 KB output) drains cleanly across multiple
    /// <c>CHANNEL_DATA</c> packets with automatic inbound window-adjust under
    /// the default <see cref="RekeyPolicy"/> (no rekey). All 1000 lines must be
    /// present in order.
    /// </summary>
    [Fact]
    public async Task Exec_LargeOutput_DrainedByRepeatedReads()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        await using SshChannel channel = await session.OpenSessionAsync(cancellationToken);
        (string? stdout, int exit) = await ExecAndDrainAsync(channel, "seq 1 1000", cancellationToken);

        Assert.Equal(0, exit);
        string[] lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(1000, lines.Length);
        Assert.Equal("1", lines[0]);
        Assert.Equal("1000", lines[^1]);
    }

    /// <summary>
    /// <c>cat</c> echoes stdin to stdout: <see cref="SshChannel.WriteAsync"/> a
    /// small payload, <see cref="SshChannel.SendEofAsync"/> to signal
    /// end-of-input, then drain stdout. Verifies the outbound write path +
    /// window bookkeeping and the client→server EOF handshake — the only live
    /// coverage of <see cref="SshChannel.WriteAsync"/>.
    /// </summary>
    [Fact]
    public async Task Exec_StdinEchoedToStdout()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        CancellationToken ct = cancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("cat", ct);

        byte[] input = Encoding.UTF8.GetBytes("libssh2cs exec round-trip\n");
        await channel.WriteAsync(input, ct);
        await channel.SendEofAsync(ct);

        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        Assert.Equal(0, exit);
        Assert.Equal(input, ms.ToArray());
    }

    /// <summary>
    /// Live end-to-end coverage of <see cref="SshChannel.SignalAsync(SshSignal, CancellationToken)"/>
    /// (increment 3.6.2): exec <c>sleep 30</c>, send <c>SIGTERM</c>, await the
    /// close handshake, then assert <see cref="SshChannel.ExitSignal"/> captured
    /// the server's <c>exit-signal "TERM"</c> message. Confirms wire parity
    /// against real OpenSSH — the cleartext mock-pipe test
    /// (<c>SshChannelSignalTests</c>) is the byte-exact anchor; this test
    /// verifies the signal is honored by the server and the exit-signal reply
    /// round-trips through the router into channel state.
    /// </summary>
    [Fact]
    public async Task Exec_SignalTerm_KillsSleepAndReportsExitSignal()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        CancellationToken ct = cancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("sleep 30", ct);

        // Fire SIGTERM at the remote sleep process.
        await channel.SignalAsync(SshSignal.Term, ct);

        // Pump the transport until the server sends "exit-signal" + CLOSE.
        // GetExitStatusAsync internally pumps until exit-status/signal arrives
        // or the channel closes; the server
        // will send SSH_MSG_CHANNEL_REQUEST "exit-signal" "TERM" followed by
        // SSH_MSG_CHANNEL_CLOSE.
        //
        // OpenSSH race tolerance: session_signal_req (session.c) can refuse a
        // signal that arrives before the exec'd child completes setsid() — the
        // one-shot killpg(s->pid, SIGTERM) then fails with ESRCH ("No such
        // process") and the command keeps running (observed live in the
        // parallel suite; the C library hits the identical server race).
        // Retry the signal once after a short grace period if no exit info
        // arrived — by then the child's process group exists, so the second
        // signal is always honored.
        using var graceCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        graceCts.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await channel.GetExitStatusAsync(graceCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            await channel.SignalAsync(SshSignal.Term, ct);
            await channel.GetExitStatusAsync(ct);
        }

        Assert.Equal("TERM", channel.ExitSignal);
    }

    /// <summary>
    /// With a tiny <see cref="RekeyPolicy"/> (<c>MaxBytes = 1024</c>) set before
    /// handshake, the increment-3.4 auto-trigger must fire during a multi-KB
    /// exec transfer and complete without dropping the session. The transfer
    /// must still produce the full expected output and a zero exit status.
    /// Asserts <c>session.RekeyCount &gt;= 1</c> to confirm the rekey actually
    /// ran (a silent no-op would let the transfer succeed without exercising
    /// the rekey path at all).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The 1024-byte threshold is per-direction on the full encrypted wire
    /// frame. Auth replies + the first couple of <c>CHANNEL_DATA</c> packets
    /// push inbound past 1024; the next <c>PumpOnceAsync</c> in the read loop
    /// fires <c>MaybeRekeyAsync</c> → <see cref="SshSession.RekeyAsync"/>. Uses
    /// <c>&gt;= 1</c> (not <c>== 1</c>): at 1024-byte granularity against ~3.9
    /// KB of output the trigger may fire 2–3×, bounded by the per-rekey counter
    /// reset.
    /// </para>
    /// <para>
    /// The hostkey is pinned to <c>ssh-ed25519</c> and the post-rekey
    /// <see cref="SshSession.HostKey"/> + SHA256 fingerprint are asserted
    /// against the container's host key file: a rekey re-runs the exchange
    /// with a fresh K_S, and the session must surface the (re-derived) host
    /// key + fingerprint intact — parity with the C re-copying K_S and
    /// recomputing the hashes on every rekey (kex.c:472-485, 516-556).
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Exec_WithTinyRekeyPolicy_TriggersRekeyWithoutDroppingSession()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        CancellationToken ct = cancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);

        // Connect inline (rather than via SshDockerFixture.ConnectAsync) so the
        // policy can be applied before handshake — the router captures the
        // policy at handshake completion.
        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await using var session = new SshSession();
        session.RekeyPolicy = new RekeyPolicy { MaxBytes = 1024 };
        session[SshMethodType.HostKey] = "ssh-ed25519";
        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        byte[] hostKeyBefore = session.HostKey.ToArray();

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        (string? stdout, int exit) = await ExecAndDrainAsync(channel, "seq 1 1000", ct);

        Assert.Equal(0, exit);
        string[] lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(1000, lines.Length);
        Assert.Equal("1000", lines[^1]);
        Assert.True(session.RekeyCount >= 1,
            "auto-rekey should have fired at least once during the exec transfer; RekeyCount=" + session.RekeyCount);

        // Post-rekey hostkey + fingerprint must still reflect the server's
        // ed25519 host key (the rekey refreshed them from the new K_S).
        Assert.False(session.HostKey.IsEmpty);
        Assert.Equal(hostKeyBefore, session.HostKey);

        string pubLine = await container.GetHostKeyAsync("ed25519", ct);
        byte[] expectedHostKey = Convert.FromBase64String(pubLine.Split(' ')[1]);
        Assert.Equal(expectedHostKey, session.HostKey);
        string expectedSha256 = Convert.ToHexString(SHA256.HashData(expectedHostKey)).ToLowerInvariant();
        Assert.Equal(expectedSha256, session.HostKeyHash(SshHostKeyHashType.Sha256));
    }

    /// <summary>
    /// <c>zlib@openssh.com</c> (delayed) compression must SURVIVE a post-auth
    /// rekey: pin compression to <c>zlib@openssh.com</c>, set a tiny rekey
    /// threshold, authenticate (which activates the delayed compression on
    /// both directions), then transfer ~24 KB. The rekey must fire mid-stream
    /// and the session must stay intact (full output, exit 0).
    /// </summary>
    /// <remarks>
    /// Regression test for a bug in which the NEWKEYS key install
    /// used to recompute <c>compressionActive = Compresses &amp;&amp;
    /// UseInAuth</c> (false for <c>zlib@openssh.com</c>), silently turning
    /// compression OFF client-side at the first post-auth rekey while the
    /// server kept compressing — the session broke on the next compressed
    /// packet. The C's predicate <c>(AUTHENTICATED || use_in_auth)</c>
    /// (transport.c:292-295) persists across rekeys. The existing suites
    /// couldn't catch this: the compression negotiation test never rekeys,
    /// and the rekey test never compresses.
    /// </remarks>
    [Fact]
    public async Task Exec_CompressionZlib_SurvivesPostAuthRekey()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        CancellationToken ct = cancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);

        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await using var session = new SshSession();
        session.RekeyPolicy = new RekeyPolicy { MaxBytes = 1024 };
        // The Compress flag must be set before handshake so the KEXINIT
        // name-lists include zlib@openssh.com (delayed compression).
        session.SetFlag(SshFlag.Compress, true);
        session[SshMethodType.CompCs] = "zlib@openssh.com";
        session[SshMethodType.CompSc] = "zlib@openssh.com";
        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        (string? stdout, int exit) = await ExecAndDrainAsync(channel, "seq 1 5000", ct);

        Assert.Equal(0, exit);
        string[] lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(5000, lines.Length);
        Assert.Equal("5000", lines[^1]);
        Assert.True(session.RekeyCount >= 1,
            "auto-rekey should have fired at least once during the compressed transfer; RekeyCount=" + session.RekeyCount);
    }

    /// <summary>
    /// A zero-length <see cref="SshChannel.ReadAsync"/> must return 0
    /// immediately (the .NET <c>Stream</c> contract) while the exec'd command
    /// is still running — it must NOT block until peer EOF/CLOSE.
    /// </summary>
    /// <remarks>
    /// Regression test for a bug in which the wait loop could
    /// never break out with data, so an empty buffer hung indefinitely on an
    /// idle channel (silently draining inbound data into the FIFOs). The C
    /// returns immediately (channel.c:2207-2218). The 5-second guard CTS
    /// turns a regression (indefinite hang) into a test failure.
    /// </remarks>
    [Fact]
    public async Task Exec_ZeroLengthRead_ReturnsImmediately()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        CancellationToken ct = cancellationToken;
        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("sleep 30", ct);

        // Empty buffer against a running command: must return 0 promptly.
        // The linked CTS fails the test instead of hanging forever if the
        // early-return guard regresses.
        using var guardCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        guardCts.CancelAfter(TimeSpan.FromSeconds(5));
        int read = await channel.ReadAsync(Array.Empty<byte>(), guardCts.Token);
        Assert.Equal(0, read);

        // The channel is still alive: kill the sleep so the container can
        // tear down promptly.
        await channel.SignalAsync(SshSignal.Kill, ct);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs <paramref name="command"/> via <see cref="SshChannel.ExecAsync"/>,
    /// drains all of stdout into a string via repeated
    /// <see cref="SshChannel.ReadAsync"/> until peer EOF (returns 0), then
    /// retrieves the exit status. Returns the decoded stdout and exit code.
    /// </summary>
    private static async Task<(string Stdout, int Exit)> ExecAndDrainAsync(
        SshChannel channel, string command, CancellationToken ct)
    {
        await channel.ExecAsync(command, ct);

        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        return (Encoding.UTF8.GetString(ms.ToArray()), exit);
    }

    // ── 3.6 live concurrent-channels integration ─────────────────────────────

    /// <summary>
    /// Two channels on the same session run <c>exec</c> concurrently — one
    /// <c>seq 1 100</c>, the other <c>seq 1 50</c>. Both outputs must complete
    /// with the correct number of lines, in order, with exit status 0. This is
    /// the increment-3.6 live integration check: the cooperative pumper must
    /// route each channel's DATA + EOF + exit-status correctly under real
    /// network packet timing, with both channels' <c>ReadAsync</c> calls
    /// outstanding simultaneously.
    /// </summary>
    /// <remarks>
    /// Gated identically to the other Docker tests: no-op when Docker is not
    /// reachable.
    /// </remarks>
    [Fact]
    public async Task ConcurrentChannels_TwoExecChannelsRunSimultaneously()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Open both session channels up front.
        await using SshChannel chA = await session.OpenSessionAsync(cancellationToken);
        await using SshChannel chB = await session.OpenSessionAsync(cancellationToken);

        // Drive both exec+drain concurrently. The cooperative pumper must
        // demultiplex each channel's DATA + EOF + exit-status correctly; if it
        // conflates them, one task hangs and Task.WhenAll never returns.
        Task<(string Stdout, int Exit)> taskA =
            ExecAndDrainAsync(chA, "seq 1 100", cancellationToken);
        Task<(string Stdout, int Exit)> taskB =
            ExecAndDrainAsync(chB, "seq 1 50", cancellationToken);

        await Task.WhenAll(taskA, taskB);

        (string stdoutA, int exitA) = await taskA;
        (string stdoutB, int exitB) = await taskB;

        Assert.Equal(0, exitA);
        Assert.Equal(0, exitB);

        // Each output should be exactly N lines numbered 1..N.
        int[] linesA = stdoutA.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(int.Parse).ToArray();
        int[] linesB = stdoutB.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(int.Parse).ToArray();
        Assert.Equal(Enumerable.Range(1, 100).ToArray(), linesA);
        Assert.Equal(Enumerable.Range(1, 50).ToArray(), linesB);
    }
}
