using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration tests for the <see cref="SshChannel"/> request surface
/// beyond the basic exec round-trip already covered by
/// <see cref="DockerExecTests"/>. Exercises the CHANNEL_REQUEST paths that
/// <see cref="DockerExecTests"/> leaves dark: <see cref="SshChannel.SetEnvAsync"/>,
/// <see cref="SshChannel.RequestPtyAsync"/> + <see cref="SshChannel.ShellAsync"/>,
/// <see cref="SshChannel.RequestPtyWindowSizeAsync"/>,
/// <see cref="SshChannel.RequestAuthAgentAsync"/>,
/// <see cref="SshChannel.SetExtendedDataModeAsync"/> (Merge) +
/// <see cref="SshChannel.ReadStderrAsync"/>, and the
/// <see cref="SshSignal.Int"/> arm of <see cref="SshChannel.SignalAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each test runs a real OpenSSH server in Docker via the shared
/// <see cref="AlpineNoKeySshImageFixture"/> assembly fixture and exercises
/// the wire parity of one CHANNEL_REQUEST variant against it. The cleartext
/// mock-pipe unit tests (under <c>LibSsh2CS.UnitTests/Channel/</c>) pin the
/// exact bytes; these tests confirm interoperability with a live peer.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerChannelSurfaceTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerChannelSurfaceTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// <see cref="SshChannel.SetEnvAsync"/> delivers a remote environment
    /// variable that the subsequently-exec'd process can read. Verifies the
    /// <c>"env"</c> CHANNEL_REQUEST (want_reply=TRUE) + SUCCESS round-trip and
    /// that OpenSSH applies the variable to the child process environment.
    /// Lights up <see cref="SshChannel.SetEnvAsync"/> (0% → covered).
    /// </summary>
    [Fact]
    public async Task SetEnv_BeforeExec_PassesEnvVarToRemoteProcess()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // Set two env vars to also exercise the multi-pair path.
        await channel.SetEnvAsync("LIBSSH2CS_FOO", "bar", ct);
        await channel.SetEnvAsync("LIBSSH2CS_BAZ", "qux", ct);

        // sh -c reads the variables from its inherited environment.
        await channel.ExecAsync("sh -c 'echo $LIBSSH2CS_FOO/$LIBSSH2CS_BAZ'", ct);

        (string stdout, int exit) = await DrainStdoutAsync(channel, ct);
        Assert.Equal(0, exit);
        Assert.Equal("bar/qux\n", stdout);
    }

    /// <summary>
    /// <see cref="SshChannel.RequestPtyAsync"/> + <see cref="SshChannel.ShellAsync"/>
    /// opens an interactive shell with a pseudo-terminal. The test writes
    /// <c>echo pty-mark; exit 3</c> to the shell's stdin, then EOF, and reads
    /// the shell's stdout back through the PTY. Because a PTY converts \n to
    /// \r\n on output, the assertion tolerates CR. The explicit <c>exit 3</c>
    /// makes the shell terminate with a non-zero status we can assert.
    /// Lights up <see cref="SshChannel.RequestPtyAsync"/> and
    /// <see cref="SshChannel.ShellAsync"/> (both 0% → covered).
    /// </summary>
    /// <remarks>
    /// A PTY-backed shell echoes the input back (local echo), so stdout
    /// contains both the typed command and its output. We assert the output
    /// contains <c>pty-mark</c> and the exit status is 3.
    /// </remarks>
    [Fact]
    public async Task PtyAndShell_RunsInteractiveShellAndExits()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // Request a PTY before starting the shell. xterm is universally
        // supported by OpenSSH; 80x24 is the canonical default.
        await channel.RequestPtyAsync(
            term: "xterm", width: 80, height: 24,
            widthPx: 0, heightPx: 0,
            terminalModes: null, cancellationToken: ct);

        // Start the interactive shell. After this, stdin writes go to the
        // shell's pty and stdout reads come back from it.
        await channel.ShellAsync(ct);

        // Send a command followed by an explicit exit. The shell's local
        // echo will mirror the input; the command output (pty-mark) is what
        // we assert on. Using `exit 3` gives us a distinct exit status to
        // confirm the shell actually ran the command.
        byte[] input = Encoding.UTF8.GetBytes("echo pty-mark\nexit 3\n");
        await channel.WriteAsync(input, ct);
        await channel.SendEofAsync(ct);

        (string stdout, int exit) = await DrainStdoutAsync(channel, ct);

        // PTY converts \n to \r\n on output, and the shell echoes the input
        // line(s) as well. Just assert the marker is present and the exit
        // status is what we asked for.
        Assert.Contains("pty-mark", stdout);
        Assert.Equal(3, exit);
    }

    /// <summary>
    /// <see cref="SshChannel.RequestPtyWindowSizeAsync"/> sends a
    /// <c>"window-change"</c> CHANNEL_REQUEST (want_reply=FALSE) to an
    /// already-started shell. The test opens a PTY shell, sends a
    /// window-change to 120x40, then drives the shell to exit. The
    /// fire-and-forget request should not throw and the shell should still
    /// terminate cleanly. Lights up <see cref="SshChannel.RequestPtyWindowSizeAsync"/>
    /// (0% → covered).
    /// </summary>
    /// <remarks>
    /// OpenSSH acknowledges <c>window-change</c> silently (want_reply=FALSE
    /// per RFC 4254 §6.7), so the test only asserts the send path doesn't
    /// throw and the subsequent shell round-trip still works.
    /// </remarks>
    [Fact]
    public async Task WindowChange_AfterPtyShell_DoesNotThrowAndShellExits()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        await channel.RequestPtyAsync(
            term: "xterm", width: 80, height: 24,
            widthPx: 0, heightPx: 0,
            terminalModes: null, cancellationToken: ct);
        await channel.ShellAsync(ct);

        // Resize the PTY to 120x40 — fire-and-forget, no reply expected.
        await channel.RequestPtyWindowSizeAsync(
            width: 120, height: 40, widthPx: 0, heightPx: 0,
            cancellationToken: ct);

        // Drive the shell to exit so the channel closes cleanly.
        byte[] input = Encoding.UTF8.GetBytes("exit 0\n");
        await channel.WriteAsync(input, ct);
        await channel.SendEofAsync(ct);

        int exit = await channel.GetExitStatusAsync(ct);
        Assert.Equal(0, exit);
    }

    /// <summary>
    /// <see cref="SshChannel.SetExtendedDataModeAsync"/> with
    /// <see cref="SshExtendedDataMode.Normal"/> (the default) keeps stderr
    /// in its own stream: <see cref="SshChannel.ReadAsync"/> returns only
    /// stdout, <see cref="SshChannel.ReadStderrAsync"/> returns only stderr.
    /// The test execs a command that writes one line to each stream and
    /// asserts they come back via the matching read call. Lights up
    /// <see cref="SshChannel.ReadStderrAsync"/> (0% → covered).
    /// </summary>
    [Fact]
    public async Task Stderr_NormalMode_ReadStderrReturnsOnlyStderr()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // Default mode is Normal; make it explicit for documentation.
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Normal, ct);

        // Write one line to stdout and a different one to stderr. The two
        // writes are ordered stdout-first so that in Merge mode they'd
        // interleave differently than we assert here.
        await channel.ExecAsync("sh -c 'echo out-line; echo err-line >&2'", ct);

        // Drain stdout first — ReadAsync must return only "out-line\n".
        string stdout = await DrainStdoutToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);

        // Drain stderr — ReadStderrAsync must return "err-line\n". After
        // GetExitStatusAsync the channel has observed peer EOF/CLOSE so
        // ReadStderrAsync returns 0 once the stderr buffer is drained.
        string stderr = await DrainStderrToEndAsync(channel, ct);

        Assert.Equal(0, exit);
        Assert.Equal("out-line\n", stdout);
        Assert.Equal("err-line\n", stderr);
    }

    /// <summary>
    /// <see cref="SshChannel.SetExtendedDataModeAsync"/> with
    /// <see cref="SshExtendedDataMode.Merge"/> makes <see cref="SshChannel.ReadAsync"/>
    /// also drain the stderr buffer after stdout. The test execs a command
    /// that writes to both streams and asserts a single
    /// <see cref="SshChannel.ReadAsync"/> loop surfaces bytes from both.
    /// Lights up the Merge branch of <see cref="SshChannel.ReadAsync"/> and
    /// the <see cref="SshChannel.SetExtendedDataModeAsync"/> setter
    /// (0% → covered).
    /// </summary>
    /// <remarks>
    /// Per the <see cref="SshExtendedDataMode.Merge"/> doc, this port drains
    /// the stdout FIFO first, then the stderr FIFO (divergence from
    /// libssh2's arrival-order preservation). The assertion tolerates that
    /// ordering: both markers must be present in the merged output.
    /// </remarks>
    [Fact]
    public async Task Stderr_MergeMode_ReadAsyncReturnsBothStreams()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // Switch to Merge BEFORE exec so the router buffers stderr for
        // ReadAsync to drain.
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, ct);

        await channel.ExecAsync("sh -c 'echo out-mark; echo err-mark >&2'", ct);

        // Single ReadAsync loop — must surface both stdout and stderr bytes.
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        string merged = Encoding.UTF8.GetString(ms.ToArray());

        Assert.Equal(0, exit);
        Assert.Contains("out-mark", merged);
        Assert.Contains("err-mark", merged);
    }

    /// <summary>
    /// <see cref="SshChannel.RequestAuthAgentAsync"/> sends the
    /// <c>"auth-agent-req@openssh.com"</c> CHANNEL_REQUEST (want_reply=TRUE)
    /// to ask the server to set up agent-forwarding on this channel. OpenSSH
    /// accepts the request (replies CHANNEL_SUCCESS) when the user is
    /// authenticated; the test asserts the call completes without throwing.
    /// Lights up <see cref="SshChannel.RequestAuthAgentAsync"/>'s OpenSSH
    /// success path (0% → covered).
    /// </summary>
    /// <remarks>
    /// The test does NOT actually forward an agent (no agent is connected
    /// on the client side); it only verifies the request is accepted by the
    /// server. The agent itself is exercised by <see cref="DockerAgentTests"/>.
    /// </remarks>
    [Fact]
    public async Task RequestAuthAgent_OpenSshVariant_AcceptedByServer()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // OpenSSH accepts "auth-agent-req@openssh.com" with CHANNEL_SUCCESS
        // for an authenticated session. The call must not throw.
        await channel.RequestAuthAgentAsync(ct);

        // Run a trivial exec afterwards to confirm the channel is still
        // usable (the request must not have broken the channel state).
        await channel.ExecAsync("echo after-agent", ct);
        (string stdout, int exit) = await DrainStdoutAsync(channel, ct);
        Assert.Equal(0, exit);
        Assert.Equal("after-agent\n", stdout);
    }

    /// <summary>
    /// <see cref="SshChannel.SignalAsync(SshSignal, CancellationToken)"/> with
    /// <see cref="SshSignal.Int"/> delivers SIGINT to the remote process.
    /// Mirrors the existing <c>Exec_SignalTerm_KillsSleepAndReportsExitSignal</c>
    /// test in <see cref="DockerExecTests"/> but with SIGINT, exercising the
    /// <see cref="SshSignal.Int"/> arm of <see cref="SshSignalExtensions.ToWireName"/>
    /// and the server's <c>exit-signal "INT"</c> reply path. Lights up the
    /// <see cref="SshSignal.Int"/> branch (12.5% → covered) and adds a second
    /// live data point for the signal-delivery path.
    /// </summary>
    [Fact]
    public async Task SignalInt_KillsSleepAndReportsExitSignal()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("sleep 30", ct);

        // Fire SIGINT at the remote sleep process.
        await channel.SignalAsync(SshSignal.Int, ct);

        // Pump the transport until the server sends "exit-signal" + CLOSE.
        // GetExitStatusAsync internally pumps until exit-status/signal arrives
        // or the channel closes; OpenSSH replies with exit-signal "INT"
        // followed by SSH_MSG_CHANNEL_CLOSE.
        await channel.GetExitStatusAsync(ct);

        Assert.Equal("INT", channel.ExitSignal);
    }

    /// <summary>
    /// <see cref="SshChannel.IsEof"/> reports <c>false</c> while the channel
    /// has buffered data or the peer has not yet sent EOF, and flips to
    /// <c>true</c> once the peer's EOF has arrived AND the stdout/stderr
    /// buffers are fully drained. Lights up the <see cref="SshChannel.IsEof"/>
    /// getter (0% → covered), which mirrors <c>libssh2_channel_eof</c>'s
    /// "EOF is masked while buffered data remains" semantics
    /// (<c>channel.c:2543-2578</c>).
    /// </summary>
    /// <remarks>
    /// The test execs a command that writes one line, then:
    /// <list type="bullet">
    /// <item>Asserts <see cref="SshChannel.IsEof"/> is <c>false</c> before
    /// reading (either buffered data is present or EOF hasn't arrived).</item>
    /// <item>Drains stdout to peer EOF via <see cref="SshChannel.ReadAsync"/>
    /// (the read loop pumps the transport until the peer's EOF + CLOSE are
    /// observed).</item>
    /// <item>Asserts <see cref="SshChannel.IsEof"/> is <c>true</c> after the
    /// drain — both the peer-EOF flag and the empty-buffer condition are
    /// now satisfied.</item>
    /// </list>
    /// </remarks>
    [Fact]
    public async Task IsEof_FalseBeforeDrain_TrueAfterPeerEofAndBuffersEmpty()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("echo hello", ct);

        // Before draining: the channel may have buffered stdout and/or may
        // not have observed the peer's EOF yet. IsEof must be false.
        Assert.False(channel.IsEof);

        // Drain stdout to EOF — the read loop pumps the transport until
        // ReadAsync returns 0 (peer EOF observed + stdout buffer empty).
        string stdout = await DrainStdoutToEndAsync(channel, ct);

        // After the drain: peer EOF has arrived and the stdout buffer is
        // empty. IsEof must now be true.
        Assert.True(channel.IsEof);
        Assert.Equal("hello\n", stdout);
    }

    /// <summary>
    /// <see cref="SshChannel.WriteStderrAsync"/> sends
    /// <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> with
    /// <c>data_type_code=SSH_EXTENDED_DATA_STDERR</c> (stream id 1) to the
    /// peer. The test opens a PTY-backed shell (so the server reads stdin
    /// and echoes it), writes a marker to stderr via
    /// <see cref="SshChannel.WriteStderrAsync"/>, then sends a second
    /// distinct marker via the regular <see cref="SshChannel.WriteAsync"/>
    /// (stdout) and exits the shell. The shell's local echo surfaces both
    /// markers in the merged stdout stream, proving the extended-data write
    /// path did not break the channel. Lights up
    /// <see cref="SshChannel.WriteStderrAsync"/> (0% → covered).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why a PTY shell and not exec.</b> RFC 4254 §5.2 only specifies
    /// extended data for server→client on session channels; most servers
    /// ignore client→server <c>EXTENDED_DATA</c> on an exec channel (the
    /// child process's stdin is stdout-routed, not stderr-routed). A PTY
    /// shell, however, treats all channel data as terminal input regardless
    /// of the data_type_code, so the stderr-written bytes reach the shell
    /// and are echoed back alongside the stdout-written bytes. This is the
    /// most reliable way to verify the extended-data send path against a
    /// live server without a custom peer.
    /// </para>
    /// <para>
    /// <b>Why <see cref="SshChannel.WaitEofAsync"/> is exercised here.</b>
    /// After <see cref="SshChannel.SendEofAsync"/> + driving the shell to
    /// <c>exit</c>, the test calls <see cref="SshChannel.WaitEofAsync"/> to
    /// block until the peer's EOF arrives — lighting up the
    /// <c>while (!_remoteEof) WaitForStateChangeAsync</c> loop (0% →
    /// covered). <see cref="SshChannel.GetExitStatusAsync"/> already pumps
    /// until exit-status/close, but <see cref="SshChannel.WaitEofAsync"/>
    /// is a distinct public surface that returns as soon as the peer EOF is
    /// observed (before close), so it warrants its own assertion.
    /// </para>
    /// <para>
    /// Per the <see cref="SshChannel.WriteStderrAsync"/> doc, most servers
    /// ignore client→server extended data; the test asserts the call
    /// completes without throwing and the channel remains usable (the
    /// subsequent stdout write + shell exit round-trip succeeds). The
    /// stderr marker may or may not appear in the echo depending on the
    /// server's PTY handling, so the assertion only checks the stdout
    /// marker is present.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task WriteStderr_ToPtyShell_DoesNotBreakChannelAndWaitEofReturnsAfterPeerEof()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // PTY + shell so the server treats all channel data as terminal
        // input (the extended-data stream id is ignored by the PTY layer).
        await channel.RequestPtyAsync(
            term: "xterm", width: 80, height: 24,
            widthPx: 0, heightPx: 0,
            terminalModes: null, cancellationToken: ct);
        await channel.ShellAsync(ct);

        // Write a marker to stderr (EXTENDED_DATA, stream id 1). The PTY
        // layer on the server side routes it to the shell's stdin just like
        // a stdout write; the shell echoes it back. The call must not throw.
        byte[] stderrMarker = Encoding.UTF8.GetBytes("echo stderr-mark\n");
        await channel.WriteStderrAsync(stderrMarker, ct);

        // Write a distinct marker to stdout (regular CHANNEL_DATA) and exit.
        byte[] stdoutMarker = Encoding.UTF8.GetBytes("echo stdout-mark\nexit 0\n");
        await channel.WriteAsync(stdoutMarker, ct);
        await channel.SendEofAsync(ct);

        // WaitEofAsync: blocks until the peer's EOF arrives. After the
        // shell exits and the server sends EOF, this returns. Lights up
        // the while (!_remoteEof) pump loop. The peer-EOF flag is set here;
        // the IsEof property additionally requires the stdout/stderr buffers
        // to be empty, which the drain below ensures.
        await channel.WaitEofAsync(ct);

        // Drain the PTY echo + exit. The stdout marker must be present; the
        // stderr marker may or may not be echoed depending on the server's
        // PTY data_type_code handling, so we only assert the stdout marker.
        string stdout = await DrainStdoutToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);

        // After the drain, the peer-EOF flag is set (WaitEofAsync returned)
        // AND the stdout buffer is empty (DrainStdoutToEndAsync drained it).
        // IsEof must now be true.
        Assert.True(channel.IsEof);
        Assert.Equal(0, exit);
        Assert.Contains("stdout-mark", stdout);
    }

    /// <summary>
    /// <see cref="SshChannel.WaitClosedAsync"/> blocks (pumping the transport)
    /// until the peer sends <c>SSH_MSG_CHANNEL_CLOSE</c>. The test execs a
    /// quick command, drains stdout, sends our own EOF, waits for the peer's
    /// EOF, retrieves the exit status (which pumps until the peer's CLOSE
    /// arrives), then calls <see cref="SshChannel.WaitClosedAsync"/> — which
    /// returns immediately because <c>_remoteClose</c> is already set. Lights
    /// up <see cref="SshChannel.WaitClosedAsync"/> (0% → covered): the method
    /// entry, the <c>_remoteEof</c> guard (line 1930, must be set or it
    /// throws <see cref="SshErrorCode.Inval"/>), and the return path.
    /// </summary>
    /// <remarks>
    /// <b>Why the close has already arrived.</b> <see cref="SshChannel.GetExitStatusAsync"/>
    /// pumps until exit-status/signal OR <c>_remoteClose</c> (SshChannel.cs:1984).
    /// OpenSSH sends <c>CHANNEL_CLOSE</c> right after <c>exit-status</c>, so by
    /// the time <c>GetExitStatusAsync</c> returns, <c>_remoteClose</c> is set
    /// and the <c>while(!_remoteClose)</c> loop body in
    /// <see cref="SshChannel.WaitClosedAsync"/> doesn't execute. The coverage
    /// win is the method entry + guard + return (0% → partial); the
    /// blocks-until-close loop body stays uncovered (exercising it would
    /// require calling <see cref="SshChannel.WaitClosedAsync"/> before the
    /// close arrives, which is awkward to orchestrate against a live server).
    /// </remarks>
    [Fact]
    public async Task WaitClosedAsync_AfterExitStatus_ReturnsWithoutHanging()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("echo bye", ct);

        // Drain stdout → peer EOF observed → GetExitStatusAsync pumps until
        // exit-status + peer CLOSE arrive.
        _ = await DrainStdoutToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);
        Assert.Equal(0, exit);

        // Send our EOF (idempotent if DisposeAsync already sent it) and wait
        // for the peer's EOF — both are required before WaitClosedAsync
        // (the guard at SshChannel.cs:1930 throws Inval if _remoteEof is
        // not set).
        await channel.SendEofAsync(ct);
        await channel.WaitEofAsync(ct);

        // WaitClosedAsync: the peer CLOSE has already arrived during the
        // GetExitStatusAsync pump, so this returns immediately. Wrap in a
        // 10s timeout to fail-fast on a hang (the call itself has no
        // cancellation-aware timeout).
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(10));
        await channel.WaitClosedAsync(cts.Token);
    }

    /// <summary>
    /// <see cref="SshChannel.SignalAsync(SshSignal, CancellationToken)"/> with
    /// <see cref="SshSignal.Usr1"/> delivers <c>SIGUSR1</c> to the remote
    /// process. Mirrors the existing <c>SignalInt_KillsSleepAndReportsExitSignal</c>
    /// test but with <c>SIGUSR1</c>, exercising the <see cref="SshSignal.Usr1"/>
    /// arm of <see cref="SshSignalExtensions.ToWireName"/> live (the unit tests
    /// already cover the switch exhaustively; this adds a second live interop
    /// data point for the signal-delivery path with a different signal name).
    /// </summary>
    /// <remarks>
    /// <c>SIGUSR1</c> is catchable — BusyBox <c>ash</c> (Alpine's default
    /// shell) does not trap it by default, so the <c>sleep</c> child is
    /// terminated. OpenSSH replies with <c>exit-signal "USR1"</c> followed by
    /// <c>SSH_MSG_CHANNEL_CLOSE</c>, matching the <c>SIGTERM</c>/<c>SIGINT</c>
    /// behavior.
    /// </remarks>
    [Fact]
    public async Task SignalUsr1_KillsSleepAndReportsExitSignal()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("sleep 30", ct);

        // Fire SIGUSR1 at the remote sleep process.
        await channel.SignalAsync(SshSignal.Usr1, ct);

        // Pump the transport until the server sends "exit-signal" + CLOSE.
        await channel.GetExitStatusAsync(ct);

        Assert.Equal("USR1", channel.ExitSignal);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Drains stdout into a string via repeated
    /// <see cref="SshChannel.ReadAsync"/> until peer EOF (returns 0), then
    /// retrieves the exit status. Returns the decoded stdout and exit code.
    /// </summary>
    private static async Task<(string Stdout, int Exit)> DrainStdoutAsync(
        SshChannel channel, CancellationToken ct)
    {
        string stdout = await DrainStdoutToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);
        return (stdout, exit);
    }

    /// <summary>Drains stdout to EOF via <see cref="SshChannel.ReadAsync"/>.</summary>
    private static async Task<string> DrainStdoutToEndAsync(
        SshChannel channel, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>Drains stderr to EOF via <see cref="SshChannel.ReadStderrAsync"/>.</summary>
    private static async Task<string> DrainStderrToEndAsync(
        SshChannel channel, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadStderrAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
