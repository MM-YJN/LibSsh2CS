using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration tests for
/// <see cref="SshSession.OpenDirectStreamLocalAsync"/>: opens a
/// <c>direct-streamlocal@openssh.com</c> channel to a Unix-domain socket
/// inside a real OpenSSH server in Docker (via the shared
/// <see cref="AlpineStreamLocalSshImageFixture"/> assembly fixture, which
/// adds <c>socat</c> to the Alpine image for the Unix-socket listener).
/// Lights up <see cref="SshSession.OpenDirectStreamLocalAsync"/> +
/// <see cref="SshChannel.BuildDirectStreamLocalExtra"/> (both 0% before
/// this test).
/// </summary>
/// <remarks>
/// <para>
/// <b>Test flow.</b> Each test:
/// <list type="number">
/// <item>Starts a <c>socat UNIX-LISTEN</c> listener inside the container
/// via a background exec (a separate exec channel runs
/// <c>nohup socat ... &</c> and returns immediately).</item>
/// <item>Opens a <c>direct-streamlocal@openssh.com</c> channel to the
/// socket path via <see cref="SshSession.OpenDirectStreamLocalAsync"/>.
/// OpenSSH's sshd connects the channel to the Unix socket on the server
/// side.</item>
/// <item>Writes data to the channel (which arrives at the Unix socket) and
/// reads the echo back (the <c>socat EXEC:cat</c> listener echoes received
/// data back through the socket to the channel).</item>
/// </list>
/// </para>
/// <para>
/// <b>Why <c>socat EXEC:cat</c>.</b> BusyBox <c>nc</c> in Alpine does not
/// support <c>-U</c> (Unix-domain sockets). <c>socat</c> with
/// <c>UNIX-LISTEN:...,fork EXEC:cat</c> spawns a <c>cat</c> process per
/// connection that echoes received bytes back through the socket — a
/// minimal echo server that lets the test verify both the write and read
/// directions of the streamlocal channel.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerStreamLocalTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineStreamLocalSshImageFixture _alpineStreamLocal;

    public DockerStreamLocalTests(
        AlpineStreamLocalSshImageFixture alpineStreamLocal,
        ITestOutputHelper testOutputHelper)
    {
        _alpineStreamLocal = alpineStreamLocal;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Opens a <c>direct-streamlocal@openssh.com</c> channel to a
    /// <c>socat UNIX-LISTEN</c> echo server inside the container, writes a
    /// marker, and reads the echo back. Verifies the full
    /// <c>SSH_MSG_CHANNEL_OPEN "direct-streamlocal@openssh.com"</c> round-trip
    /// + the channel data path in both directions over a real Unix-domain
    /// socket forwarded through sshd. Lights up
    /// <see cref="SshSession.OpenDirectStreamLocalAsync"/> +
    /// <see cref="SshChannel.BuildDirectStreamLocalExtra"/> (both 0% →
    /// covered).
    /// </summary>
    [Fact]
    public async Task DirectStreamLocal_ToUnixSocketEcho_RoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string SocketPath = "/tmp/libssh2cs-streamlocal.sock";

        await using SshDockerContainer container = await _alpineStreamLocal.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        // Start the socat Unix-socket echo listener in the background via an
        // exec channel. The `nohup ... &` + `sleep 0.2` pattern lets the exec
        // return immediately while socat keeps running in the background.
        // EXEC:cat echoes received bytes back through the socket.
        await using (SshChannel starterChannel = await session.OpenSessionAsync(ct))
        {
            await starterChannel.ExecAsync(
                "rm -f " + SocketPath + " && nohup socat UNIX-LISTEN:" + SocketPath + ",fork EXEC:cat >/dev/null 2>&1 & sleep 0.2",
                ct);
            // Drain the exec channel so the transport is in a clean state
            // before opening the streamlocal channel.
            await starterChannel.GetExitStatusAsync(ct);
        }

        // Open the direct-streamlocal channel to the Unix socket. sshd
        // connects the channel to the socket; socat's forked cat process
        // echoes received data back.
        await using SshChannel streamChannel = await session.OpenDirectStreamLocalAsync(
            socketPath: SocketPath,
            originatorAddress: "127.0.0.1",
            originatorPort: 0,
            cancellationToken: ct);

        // Write a marker through the channel → arrives at the Unix socket →
        // cat echoes it back → read it from the channel.
        byte[] marker = Encoding.UTF8.GetBytes("streamlocal-echo\n");
        await streamChannel.WriteAsync(marker, ct);
        await streamChannel.SendEofAsync(ct);

        // Read the echo back. Use a short timeout in case the server closes
        // the socket before echoing (socat EXEC:cat exits after the socket
        // peer sends EOF, which we did above).
        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        readCts.CancelAfter(TimeSpan.FromSeconds(5));
        byte[] buf = new byte[256];
        int n = await streamChannel.ReadAsync(buf, readCts.Token);
        Assert.True(n > 0, "expected the echo marker back through the streamlocal channel");

        string received = Encoding.UTF8.GetString(buf, 0, n);
        Assert.Equal("streamlocal-echo\n", received);
    }
}
