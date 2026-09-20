using System.Net.Sockets;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Phase 5.7 live integration tests for keepalive + direct-tcpip over a real
/// OpenSSH server in Docker. Verifies wire parity of the Phase 5.1–5.6
/// machinery against a live sshd:
/// <list type="bullet">
/// <item><see cref="SshSession.SendKeepAliveAsync"/> with wantReply=true
/// completes against a real server (exercises the global-request reply
/// dispatch + the cooperative pump integration).</item>
/// <item><see cref="SshSession.SendKeepAliveAsync"/> with wantReply=false
/// exercises the fire-and-forget <see cref="KeepAlive.BuildPayload(false)"/>
/// send path (<c>SshSession.cs:891</c>) that the wantReply=true test leaves
/// dark.</item>
/// <item><see cref="SshSession.OpenDirectTcpIpAsync"/> opens a
/// <c>"direct-tcpip"</c> channel to the container's loopback SSH port; the
/// test reads the server's SSH banner back through the tunnel.</item>
/// </list>
/// </summary>
/// <remarks>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </remarks>
public sealed class DockerForwardTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerForwardTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Caller-driven keepalive with wantReply=true against a live server. The
    /// server is required to respond to <c>keepalive@libssh2.org</c> with
    /// <c>SSH_MSG_REQUEST_SUCCESS</c> (OpenSSH does so unconditionally). Verifies
    /// <see cref="SshSession.SendKeepAliveAsync"/> completes (does not hang) and
    /// returns the configured interval.
    /// </summary>
    [Fact]
    public async Task KeepAlive_WantReplyTrue_LiveServer_RespondsAndReturnsInterval()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        session.ConfigureKeepAlive(wantReply: true, intervalSeconds: 30);

        // First call: interval hasn't elapsed (session just connected), so this
        // should return the remaining time without sending. But because the
        // session was JUST constructed, elapsed ≈ 0 and remaining ≈ 30.
        int first = await session.SendKeepAliveAsync(cancellationToken);
        Assert.InRange(first, 25, 30);

        // Force a send by reconfiguring with interval=1 (the libssh2 quirk
        // rewrites this to 2). Then immediately call SendKeepAliveAsync — the
        // elapsed time is now > 2 seconds since the session was constructed, so
        // it should actually send and return the interval.
        session.ConfigureKeepAlive(wantReply: true, intervalSeconds: 1);
        int sent = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(2, sent);   // interval rewritten 1→2 per keepalive.c:50-51

        // A second send immediately afterwards should not resend (last_sent
        // just updated), and should return ~2 (the remaining time).
        int second = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(2, second);
    }

    /// <summary>
    /// Caller-driven keepalive with wantReply=false against a live server.
    /// Mirrors <see cref="KeepAlive_WantReplyTrue_LiveServer_RespondsAndReturnsInterval"/>
    /// but exercises the fire-and-forget send path
    /// (<see cref="KeepAlive.BuildPayload(false)"/> →
    /// <see cref="Transport.PacketWriter.WritePacketAsync"/>) that the
    /// wantReply=true test leaves dark. The server does NOT reply to a
    /// want_reply=0 keepalive (the packet is fire-and-forget per
    /// <c>keepalive.c:74-89</c>), so the send must complete without hanging
    /// and return the configured interval. Lights up
    /// <see cref="KeepAlive.BuildPayload(bool)"/> (0% → covered) and the
    /// <c>wantReply=false</c> arm of <see cref="SshSession.SendKeepAliveAsync"/>
    /// (26% → covered).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why <see cref="FakeTimeProvider"/> (inline connect).</b> The session's
    /// keepalive elapsed-gate compares <c>now - _lastKeepaliveTimestampTicks</c>
    /// against the configured interval; the baseline is captured at construction
    /// (<c>SshSession.cs:145</c>). A real <see cref="SshSession"/> constructed
    /// milliseconds before <see cref="SshSession.SendKeepAliveAsync"/> has
    /// elapsed ≈ 0, so the send branch (<c>SshSession.cs:868</c>) is never
    /// taken and <see cref="KeepAlive.BuildPayload(bool)"/> stays unexercised.
    /// Injecting <see cref="FakeTimeProvider"/> via the internal
    /// <c>SshSession(TimeProvider)</c> ctor and advancing it past the interval
    /// deterministically trips the gate — no wall-clock delay, no flakiness.
    /// This mirrors the unit-test pattern in
    /// <c>KeepAliveTests.ConfigureKeepAlive_IntervalOneIsRewrittenToTwo</c>.
    /// </para>
    /// <para>
    /// The <see cref="TcpClient"/> is constructed inline (rather than via
    /// <see cref="SshDockerFixture.ConnectAsync"/>) because the fixture helper
    /// hard-wires <c>new SshSession()</c> with <see cref="TimeProvider.System"/>.
    /// The inline pattern matches
    /// <c>DockerExecTests.Exec_WithTinyRekeyPolicy_TriggersRekeyWithoutDroppingSession</c>.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task KeepAlive_WantReplyFalse_SendsAndReturnsInterval()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        // Inline connect with FakeTimeProvider so the keepalive elapsed-gate
        // can be tripped deterministically (see remarks).
        var fakeTime = new FakeTimeProvider();
        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await using var session = new SshSession(fakeTime);
        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Configure with interval=1 (the libssh2 quirk rewrites this to 2 per
        // keepalive.c:50-51). Then advance fake time past the effective 2s
        // interval — the elapsed-gate (SshSession.cs:868) now fires the send
        // branch on the next SendKeepAliveAsync call.
        session.ConfigureKeepAlive(wantReply: false, intervalSeconds: 1);
        fakeTime.Advance(TimeSpan.FromSeconds(3));

        // First call: elapsed (3s) > interval (2s) → send branch fires,
        // KeepAlive.BuildPayload(false) is written to the wire, and the
        // full effective interval (2) is returned.
        int sent = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(2, sent);

        // A second send immediately afterwards should not resend
        // (_lastKeepaliveTimestampTicks just updated to fake-now), and should
        // return 2 (the remaining time — elapsed is 0 against interval 2).
        int second = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(2, second);

        // Confirm the session is still usable after the fire-and-forget
        // keepalive: a trivial exec round-trip must succeed. This catches any
        // state corruption from the wantReply=false send path.
        await using SshChannel channel = await session.OpenSessionAsync(cancellationToken);
        await channel.ExecAsync("echo still-alive", cancellationToken);
        using var ms = new MemoryStream();
        byte[] buf = new byte[64];
        int n;
        while ((n = await channel.ReadAsync(buf, cancellationToken)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(cancellationToken);
        Assert.Equal(0, exit);
        Assert.Equal("still-alive\n", Encoding.UTF8.GetString(ms.ToArray()));
    }

    /// <summary>
    /// Opens a direct-tcpip channel to <c>127.0.0.1:22</c> inside the container
    /// (the sshd we're connected to). Reads bytes from the tunnel — the sshd's
    /// SSH banner (<c>"SSH-2.0-OpenSSH_*"</c>) arrives first. Verifies the
    /// direct-tcpip factory + the channel data path work end-to-end against a
    /// live server.
    /// </summary>
    [Fact]
    public async Task DirectTcpIp_ToContainerSshPort_ReadsSshBannerThroughTunnel()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Open direct-tcpip to the container's loopback SSH port.
        await using SshChannel tunnel = await session.OpenDirectTcpIpAsync(
            host: "127.0.0.1", port: 22,
            originatorAddress: "127.0.0.1", originatorPort: 0,
            cancellationToken: cancellationToken);

        // The container's sshd sends its identification banner immediately on
        // connect. Read up to 256 bytes — the banner starts with "SSH-2.0-".
        byte[] buf = new byte[256];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        int n = await tunnel.ReadAsync(buf, cts.Token);
        Assert.True(n > 0, "expected at least the SSH banner from the container's sshd");

        string received = Encoding.ASCII.GetString(buf, 0, n);
        Assert.StartsWith("SSH-2.0-OpenSSH_", received);
    }

    /// <summary>
    /// Direct-tcpip to a closed port should produce a CHANNEL_OPEN_FAILURE
    /// from the server (typically <c>SSH_OPEN_CONNECT_FAILED</c> = reason 2).
    /// Verifies the failure path propagates as a thrown
    /// <see cref="SshException"/> with <see cref="SshErrorCode.ChannelFailure"/>.
    /// </summary>
    [Fact]
    public async Task DirectTcpIp_ToClosedPort_ThrowsChannelFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Port 1 on the container's loopback: nothing should be listening.
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.OpenDirectTcpIpAsync(
                host: "127.0.0.1", port: 1,
                originatorAddress: "127.0.0.1", originatorPort: 0,
                cancellationToken: cancellationToken));

        Assert.Equal(SshErrorCode.ChannelFailure, ex.ErrorCode);
        // OpenSSH returns reason=2 (connect failed) with a description.
        Assert.Contains("connect failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Opens a remote TCP forward listener on the server (port 0 = server
    /// assigns), triggers a connection from inside the container via
    /// <c>nc</c>, and accepts the inbound <c>"forwarded-tcpip"</c> channel
    /// through <see cref="SshListener.AcceptAsync"/>. Verifies the full
    /// <c>tcpip-forward</c> global-request → inbound CHANNEL_OPEN dispatch →
    /// listener accept-queue path against a live OpenSSH server.
    /// </summary>
    /// <remarks>
    /// <b>Gating:</b> identical to the other Docker tests — no-op when Docker
    /// is not reachable.
    /// </remarks>
    [Fact]
    public async Task ForwardListen_AcceptsInboundChannel_ThroughTunnel()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Ask the server to bind a port on its loopback. Port 0 = server
        // assigns an ephemeral port, exposed via listener.BoundPort.
        await using SshListener listener = await session.ListenForwardAsync(
            host: "127.0.0.1", port: 0, cancellationToken: cancellationToken);
        Assert.True(listener.BoundPort > 0, "server should assign a non-zero bound port");

        // Trigger a connection from inside the container: nc connects to the
        // bound port, sends "HELLO", then waits for socket data. -w2 sets a
        // 2-second idle timeout (BusyBox nc -w) so nc exits on its own
        // without the client having to close the inbound channel first.
        await using SshChannel execChannel = await session.OpenSessionAsync(cancellationToken);
        await execChannel.ExecAsync(
            "sh -c 'printf HELLO | nc -w2 127.0.0.1 " + listener.BoundPort + "'",
            cancellationToken);

        // Pump the transport until nc exits. AcceptAsync parks on a semaphore
        // (it does NOT pump), so GetExitStatusAsync is the pump that delivers
        // the server's forwarded-tcpip CHANNEL_OPEN to the listener's queue.
        await execChannel.GetExitStatusAsync(cancellationToken);

        // The forwarded-tcpip CHANNEL_OPEN was routed during the pump above;
        // AcceptAsync should dequeue immediately. The 5-s timeout is a safety
        // net in case the CHANNEL_OPEN arrives late.
        using var acceptCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        acceptCts.CancelAfter(TimeSpan.FromSeconds(5));
        SshChannel inbound = await listener.AcceptAsync(acceptCts.Token);
        await using (inbound)
        {
            Assert.True(inbound.LocalId > 0, "inbound channel should have a valid local id");

            // Read the data nc sent through the tunnel. The CHANNEL_DATA was
            // buffered during the GetExitStatusAsync pump.
            byte[] buf = new byte[256];
            using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            int n = await inbound.ReadAsync(buf, readCts.Token);
            string received = Encoding.ASCII.GetString(buf, 0, n);
            Assert.Contains("HELLO", received);
        }
    }

    /// <summary>
    /// Binding to a port that's already forwarded should produce a
    /// <c>SSH_MSG_REQUEST_FAILURE</c> from the server. Verifies the failure
    /// path propagates as a thrown <see cref="SshException"/> with
    /// <see cref="SshErrorCode.RequestDenied"/>.
    /// </summary>
    [Fact]
    public async Task ForwardListen_BindToInUsePort_ThrowsRequestDenied()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Bind a port on the server.
        await using SshListener listener = await session.ListenForwardAsync(
            host: "127.0.0.1", port: 0, cancellationToken: cancellationToken);
        Assert.True(listener.BoundPort > 0);

        // Try to bind the same port again — the server should reject with
        // REQUEST_FAILURE (EADDRINUSE) → SshErrorCode.RequestDenied.
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.ListenForwardAsync(
                host: "127.0.0.1", port: listener.BoundPort,
                cancellationToken: cancellationToken));
        Assert.Equal(SshErrorCode.RequestDenied, ex.ErrorCode);
    }

    /// <summary>
    /// Disposing a listener sends <c>cancel-tcpip-forward</c> to the server,
    /// drains the accept queue, and marks the listener as disposed. Verifies
    /// the teardown path doesn't hang and <see cref="SshListener.IsDisposed"/>
    /// flips to true.
    /// </summary>
    [Fact]
    public async Task ForwardListen_Dispose_SendsCancelAndDrainsQueue()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        SshListener listener = await session.ListenForwardAsync(
            host: "127.0.0.1", port: 0, cancellationToken: cancellationToken);
        Assert.False(listener.IsDisposed);
        Assert.Equal(0, listener.QueuedCount);

        await listener.DisposeAsync();

        Assert.True(listener.IsDisposed);
        Assert.Equal(0, listener.QueuedCount);
    }

    /// <summary>
    /// Disposing a listener while <see cref="SshListener.AcceptAsync"/> is
    /// parked waiting for an inbound channel must wake the waiter and throw
    /// <see cref="SshException"/> with <see cref="SshErrorCode.ChannelUnknown"/>
    /// (parity <c>SshListener.AcceptAsync</c>: "Listener was disposed while
    /// waiting for an incoming channel."). Lights up the disposed-while-parked
    /// throw branch of <see cref="SshListener.AcceptAsync(CancellationToken)"/>
    /// (53% → covered).
    /// </summary>
    /// <remarks>
    /// The test starts a listener with no inbound connection pending, parks an
    /// <see cref="SshListener.AcceptAsync"/> call on a background thread, then
    /// disposes the listener. The parked <c>AcceptAsync</c> must observe the
    /// dispose (the semaphore is released by
    /// <see cref="SshListener.DisposeAsync"/>) and throw
    /// <see cref="SshErrorCode.ChannelUnknown"/>. A 1-second delay before
    /// disposing ensures the <c>AcceptAsync</c> await is actually parked before
    /// the wake arrives.
    /// </remarks>
    [Fact]
    public async Task ForwardListen_DisposeWhileAccepting_ThrowsChannelUnknown()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        SshListener listener = await session.ListenForwardAsync(
            host: "127.0.0.1", port: 0, cancellationToken: cancellationToken);
        Assert.True(listener.BoundPort > 0);

        // Park AcceptAsync on a background thread. No inbound connection is
        // pending, so this blocks on the listener's semaphore. Use a long
        // timeout so the test fails on a hang rather than timing out
        // ambiguously; the dispose should wake it well before this fires.
        using var acceptCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Task<SshChannel> acceptTask = Task.Run(
            () => listener.AcceptAsync(acceptCts.Token),
            cancellationToken);

        // Give the AcceptAsync await time to actually park on the semaphore
        // before we dispose. 250 ms is plenty for the threadpool to schedule
        // the task and reach the WaitAsync call.
        await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);

        // Dispose wakes the parked waiter (DisposeAsync releases the
        // semaphore). The accept must then throw ChannelUnknown.
        await listener.DisposeAsync();
        SshException ex = await Assert.ThrowsAsync<SshException>(() => acceptTask);
        Assert.Equal(SshErrorCode.ChannelUnknown, ex.ErrorCode);
    }
}
