using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Packet-read timeout — parity with libssh2's <c>packet_read_timeout</c>
/// (default 60 s; session.c:474, packet.c:1510-1526, 1633-1642:
/// <c>LIBSSH2_ERROR_TIMEOUT</c> when the expected packet has not arrived
/// within the deadline) and <c>libssh2_session_set_read_timeout</c>'s
/// "&lt;= 0 → default" semantics (session.c:1500-1514). Previously the port
/// blocked until caller cancellation.
/// </summary>
public class ReadTimeoutTests
{
    [Fact]
    public async Task WaitForType_DeadlineElapsed_ThrowsTimeout()
    {
        // Deterministic: the session runs on a FakeTimeProvider; advancing
        // the clock past the deadline fires the queue's read-deadline timer.
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake)
        {
            ReadTimeout = TimeSpan.FromSeconds(5)
        };

        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await handshookTask;

        // The server sends nothing; the wait must time out after 5 s.
        Task<RawPacket> waitTask = session.Queue!.WaitForTypeAsync(
            PacketType.UserauthSuccess, ct);

        fake.Advance(TimeSpan.FromSeconds(6));
        await Task.Delay(TimeSpan.FromMilliseconds(50), ct);   // let the timer fire

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await waitTask);
        Assert.Equal(SshErrorCode.Timeout, ex.ErrorCode);
        Assert.Contains("Timeout waiting for SSH packet", ex.Message, StringComparison.Ordinal);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task WaitForType_DeadlineElapsed_InlinePacketsDoNotRestartClock()
    {
        // The deadline covers the whole wait — a stream of inline-dispatched
        // IGNORE packets must not restart it (the C's wall-clock `left`
        // computation, packet.c:1510-1526).
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake)
        {
            ReadTimeout = TimeSpan.FromSeconds(5)
        };

        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await handshookTask;

        Task<RawPacket> waitTask = session.Queue!.WaitForTypeAsync(
            PacketType.UserauthSuccess, ct);

        // A periodic IGNORE packet every second, then silence — the wait must
        // still time out at 5 s (not survive on restarted clocks).
        for (int i = 0; i < 4; i++)
        {
            fake.Advance(TimeSpan.FromSeconds(1));
            await Task.Delay(TimeSpan.FromMilliseconds(30), ct);
            byte[] ignorePayload = [(byte)PacketType.Ignore, 0, 0, 0, 1, (byte)'x'];
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.Ignore, ignorePayload, ct);
        }

        fake.Advance(TimeSpan.FromSeconds(2));
        await Task.Delay(TimeSpan.FromMilliseconds(50), ct);

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await waitTask);
        Assert.Equal(SshErrorCode.Timeout, ex.ErrorCode);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task WaitForType_CallerCancellation_NotMappedToTimeout()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider())
        {
            ReadTimeout = TimeSpan.FromSeconds(60)
        };

        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await handshookTask;

        using var cts = new CancellationTokenSource();
        Task<RawPacket> waitTask = session.Queue!.WaitForTypeAsync(
            PacketType.UserauthSuccess, cts.Token);

        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await waitTask);

        await session.DisposeAsync();
    }

    [Fact]
    public void ReadTimeout_NonPositive_ResetsToDefault()
    {
        // libssh2_session_set_read_timeout: timeout <= 0 → 60 s default
        // (session.c:1500-1514).
        var session = new SshSession(new FakeTimeProvider());
        Assert.Equal(TimeSpan.FromSeconds(60), session.ReadTimeout);

        session.ReadTimeout = TimeSpan.Zero;
        Assert.Equal(TimeSpan.FromSeconds(60), session.ReadTimeout);

        session.ReadTimeout = TimeSpan.FromSeconds(-5);
        Assert.Equal(TimeSpan.FromSeconds(60), session.ReadTimeout);

        session.ReadTimeout = TimeSpan.FromSeconds(30);
        Assert.Equal(TimeSpan.FromSeconds(30), session.ReadTimeout);
    }

    [Fact]
    public void ReadTimeout_SetBeforeHandshake_IsWiredToQueue()
    {
        var session = new SshSession(new FakeTimeProvider())
        {
            ReadTimeout = TimeSpan.FromSeconds(7)
        };
        Assert.Equal(TimeSpan.FromSeconds(7), session.ReadTimeout);
        // The backing field is pushed at queue creation (verified implicitly
        // by the deadline tests; here we only check the property surface).
    }

    private sealed class DuplexPipeFromPipes : IDuplexPipe
    {
        public DuplexPipeFromPipes(PipeReader input, PipeWriter output)
        {
            Input = input;
            Output = output;
        }

        public PipeReader Input { get; }
        public PipeWriter Output { get; }
    }
}
