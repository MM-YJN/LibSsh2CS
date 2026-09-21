using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Regression tests: <c>SshSession.HandshakeAsync</c>
/// had no re-entry guard — a second call (retry or concurrent) replaced
/// <c>_writer</c>/<c>_queue</c>/<c>_channelRouter</c> without disposing the old
/// instances (leaking their cipher/MAC state) and two concurrent calls
/// interleaved writes on the same pipe. The C reference
/// (<c>libssh2_session_startup</c>) has no managed disposables and is
/// single-threaded; the re-entry hazard is managed-only.
/// </summary>
public class HandshakeReentryTests
{
    [Fact]
    public async Task Handshake_SecondCallAfterSuccess_ThrowsInvalidOperation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        // A second handshake on the same session must fail fast. Pre-fix it
        // proceeded (replacing the live writer/queue/router) and blocked on the
        // server banner read — the timeout guard turns that hang into a failure.
        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
                verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct)
                .WaitAsync(TimeSpan.FromSeconds(5), ct));

        Assert.Contains("once per session", ex.Message);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_ConcurrentCalls_ExactlyOneProceeds()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());
        var duplex = new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter);
        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);

        // Two concurrent handshakes on the same session: exactly one passes the
        // (atomic) re-entry guard and runs the real exchange; the other throws
        // InvalidOperationException immediately. Pre-fix BOTH proceeded,
        // interleaving writes on the same pipe — the loser of the guard is
        // deterministic post-fix, so exactly one InvalidOperationException is
        // asserted regardless of which call wins.
        Task t1 = session.HandshakeAsync(duplex, (_, _, _) => Task.FromResult(true), ct);
        Task t2 = session.HandshakeAsync(duplex, (_, _, _) => Task.FromResult(true), ct);

        // Bounded per-task waits: pre-fix both calls proceeded and the
        // handshakes hung on the shared pipe (the mock can only serve one
        // banner exchange) — the timeout turns that into a failure. (No
        // WhenAll: the loser's InvalidOperationException is expected.)
        var outcomes = new Exception?[2];
        for (int i = 0; i < 2; i++)
        {
            try
            {
                await (i == 0 ? t1 : t2).WaitAsync(TimeSpan.FromSeconds(10), ct);
            }
            catch (Exception e)
            {
                outcomes[i] = e;
            }
        }

        Assert.Single(outcomes, e => e is InvalidOperationException);
        Assert.Contains(outcomes, e => e is null);   // the winner completed

        // The winner's handshake ran against the mock server to completion.
        await serverTask.WaitAsync(TimeSpan.FromSeconds(10), ct);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_FailedHandshake_CanRetryCleanly()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        // First handshake fails fast: the transport's input pipe is completed
        // empty, so the server-banner read throws immediately.
        var session = new SshSession(new FakeTimeProvider());
        var deadInput = new Pipe();
        var deadOutput = new Pipe();
        await deadInput.Writer.CompleteAsync();
        await Assert.ThrowsAnyAsync<Exception>(() =>
            session.HandshakeAsync(new DuplexPipeFromPipes(deadInput.Reader, deadOutput.Writer),
                verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct)
                .WaitAsync(TimeSpan.FromSeconds(10), ct));

        // The failed handshake must also clear the cached handshake state so
        // the public surface reports "not available" before the retry.
        Assert.True(session.HostKey.IsEmpty);
        Assert.True(session.SessionId.IsEmpty);
        Assert.Null(session.ServerSignatureAlgorithms);
        Assert.Null(session.ServerBanner);

        // The failure path must dispose the fresh writer/queue/router (no leak)
        // AND reset the re-entry guard so a retry is allowed. Post-fix this
        // succeeds; a leak or a stuck guard would break it.
        using var mock = new MockSshServer();
        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        await session.DisposeAsync();
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
