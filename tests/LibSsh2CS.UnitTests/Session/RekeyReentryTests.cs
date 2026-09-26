using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Regression test: <c>SshSession.RekeyAsync</c>'s
/// re-entry guard was a plain-bool check-then-set, so the public
/// <c>RekeyAsync</c> racing the pump-triggered rekey callback (different tasks)
/// could both pass the guard and both send <c>KEXINIT</c> — a protocol desync
/// plus two <c>RunExchangeAsync</c> runs racing on the writer/queue. The C is
/// single-threaded and cannot race; the guard is managed-only hardening.
/// </summary>
public class RekeyReentryTests
{
    [Fact]
    public async Task Rekey_ConcurrentSecondCall_ThrowsProto_AndOnlyOneKexInitSent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        // First rekey: sends KEXINIT and parks waiting for the server's KEXINIT
        // (the mock never replies — that's the point: the rekey stays in flight).
        using var cts1 = new CancellationTokenSource();
        Task rekey1 = session.RekeyAsync(cts1.Token);
        RawPacket kex1 = await mock.ServerPacketReader!.ReadPacketAsync(ct);
        Assert.Equal(PacketType.KexInit, kex1.Type);

        // Second concurrent rekey: post-fix the atomic guard throws Proto
        // immediately. Pre-fix it passed the bool guard and sent a SECOND
        // KEXINIT, then hung waiting for the server's reply — the bounded wait
        // turns that hang into a failure.
        Task rekey2 = session.RekeyAsync(ct);
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            rekey2.WaitAsync(TimeSpan.FromSeconds(5), ct));
        Assert.Equal(SshErrorCode.Proto, ex.ErrorCode);
        Assert.Contains("Rekey already in progress", ex.Message);

        // Exactly one KEXINIT reached the wire: a second server-side read must
        // find nothing (post-fix). Pre-fix it would read the second KEXINIT.
        using var cts2 = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            mock.ServerPacketReader.ReadPacketAsync(cts2.Token).AsTask());

        // Cleanup: cancel the parked first rekey, then dispose.
        await cts1.CancelAsync();
        try
        {
            await rekey1.WaitAsync(TimeSpan.FromSeconds(5), ct);
        }
        catch (Exception)
        {
            // OperationCanceledException is the expected outcome.
        }

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
