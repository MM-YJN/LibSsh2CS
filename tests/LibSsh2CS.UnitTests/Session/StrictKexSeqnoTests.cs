using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Regression tests for strict-KEX "first packet must be
/// KEXINIT" (RFC 8709 / packet.c:715-726). When strict KEX is negotiated,
/// the server's KEXINIT must be the very first packet it sent — an on-path
/// attacker (or sloppy server) injecting a pre-KEXINIT packet consumes
/// seqno 0, so the KEXINIT arriving at a nonzero seqno is the Terrapin
/// pre-NEWKEYS injection signal and the session must disconnect with
/// "strict KEX violation: KEXINIT was not the first packet".
/// </summary>
public class StrictKexSeqnoTests
{
    [Fact]
    public async Task Handshake_PreKexInitInjection_StrictKex_ThrowsKexInitNotFirstPacket()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer { SendIgnoreBeforeKexInit = true };
        var session = new SshSession(new FakeTimeProvider());

        // The mock's server KEXINIT advertises kex-strict-s-v00@openssh.com,
        // so strict KEX is negotiated; the injected IGNORE made the KEXINIT's
        // seqno 1. Pre-fix the injection was silently tolerated (the IGNORE is
        // inline-consumed during the KEXINIT wait and the seqno is never
        // checked) and the handshake completed — this assertion fails.
        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
                verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct));

        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Contains("KEXINIT was not the first packet", ex.Message);

        // Tear down. The client threw mid-KEX and owns no pipes, so the mock
        // server is still blocked reading the client's KEXDH_INIT; completing
        // the mock's pipes unblocks it (it then aborts on EOF).
        await session.DisposeAsync();
        mock.Dispose();
        try
        {
            await serverTask.WaitAsync(TimeSpan.FromSeconds(30), ct);
        }
        catch (Exception)
        {
            // The mock aborts when its read of the client's KEXDH_INIT hits EOF.
        }
    }

    [Fact]
    public async Task Handshake_NoInjection_StrictKex_Succeeds()
    {
        // Sanity: without the injection, the first server packet IS the KEXINIT
        // (seqno 0) and the strict-KEX handshake completes normally.
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        Assert.True(mock.Negotiated!.StrictKex);
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
