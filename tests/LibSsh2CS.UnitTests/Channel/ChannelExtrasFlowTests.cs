using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// End-to-end lifecycle tests that exercise multiple 3.3 surfaces together:
/// open → RequestPty → Shell → WriteStdin → ReadStdout → SendEof → WaitEof →
/// GetExitStatus → Dispose. Both sides drive real <see cref="PacketReader"/>/
/// <see cref="PacketWriter"/>; every wire byte is asserted. Mirrors the
/// 3.2-shipped <c>ChannelFlowTests</c> pattern.
/// </summary>
public class ChannelExtrasFlowTests
{
    /// <summary>
    /// The canonical interactive-shell lifecycle: open a session, request a
    /// PTY, start a shell, write stdin, read stdout + EOF + exit-status, close.
    /// If this passes, the 3.3 extras compose end-to-end.
    /// </summary>
    [Fact]
    public async Task FullLifecycle_PtyShellStdinStdoutExitStatusClose()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 100);

        // 1. PTY request — client → server.
        Task ptyTask = ch.RequestPtyAsync("xterm", 80, 24, terminalModes: new byte[] { 0 },
            cancellationToken: TestContext.Current.CancellationToken);
        RawPacket ptyReq = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal("pty-req", ReadStringAt(ptyReq.Payload, 5));
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)));
        await ptyTask;

        // 2. Shell request.
        Task shellTask = ch.ShellAsync(TestContext.Current.CancellationToken);
        RawPacket shellReq = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal("shell", ReadStringAt(shellReq.Payload, 5));
        // Shell carries no message — payload ends at want_reply byte (offset 14).
        Assert.Equal(15, shellReq.Payload.Length);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)));
        await shellTask;

        // 3. Write stdin → server receives CHANNEL_DATA.
        Task writeTask = ch.WriteAsync(new byte[] { 0x01, 0x02, 0x03 }, TestContext.Current.CancellationToken);
        RawPacket dataPkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelData, dataPkt.Type);
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(dataPkt.Payload.AsSpan(5, 4)));
        await writeTask;

        // 4. Server sends stdout + exit-status=0 + EOF + CLOSE (single batch;
        //    tests do NOT call CompleteInbound until the end).
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xAA, 0xBB])),
            BuildCleartext(PacketType.ChannelRequest,
                ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 0, wantReply: false)),
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)),
            BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        // 5. Read stdout.
        byte[] buf = new byte[8];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(2, n);
        Assert.Equal([0xAA, 0xBB], buf.AsSpan(0, 2).ToArray());

        // 6. Next read returns 0 (EOF reached); exit-status was captured by the
        //    router during the pump loop.
        int n2 = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(0, n2);
        Assert.True(ch.IsEof);

        int status = await ch.GetExitStatusAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, status);

        // 7. DisposeAsync: client sends EOF + CLOSE; peer's CLOSE already routed.
        Task disposeTask = ch.DisposeAsync().AsTask();
        RawPacket eofPkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelEof, eofPkt.Type);
        RawPacket closePkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelClose, closePkt.Type);
        await disposeTask;
    }

    /// <summary>
    /// SetEnv → exec flow with non-zero exit status. Confirms env + exec +
    /// stdout + exit-status compose across multiple writes on the same channel.
    /// </summary>
    [Fact]
    public async Task FullLifecycle_SetEnvThenExec_WithNonZeroExit()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 50);

        // 1. SetEnv.
        Task envTask = ch.SetEnvAsync("FOO", "bar", TestContext.Current.CancellationToken);
        RawPacket envReq = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal("env", ReadStringAt(envReq.Payload, 5));
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)));
        await envTask;

        // 2. Exec.
        Task execTask = ch.ExecAsync("echo $FOO", TestContext.Current.CancellationToken);
        RawPacket execReq = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal("exec", ReadStringAt(execReq.Payload, 5));
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)));
        await execTask;

        // 3. Server: stdout + exit-status=1 + EOF + CLOSE.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, Encoding.UTF8.GetBytes("bar\n"))),
            BuildCleartext(PacketType.ChannelRequest,
                ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 1, wantReply: false)),
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)),
            BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        byte[] buf = new byte[16];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(4, n);
        Assert.Equal("bar\n", Encoding.UTF8.GetString(buf, 0, n));

        int status = await ch.GetExitStatusAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, status);
    }

    /// <summary>
    /// Two channels on the same session — each gets its own PTY/exec/exit-status.
    /// </summary>
    [Fact]
    public async Task TwoChannels_IndependentPtyAndExitStatus()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch1 = h.CreateChannel(localId: 0, remoteId: 11);
        SshChannel ch2 = h.CreateChannel(localId: 1, remoteId: 22);

        // ch1: PTY.
        Task ptyTask = ch1.RequestPtyAsync("vt100", 40, 13, cancellationToken: TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)));
        await ptyTask;

        // ch2: exec.
        Task execTask = ch2.ExecAsync("ls", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        // 3.6.2: reply recipient must match ch2.LocalId (1); pre-3.6.2 the
        // type-only stash accepted any matching type, masking this typo.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 1)));
        await execTask;

        // Server sends different exit-status per channel. The recipient channel
        // id in the wire payload is the LOCAL id (the id WE assigned); the
        // server addresses us by it. ch1.LocalId=0, ch2.LocalId=1.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelRequest,
                ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 5, wantReply: false)),
            BuildCleartext(PacketType.ChannelRequest,
                ChannelTestHarness.BuildExitStatusPayload(1, exitStatus: 0, wantReply: false)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal(5, await ch1.GetExitStatusAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await ch2.GetExitStatusAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Merge-mode full flow: stdout + stderr + EOF arrive in a single batch;
    /// a single ReadAsync returns both (stdout drained first, then stderr).
    /// The router is pre-pumped so both DATA + EXTENDED_DATA land in their
    /// buffers before <c>ReadAsync</c> runs — mirroring how a real caller would
    /// observe the merged stream after some transport activity.
    /// </summary>
    [Fact]
    public async Task FullLifecycle_MergeModeReturnsStdoutThenStderr()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 7);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xA1])),
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, 1, [0xB2])),
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        // Route DATA + EXTENDED_DATA into the channel buffers first.
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[8];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(2, n);
        Assert.Equal([0xA1, 0xB2], buf.AsSpan(0, 2).ToArray());

        // The EOF packet is still in the pipe; pump it so IsEof reflects the
        // peer's signal. (Production code would observe this via WaitEofAsync.)
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.True(ch.IsEof);
    }

    /// <summary>
    /// Stderr-probe-on-read-zero: read stdout until EOF, then probe stderr for
    /// any server error message using <c>ReadStderrAsync</c>.
    /// </summary>
    [Fact]
    public async Task FullLifecycle_StderrProbeOnReadZero_NormalMode()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        // Server: stdout=ok, stderr=error message, EOF.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, Encoding.UTF8.GetBytes("ok\n"))),
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, 1,
                    Encoding.UTF8.GetBytes("fatal: repository not found\n"))),
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        byte[] stdoutBuf = new byte[16];
        int nStdout = await ch.ReadAsync(stdoutBuf, TestContext.Current.CancellationToken);
        Assert.Equal(3, nStdout);
        Assert.Equal("ok\n", Encoding.UTF8.GetString(stdoutBuf, 0, nStdout));

        // Read stdout again → returns 0 (EOF reached).
        Assert.Equal(0, await ch.ReadAsync(stdoutBuf, TestContext.Current.CancellationToken));

        // Probe stderr for the error message.
        byte[] stderrBuf = new byte[64];
        int nStderr = await ch.ReadStderrAsync(stderrBuf, TestContext.Current.CancellationToken);
        Assert.Equal("fatal: repository not found\n", Encoding.UTF8.GetString(stderrBuf, 0, nStderr));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string ReadStringAt(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        return Encoding.ASCII.GetString(buf, (int)(offset + 4), (int)len);
    }

    private static byte[] BuildReply(int type, uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
