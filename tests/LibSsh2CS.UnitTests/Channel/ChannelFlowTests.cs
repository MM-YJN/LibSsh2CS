using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// End-to-end channel lifecycle tests over a cleartext mock-pipe peer:
/// the full open → exec → write → read → close flow, exit-status delivery
/// during the close handshake, and two-channel demultiplexing in one session.
/// Both sides drive real <see cref="PacketReader"/>/<see cref="PacketWriter"/>
/// pairs; the mock server interleaves with the client's async steps.
/// </summary>
public class ChannelFlowTests
{
    /// <summary>
    /// The canonical git-transport-style flow: open a session channel, exec a
    /// remote command, write stdin, read stdout, observe EOF, and close. Every
    /// packet on both sides is asserted against the wire format. This is the
    /// strongest parity check — if it passes, the channel sub-system composes
    /// end-to-end.
    /// </summary>
    [Fact]
    public async Task FullLifecycle_OpenExecWriteReadClose()
    {
        using var h = new ChannelTestHarness();
        const uint ServerChId = 500;

        // ── 1. Open ─────────────────────────────────────────────────────────
        Task<SshChannel> openTask = SshChannel.OpenAsync(
            h.ClientWriter, h.Router, TestContext.Current.CancellationToken);

        RawPacket openPkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelOpen, openPkt.Type);
        Assert.Equal("session", ReadStringAt(openPkt.Payload, 1));

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelOpenConfirmation,
            ChannelTestHarness.BuildOpenConfirmationPayload(
                recipientChannel: 0, senderChannel: ServerChId,
                window: ChannelConstants.WindowDefault, maxPacket: ChannelConstants.PacketDefault)));
        SshChannel ch = await openTask;
        Assert.Equal(ServerChId, ch.RemoteId);

        // ── 2. Exec ─────────────────────────────────────────────────────────
        Task execTask = ch.ExecAsync("git-upload-pack '/repo.git'", TestContext.Current.CancellationToken);

        RawPacket execPkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, execPkt.Type);
        Assert.Equal("exec", ReadStringAt(execPkt.Payload, 5));
        Assert.Equal(1, execPkt.Payload[13]);   // want_reply = TRUE

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess,
            BuildReply(PacketType.ChannelSuccess, 0)));
        await execTask;

        // ── 3. Write (client → server) ─────────────────────────────────────
        byte[] stdin = Encoding.UTF8.GetBytes("want-list");
        await ch.WriteAsync(stdin, TestContext.Current.CancellationToken);

        RawPacket dataPkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelData, dataPkt.Type);
        Assert.Equal(ServerChId, BinaryPrimitives.ReadUInt32BigEndian(dataPkt.Payload.AsSpan(1, 4)));
        Assert.Equal(stdin, dataPkt.Payload.AsSpan(9, stdin.Length).ToArray());

        // ── 4. Read (server → client) ──────────────────────────────────────
        byte[] replyBytes = Encoding.UTF8.GetBytes("have-list\n");
        byte[] readBuf = new byte[64];
        Task<int> readTask = ch.ReadAsync(readBuf, TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(0, replyBytes)));

        int n = await readTask;
        Assert.Equal(replyBytes.Length, n);
        Assert.Equal(replyBytes, readBuf.AsSpan(0, n).ToArray());

        // ── 5. Close ───────────────────────────────────────────────────────
        Task closeTask = ch.DisposeAsync().AsTask();

        // Server reads EOF then CLOSE (D1: close sends EOF-if-not-sent first).
        Assert.Equal(PacketType.ChannelEof,
            (await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken)).Type);
        Assert.Equal(PacketType.ChannelClose,
            (await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken)).Type);

        // Server replies with its CLOSE; the client's close handshake completes.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;

        Assert.True(ch.LocalClose);
        Assert.False(h.Router.TryGet(0, out _));   // unregistered
    }

    /// <summary>
    /// An <c>exit-status</c> CHANNEL_REQUEST arriving during the close-wait pump
    /// is captured into channel state before the peer CLOSE
    /// completes the handshake.
    /// </summary>
    [Fact]
    public async Task ExitStatus_ArrivingDuringClose_IsCaptured()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 7);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE

        // Server sends exit-status THEN its CLOSE — interleaved.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelRequest,
                ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 0, wantReply: false)),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
                ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        await closeTask;
        Assert.Equal(0, ch.ExitStatusInternal);
    }

    /// <summary>
    /// Two channels on one session: data for each routes to the right channel
    /// when either is read, and closing one does not affect the other's routing.
    /// </summary>
    [Fact]
    public async Task TwoChannels_RouteIndependently()
    {
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        // Read on A first — the pump may route B's data into B's buffer en route.
        byte[] buf = new byte[16];
        Task<int> readA = chA.ReadAsync(buf, TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(1, [0xB0])),   // for B
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, [0xA0])));  // for A

        int nA = await readA;
        Assert.Equal(1, nA);
        Assert.Equal(0xA0, buf[0]);

        // B's data was routed into B's buffer during A's read pump.
        Assert.Equal([0xB0], chB.TryDequeueStdout());

        // Close A; B remains usable.
        Task closeA = chA.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeA;

        Assert.False(h.Router.TryGet(0, out _));   // A unregistered
        Assert.True(h.Router.TryGet(1, out _));    // B still registered
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string ReadStringAt(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        return Encoding.ASCII.GetString(buf, (int)(offset + 4), (int)len);
    }

    private static byte[] BuildReply(int type, uint recipient)
    {
        byte[] p = new byte[5];
        p[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(1, 4), recipient);
        return p;
    }

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
