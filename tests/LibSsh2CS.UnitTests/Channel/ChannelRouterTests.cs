using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="ChannelRouter"/>: channel-id demultiplexing, the
/// per-type routing branches (DATA / EXTENDED_DATA / WINDOW_ADJUST / EOF /
/// CLOSE / REQUEST), packet-size + window truncation, exit-status capture, and
/// the <c>wait_reply</c>→<c>CHANNEL_FAILURE</c> reply.
/// </summary>
/// <remarks>
/// All tests use the cleartext <see cref="ChannelTestHarness"/>;
/// the router is cipher-agnostic. Each test feeds one or more framed packets
/// to the client's inbound pipe, pumps the router once (or to a reply), and
/// inspects the target channel's delivered state via its internal accessors.
/// </remarks>
public class ChannelRouterTests
{
    // ── Registration / id allocation ───────────────────────────────────────

    [Fact]
    public void AllocateLocalId_IsSequential_FromZero()
    {
        // _libssh2_channel_nextid (channel.c:64-89): sequential from 0.
        using var h = new ChannelTestHarness();

        Assert.Equal(0u, h.Router.AllocateLocalId());
        Assert.Equal(1u, h.Router.AllocateLocalId());
        Assert.Equal(2u, h.Router.AllocateLocalId());
    }

    [Fact]
    public void Register_And_TryGet()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 7);

        Assert.True(h.Router.TryGet(7, out SshChannel? found));
        Assert.Same(ch, found);
        Assert.False(h.Router.TryGet(8, out _));
    }

    [Fact]
    public void Unregister_RemovesChannel()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 7);

        h.Router.Unregister(ch);
        Assert.False(h.Router.TryGet(7, out _));
    }

    // ── CHANNEL_DATA routing ───────────────────────────────────────────────

    [Fact]
    public async Task PumpOnce_RoutesChannelData_ToStdoutBuffer()
    {
        // packet.c:964-1082 — DATA payload appended to the target channel.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [1, 2, 3, 4])));
        h.CompleteInbound();

        // Pump-once routes exactly one channel packet, then returns.
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal([1, 2, 3, 4], ch.TryDequeueStdout());
        Assert.Equal(4u, ch.ReadAvail);   // read_avail bumped by data length
    }

    [Fact]
    public async Task PumpOnce_RoutesExtendedData_ToStderrBuffer()
    {
        // EXTENDED_DATA (data_type_code=STDERR=1) → stderr buffer.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, dataTypeCode: 1, [9, 9])));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        // stdout empty, stderr has the data.
        Assert.Null(ch.TryDequeueStdout());
        byte[][] stderr = ch.PeekStderr().ToArray();
        Assert.Single(stderr);
        Assert.Equal([9, 9], stderr[0]);
        Assert.Equal(2u, ch.ReadAvail);
    }

    // ── Demux across multiple channels ─────────────────────────────────────

    [Fact]
    public async Task WaitAsync_RoutesByRecipientChannelId_DemuxesAcrossChannels()
    {
        // The crux of the router: a packet for channel B must not be delivered
        // to channel A, even when A is the one pumping.
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0);
        SshChannel chB = h.CreateChannel(localId: 1);

        // Feed DATA for B, then DATA for A.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(1, [0xBB])),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, [0xAA])));
        h.CompleteInbound();

        // Pump twice: first routes B's packet, second routes A's.
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        // A's stdout has only 0xAA; B's stdout has only 0xBB.
        Assert.Equal([0xAA], chA.TryDequeueStdout());
        Assert.Equal([0xBB], chB.TryDequeueStdout());
    }

    [Fact]
    public async Task WaitAsync_UnknownRecipientChannel_SilentlyDropped()
    {
        // packet.c:973-978 — DATA for an unknown channel id is dropped.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(999, [1, 2])));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Null(ch.TryDequeueStdout());
        Assert.Equal(0u, ch.ReadAvail);
    }

    // ── WINDOW_ADJUST routing ──────────────────────────────────────────────

    [Fact]
    public async Task WaitAsync_RoutesWindowAdjust_ToOutboundWindow()
    {
        // packet.c:1306-1325 — bytestoadd added to local.window_size (outbound).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, outboundWindow: 1000);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
            ChannelTestHarness.BuildWindowAdjustPayload(0, bytesToAdd: 4096)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1000u + 4096u, ch.OutboundWindow);
    }

    [Fact]
    public async Task WaitAsync_WindowAdjustForOtherChannel_DoesNotAffectThis()
    {
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, outboundWindow: 1000);
        SshChannel chB = h.CreateChannel(localId: 1, outboundWindow: 2000);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
            ChannelTestHarness.BuildWindowAdjustPayload(1, bytesToAdd: 500)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1000u, chA.OutboundWindow);   // unchanged
        Assert.Equal(2500u, chB.OutboundWindow);   // got the adjust
    }

    // ── EOF / CLOSE routing ─────────────────────────────────────────────────

    [Fact]
    public async Task WaitAsync_RoutesEof_SetsRemoteEof()
    {
        // packet.c:1103 — remote.eof = 1.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        Assert.False(ch.RemoteEof);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
            ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.True(ch.RemoteEof);
        Assert.False(ch.RemoteClose);   // EOF alone does not close
    }

    [Fact]
    public async Task WaitAsync_RoutesClose_SetsRemoteCloseAndEof()
    {
        // packet.c:1232-1233 — remote.close = 1; remote.eof = 1.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.True(ch.RemoteClose);
        Assert.True(ch.RemoteEof);   // CLOSE implies EOF
    }

    [Fact]
    public async Task WaitAsync_DataAfterEof_RevokesRemoteEof()
    {
        // packet.c:1060 — receiving DATA clears remote.eof. Feed EOF, then DATA.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
                ChannelTestHarness.BuildEofPayload(0)),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, [0x01])));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);   // routes EOF
        Assert.True(ch.RemoteEof);

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);   // routes DATA
        Assert.False(ch.RemoteEof);   // revoked
    }

    // ── CHANNEL_REQUEST: exit-status / exit-signal ───────────

    [Fact]
    public async Task WaitAsync_RoutesExitStatus_CapturedInternally()
    {
        // packet.c:1141-1144 — exit_status stored on the channel.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 42, wantReply: false)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal(42, ch.ExitStatusInternal);
    }

    [Fact]
    public async Task WaitAsync_RoutesExitSignal_CapturedInternally()
    {
        // packet.c:1169-1183 — exit signal name stored on the channel.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitSignalPayload(0, signal: "TERM", wantReply: false)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal("TERM", ch.ExitSignalInternal);
    }

    [Fact]
    public async Task WaitAsync_ExitStatusWantReplyTrue_SendsChannelFailure()
    {
        // packet.c:1196-1205 — any CHANNEL_REQUEST with want_reply=TRUE gets a
        // CHANNEL_FAILURE back. The reply goes to the server's channel id
        // (= channel.RemoteId).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 555);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 0, wantReply: true)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        // The router wrote CHANNEL_FAILURE to the client's outbound pipe; read
        // it from the mock-server side and verify it's addressed to remoteId.
        RawPacket reply = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelFailure, reply.Type);
        // Payload: [100][u32 recipient=555]
        Assert.Equal(555u, ReadUInt32At(reply.Payload, 1));
        Assert.Equal(0, ch.ExitStatusInternal);   // status was still captured
    }

    // ── packet-size / window truncation (packet.c:1037-1069) ───────────────

    [Fact]
    public async Task WaitAsync_DataExceedingInboundMaxPacket_Truncated()
    {
        // packet.c:1037-1046 — payload beyond remote.packet_size is truncated.
        using var h = new ChannelTestHarness();
        // Construct a channel with a small advertised inbound max packet.
        // (InboundMaxPacket is always PacketDefault; we send a payload larger
        // than it to exercise the truncation.)
        SshChannel ch = h.CreateChannel(localId: 0);

        byte[] oversize = new byte[ChannelConstants.PacketDefault + 100];
        for (int i = 0; i < oversize.Length; i++)
        {
            oversize[i] = (byte)(i & 0xFF);
        }

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(0, oversize)));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[]? delivered = ch.TryDequeueStdout();
        Assert.NotNull(delivered);
        Assert.Equal((int)ChannelConstants.PacketDefault, delivered.Length);
    }

    // NOTE: the window-full drop path (packet.c:1047-1058, InboundWindow <=
    // read_avail) is deferred to 3.2.4. With the 3.2.1 fixed 2 MB inbound
    // window it would need ~64 × 32 KB packets (and a multi-MB synchronous pipe
    // write that deadlocks the Pipe pause-watermark). 3.2.4 makes the inbound
    // window mutable (ReadAsync decrements it), so the drop path becomes
    // trivially exercisable at small scale.

    // ── Reply-wait mode: routes interleaved channel packets ────────────────

    [Fact]
    public async Task WaitAsync_ReplyMode_RoutesChannelPacketsUntilReplyArrives()
    {
        // Exec-wait style: replyTypes=[SUCCESS]. A DATA and a WINDOW_ADJUST
        // arrive first (for THIS channel); both are routed, then SUCCESS is
        // returned.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, outboundWindow: 500);

        // Build a CHANNEL_SUCCESS payload: [99][u32 recip].
        byte[] successPayload = new byte[5];
        successPayload[0] = (byte)PacketType.ChannelSuccess;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(successPayload.AsSpan(1, 4), 0u);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, [1, 2])),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
                ChannelTestHarness.BuildWindowAdjustPayload(0, bytesToAdd: 100)),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelSuccess, successPayload));
        h.CompleteInbound();

        RawPacket reply = await h.Router.WaitAsync(
            [PacketType.ChannelSuccess, PacketType.ChannelFailure], TestContext.Current.CancellationToken);

        // The interleaved DATA + ADJUST were routed (not stashed), then SUCCESS returned.
        Assert.Equal(PacketType.ChannelSuccess, reply.Type);
        Assert.Equal([1, 2], ch.TryDequeueStdout());           // DATA was routed
        Assert.Equal(600u, ch.OutboundWindow);                  // ADJUST applied (500 + 100)
    }

    [Fact]
    public async Task WaitAsync_ReplyMode_UnsolicitedReplyType_StashedForLater()
    {
        // A SUCCESS arriving while we pump-once (replyTypes=[]) is NOT in the
        // combined set (it's a reply type, not a channel-async type), so the
        // queue stashes it. A subsequent reply-wait retrieves it from the stash.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        byte[] successPayload = new byte[5];
        successPayload[0] = (byte)PacketType.ChannelSuccess;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(successPayload.AsSpan(1, 4), 0u);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, [7])),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelSuccess, successPayload));
        h.CompleteInbound();

        // Pump-once: routes the DATA. The SUCCESS is stashed by the queue (not
        // in ChannelAsyncTypes, not in the empty replyTypes).
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal([7], ch.TryDequeueStdout());

        // Now wait for SUCCESS — retrieved from the stash (pipe is completed).
        RawPacket reply = await h.Router.WaitAsync(
            [PacketType.ChannelSuccess, PacketType.ChannelFailure], TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelSuccess, reply.Type);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static uint ReadUInt32At(byte[] buf, int offset)
        => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
}
