using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.ReadAsync"/>: stdout draining (full packet,
/// partial across packets, partial within a packet), the 0-on-EOF/CLOSE return,
/// the automatic <c>WINDOW_ADJUST</c> at the threshold, and the
/// <see cref="ChannelConstants.MinAdjust"/> floor.
/// </summary>
public class SshChannelReadTests
{
    // ── Basic drain ────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_DeliversRoutedData_ToCaller()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // Pre-route a DATA packet by pumping (so the buffer is populated before
        // ReadAsync). Using a large inbound window so no WINDOW_ADJUST fires.
        await h.FeedInboundAsync(BuildData(0, [1, 2, 3, 4, 5]));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[16];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);

        Assert.Equal(5, n);
        Assert.Equal([1, 2, 3, 4, 5], buf.AsSpan(0, 5).ToArray());
    }

    [Fact]
    public async Task ReadAsync_PartialRead_WithinOnePacket()
    {
        // Caller's buffer smaller than the packet → ReadAsync returns the
        // partial chunk; a subsequent read returns the remainder.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildData(0, [1, 2, 3, 4, 5, 6, 7, 8]));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] first = new byte[3];
        Assert.Equal(3, await ch.ReadAsync(first, TestContext.Current.CancellationToken));
        Assert.Equal([1, 2, 3], first);

        byte[] rest = new byte[8];
        int n = await ch.ReadAsync(rest, TestContext.Current.CancellationToken);
        Assert.Equal(5, n);
        Assert.Equal([4, 5, 6, 7, 8], rest.AsSpan(0, 5).ToArray());
    }

    [Fact]
    public async Task ReadAsync_ReadsAcrossMultiplePackets()
    {
        // Caller's buffer spans two buffered packets; one ReadAsync call drains
        // across the boundary (channel.c:2118-2205 single-pass over packets).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildData(0, [1, 2, 3]), BuildData(0, [4, 5, 6]));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);   // route pkt 1
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);   // route pkt 2

        byte[] buf = new byte[6];
        Assert.Equal(6, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));
        Assert.Equal([1, 2, 3, 4, 5, 6], buf);
    }

    [Fact]
    public async Task ReadAsync_BlocksUntilDataArrives_ThenReturns()
    {
        // No data buffered; the read should block on PumpOnceAsync until a DATA
        // packet is fed from the server side, then return it.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        byte[] buf = new byte[8];
        Task<int> readTask = ch.ReadAsync(buf, TestContext.Current.CancellationToken);

        // Feed data AFTER the read is pending (server-side write on another
        // turn of the event loop).
        await Task.Yield();
        await h.FeedInboundAsync(BuildData(0, [9, 9, 9]));
        h.CompleteInbound();

        int n = await readTask;
        Assert.Equal(3, n);
        Assert.Equal([9, 9, 9], buf.AsSpan(0, 3).ToArray());
    }

    // ── EOF / CLOSE → return 0 ─────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_ReturnsZero_OnRemoteEof()
    {
        // channel.c:2212 — if remote.eof or remote.close and nothing buffered → 0.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
            ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        byte[] buf = new byte[8];
        Assert.Equal(0, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReadAsync_ReturnsZero_OnRemoteClose()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        byte[] buf = new byte[8];
        Assert.Equal(0, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReadAsync_ReturnsBufferedData_BeforeEof()
    {
        // Data + EOF both queued: read returns the data first; a second read
        // (after EOF is routed) returns 0.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildData(0, [7]), ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
            ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        byte[] buf = new byte[8];
        Assert.Equal(1, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));   // returns the data
        Assert.Equal((byte)7, buf[0]);

        // The EOF was routed during the first read's pump loop; a second read returns 0.
        Assert.Equal(0, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));
    }

    // ── Inbound window maintenance ─────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_SendsWindowAdjust_WhenWindowBelowThreshold()
    {
        // channel.c:2089-2107 — adjust when inbound window < initial*3/4 + buflen.
        // Use a small initial window so the threshold is reachable in a unit test.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1, inboundWindow: 4000, inboundMaxPacket: 4000);

        // Threshold = 4000/4*3 + buflen. With buflen=2000: 3000 + 2000 = 5000.
        // inboundWindow(4000) < 5000 → adjust. adjustment = 4000 + 2000 - 4000 = 2000.
        // (2000 > MinAdjust=1024, so not floored.)
        byte[] buf = new byte[2000];
        Task<int> readTask = ch.ReadAsync(buf, TestContext.Current.CancellationToken);

        // The router is the queue's sole reader; ReadAsync first calls
        // EnsureInboundWindow which writes a WINDOW_ADJUST to the client's
        // outbound pipe. Read it from the server side.
        RawPacket adj = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelWindowAdjust, adj.Type);
        // [93][u32 recip=1][u32 adjustment=2000]
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(adj.Payload.AsSpan(1, 4)));
        Assert.Equal(2000u, BinaryPrimitives.ReadUInt32BigEndian(adj.Payload.AsSpan(5, 4)));

        // The read then blocks on PumpOnceAsync (no data). Feed EOF to unblock
        // it so the test completes (it returns 0).
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
            ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        Assert.Equal(0, await readTask);

        // The window was bumped by the adjustment (4000 + 2000 = 6000).
        Assert.Equal(6000u, ch.InboundWindow);
    }

    [Fact]
    public async Task ReadAsync_WindowAdjust_FlooredToMinAdjust()
    {
        // channel.c:2095-2096 — if computed adjustment < MINADJUST, use MINADJUST.
        // The ctor sets inboundWindow == inboundWindowInitial, so for a fresh
        // channel the threshold check reduces to "buflen > initial/4" and the
        // computed adjustment equals buflen. Pick initial/buflen so the adjust
        // fires AND buflen < MINADJUST (forcing the floor).
        using var h = new ChannelTestHarness();
        // initial=1000: threshold = 1000/4*3 + buflen = 750 + buflen.
        // buflen=500: threshold = 1250 > 1000 ⇒ adjust fires.
        //   computed = initial + buflen - window = 1000 + 500 - 1000 = 500 < 1024 ⇒ floored.
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1, inboundWindow: 1000, inboundMaxPacket: 1000);

        byte[] buf = new byte[500];
        Task<int> readTask = ch.ReadAsync(buf, TestContext.Current.CancellationToken);

        RawPacket adj = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelWindowAdjust, adj.Type);
        Assert.Equal(ChannelConstants.MinAdjust,
            BinaryPrimitives.ReadUInt32BigEndian(adj.Payload.AsSpan(5, 4)));   // floored to 1024

        // Unblock the read with EOF.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
            ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        await readTask;

        // window bumped by MinAdjust: 1000 + 1024 = 2024.
        Assert.Equal(1000u + ChannelConstants.MinAdjust, ch.InboundWindow);
    }

    [Fact]
    public async Task ReadAsync_WindowAboveThreshold_NoAdjustSent()
    {
        // A fresh large window + small read → no WINDOW_ADJUST sent.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);   // default 2 MB window
        uint windowBefore = ch.InboundWindow;

        // Feed EOF so the read returns promptly without blocking.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
            ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        byte[] buf = new byte[16];
        Assert.Equal(0, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));

        // No WINDOW_ADJUST was sent: the window is unchanged, and the client's
        // outbound pipe carries no packets (complete it, then ServerReader reads
        // completed-empty → throws).
        Assert.Equal(windowBefore, ch.InboundWindow);   // unchanged ⇒ no adjust bumped it
        h.CompleteOutbound();
        await Assert.ThrowsAsync<SshException>(async () =>
            await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReadAsync_StderrNotReturned_StdoutOnly()
    {
        // A CHANNEL_EXTENDED_DATA (stderr) packet must NOT be
        // returned by ReadAsync (stdout); it stays in the stderr buffer.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, dataTypeCode: 1, [0xEE])),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelEof,
                ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        byte[] buf = new byte[8];
        // The stderr packet is routed (not delivered to stdout); with EOF also
        // queued, ReadAsync returns 0 (no stdout data).
        Assert.Equal(0, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));

        // But stderr was captured.
        Assert.Equal([0xEE], ch.PeekStderr().Single());
    }

    [Fact]
    public async Task ReadAsync_DecrementsReadAvail_AndInboundWindow()
    {
        // channel.c:2221-2222 — read_avail -= n; remote.window_size -= n.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1, inboundWindow: 100000);

        await h.FeedInboundAsync(BuildData(0, [1, 2, 3, 4]));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        uint windowBefore = ch.InboundWindow;
        Assert.Equal(4u, ch.ReadAvail);

        byte[] buf = new byte[4];
        Assert.Equal(4, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));

        Assert.Equal(0u, ch.ReadAvail);                  // read_avail fully drained
        Assert.Equal(windowBefore - 4u, ch.InboundWindow);   // window decremented
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static byte[] BuildData(uint recipient, byte[] data)
        => ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(recipient, data));
}
