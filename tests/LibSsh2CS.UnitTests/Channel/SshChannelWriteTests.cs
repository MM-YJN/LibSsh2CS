using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.WriteAsync"/>: single-packet writes within
/// the window, splitting at the peer's max-packet size, the 32700
/// <c>WriteChunkCap</c>, blocking when the outbound window is zero (then
/// proceeding on <c>WINDOW_ADJUST</c>), and decrement of the outbound window.
/// Mirrors <c>_libssh2_channel_write</c> (<c>channel.c:2336-2468</c>).
/// </summary>
public class SshChannelWriteTests
{
    // ── Basic write within window ──────────────────────────────────────────

    [Fact]
    public async Task WriteAsync_WithinWindow_SendsOneDataPacket()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 1_000_000, outboundMaxPacket: 32_000);

        byte[] data = [1, 2, 3, 4];
        Task writeTask = ch.WriteAsync(data, TestContext.Current.CancellationToken);

        RawPacket pkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelData, pkt.Type);
        // [94][u32 remoteId=5][u32 len=4][1,2,3,4]
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(5, 4)));
        Assert.Equal(data, pkt.Payload.AsSpan(9, 4).ToArray());

        await writeTask;
        Assert.Equal(1_000_000u - 4u, ch.OutboundWindow);   // decremented
    }

    // ── Splitting at max-packet ────────────────────────────────────────────

    [Fact]
    public async Task WriteAsync_ExceedingMaxPacket_SplitsIntoMultiplePackets()
    {
        // channel.c:2413-2420 — split when the chunk would exceed local.packet_size.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 1_000_000, outboundMaxPacket: 4);   // tiny max packet

        byte[] data = [10, 20, 30, 40, 50, 60, 70];   // 7 bytes → 4 + 3
        Task writeTask = ch.WriteAsync(data, TestContext.Current.CancellationToken);

        RawPacket p1 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        RawPacket p2 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await writeTask;

        Assert.Equal(PacketType.ChannelData, p1.Type);
        Assert.Equal(PacketType.ChannelData, p2.Type);

        // First packet: 4 bytes (the max-packet cap).
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32BigEndian(p1.Payload.AsSpan(5, 4)));
        Assert.Equal([10, 20, 30, 40], p1.Payload.AsSpan(9, 4).ToArray());

        // Second packet: the remaining 3 bytes.
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(p2.Payload.AsSpan(5, 4)));
        Assert.Equal([50, 60, 70], p2.Payload.AsSpan(9, 3).ToArray());
    }

    [Fact]
    public async Task WriteAsync_ExceedingWindow_SplitsAtWindowBoundary()
    {
        // channel.c:2405-2411 — split when the chunk would exceed the window.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 3, outboundMaxPacket: 32_000);

        byte[] data = [1, 2, 3, 4, 5];   // 5 bytes; window is 3 → first chunk = 3
        Task writeTask = ch.WriteAsync(data, TestContext.Current.CancellationToken);

        RawPacket p1 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(p1.Payload.AsSpan(5, 4)));
        Assert.Equal([1, 2, 3], p1.Payload.AsSpan(9, 3).ToArray());
        Assert.Equal(0u, ch.OutboundWindow);   // window exhausted by the first chunk

        // The write now blocks (window=0). Feed a WINDOW_ADJUST to refill.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
            ChannelTestHarness.BuildWindowAdjustPayload(0, bytesToAdd: 10)));
        h.CompleteInbound();

        RawPacket p2 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await writeTask;
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32BigEndian(p2.Payload.AsSpan(5, 4)));
        Assert.Equal([4, 5], p2.Payload.AsSpan(9, 2).ToArray());
    }

    // ── WriteChunkCap (32700) ──────────────────────────────────────────────

    [Fact]
    public async Task WriteAsync_LargerThanWriteChunkCap_SplitsAtCap()
    {
        // channel.c:2351 — buflen capped at 32700 per _libssh2_channel_write call.
        // A 40000-byte write with a large window+maxpacket splits into 32700 + 7300.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 10_000_000, outboundMaxPacket: 100_000);

        byte[] data = new byte[40000];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i & 0xFF);
        }

        Task writeTask = ch.WriteAsync(data, TestContext.Current.CancellationToken);

        RawPacket p1 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        RawPacket p2 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await writeTask;

        Assert.Equal(ChannelConstants.WriteChunkCap,
            (int)BinaryPrimitives.ReadUInt32BigEndian(p1.Payload.AsSpan(5, 4)));
        Assert.Equal(40000 - ChannelConstants.WriteChunkCap,
            (int)BinaryPrimitives.ReadUInt32BigEndian(p2.Payload.AsSpan(5, 4)));
    }

    // ── Block on zero window ───────────────────────────────────────────────

    [Fact]
    public async Task WriteAsync_ZeroWindow_BlocksUntilWindowAdjust()
    {
        // channel.c:2383-2393 — when the outbound window is 0, drain incoming
        // flow until a WINDOW_ADJUST refills it.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 0, outboundMaxPacket: 32_000);   // start blocked

        byte[] data = [0xAB];
        Task writeTask = ch.WriteAsync(data, TestContext.Current.CancellationToken);

        // The write should be blocked (no packet on the wire yet). Confirm by
        // checking that a short wait yields no output, then feed an ADJUST.
        await Task.Yield();
        Assert.False(writeTask.IsCompleted);   // still blocked

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
            ChannelTestHarness.BuildWindowAdjustPayload(0, bytesToAdd: 100)));
        h.CompleteInbound();

        RawPacket pkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await writeTask;
        Assert.Equal(PacketType.ChannelData, pkt.Type);
        Assert.Equal([0xAB], pkt.Payload.AsSpan(9, 1).ToArray());
        Assert.Equal(100u - 1u, ch.OutboundWindow);   // 100 adjusted, 1 written
    }

    [Fact]
    public async Task WriteAsync_ZeroWindow_RoutesNonAdjustPacketsThenProceeds()
    {
        // While blocked on window=0, a DATA packet for ANOTHER channel arrives
        // first; PumpOnce routes it, the write keeps waiting, then an ADJUST
        // for THIS channel unblocks it.
        using var h = new ChannelTestHarness();
        SshChannel chWrite = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 0, outboundMaxPacket: 32_000);
        SshChannel chOther = h.CreateChannel(localId: 1, remoteId: 6);

        Task writeTask = chWrite.WriteAsync(new byte[] { 0x99 }, TestContext.Current.CancellationToken);

        await Task.Yield();
        // Feed: DATA for chOther (must be routed, not stop the wait), then ADJUST for chWrite.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(1, [0x12, 0x34])),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
                ChannelTestHarness.BuildWindowAdjustPayload(0, bytesToAdd: 50)));
        h.CompleteInbound();

        RawPacket pkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await writeTask;
        Assert.Equal(PacketType.ChannelData, pkt.Type);
        Assert.Equal([0x99], pkt.Payload.AsSpan(9, 1).ToArray());

        // chOther received its DATA via the route during the write's pump loop.
        Assert.Equal([0x12, 0x34], chOther.TryDequeueStdout());
    }

    // ── Window decrement ───────────────────────────────────────────────────

    [Fact]
    public async Task WriteAsync_DecrementsOutboundWindow_ByBytesSent()
    {
        // channel.c:2448 — local.window_size -= bufwrite.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            outboundWindow: 1000, outboundMaxPacket: 32_000);

        Task writeTask = ch.WriteAsync(new byte[300], TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await writeTask;

        Assert.Equal(700u, ch.OutboundWindow);
    }
}
