using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.WriteStderrAsync"/>: emits
/// <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> with
/// <c>data_type_code=SSH_EXTENDED_DATA_STDERR (1)</c>. The shared
/// <c>_libssh2_channel_write</c> core is exercised by
/// <see cref="SshChannelWriteTests"/> for the stdout path; this file covers the
/// stderr-specific wire format and the close/eof guards.
/// </summary>
public class SshChannelWriteStderrTests
{
    [Fact]
    public async Task WriteStderrAsync_SendsExtendedDataWithStderrType()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // channel.c:2397-2401 — streamId != 0 → EXTENDED_DATA + [u32 datatype].
        // [95][u32 remote.id][u32 datatype=1][u32 datalen][data]
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 23);

        var t = Task.Run(async () => await ch.WriteStderrAsync(
            new byte[] { 0x10, 0x20, 0x30 }, cancellationToken), cancellationToken);

        RawPacket pkt = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelExtendedData, pkt.Type);
        Assert.Equal((byte)PacketType.ChannelExtendedData, pkt.Payload[0]);
        Assert.Equal(23u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(5, 4)));   // data_type_code = STDERR
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(9, 4)));   // datalen
        Assert.Equal([0x10, 0x20, 0x30], pkt.Payload.AsSpan(13, 3).ToArray());

        await t;
    }

    [Fact]
    public async Task WriteStderrAsync_LargeData_SplitsAtWriteChunkCap()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // Same chunking as WriteAsync (parity channel.c:2351).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        byte[] data = new byte[ChannelConstants.WriteChunkCap + 100];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i & 0xFF);
        }

        var t = Task.Run(async () => await ch.WriteStderrAsync(data, cancellationToken), cancellationToken);

        // First chunk: WriteChunkCap (32700).
        RawPacket p1 = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelExtendedData, p1.Type);
        uint len1 = BinaryPrimitives.ReadUInt32BigEndian(p1.Payload.AsSpan(9, 4));
        Assert.Equal((uint)ChannelConstants.WriteChunkCap, len1);

        // Second chunk: remaining 100 bytes.
        RawPacket p2 = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelExtendedData, p2.Type);
        uint len2 = BinaryPrimitives.ReadUInt32BigEndian(p2.Payload.AsSpan(9, 4));
        Assert.Equal(100u, len2);

        await t;
    }

    [Fact]
    public async Task WriteStderrAsync_AfterDispose_ThrowsChannelClosed()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // Drive a close handshake: feed EOF + CLOSE from peer so DisposeAsync completes.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)),
            BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await ch.DisposeAsync();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.WriteStderrAsync(new byte[] { 1, 2 }, TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.ChannelClosed, ex.ErrorCode);
    }

    [Fact]
    public async Task WriteStderrAsync_SharesWindowBookkeepingWithStdout()
    {
        // Each send decrements _outboundWindow; both stdout and stderr writes
        // share the same window. Two writes of N bytes each → window drops 2N.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1,
            outboundWindow: 10000);

        uint w0 = ch.OutboundWindow;

        await ch.WriteStderrAsync(new byte[] { 1, 2, 3, 4 }, TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        uint w1 = ch.OutboundWindow;
        Assert.Equal(w0 - 4, w1);

        await ch.WriteAsync(new byte[] { 5, 6 }, TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(w1 - 2, ch.OutboundWindow);
    }

    [Fact]
    public async Task WriteStderrAsync_BlocksOnZeroWindowThenProceeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // Outbound window starts at 0; feed a WINDOW_ADJUST so the write proceeds.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1,
            outboundWindow: 0);

        var t = Task.Run(async () => await ch.WriteStderrAsync(new byte[] { 0xAB }, cancellationToken), cancellationToken);

        // Release the window — the blocked writer should now send.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelWindowAdjust,
            ChannelTestHarness.BuildWindowAdjustPayload(0, 4096)));
        h.CompleteInbound();

        RawPacket pkt = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelExtendedData, pkt.Type);
        await t;
    }

    [Fact]
    public async Task WriteStderrAsync_EmptyData_IsNoOp()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await ch.WriteStderrAsync(ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken);

        // Nothing written.
        h.CompleteOutbound();
        await Assert.ThrowsAsync<SshException>(async () =>
            await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task WriteAsync_AndWriteStderrAsync_ProduceDistinctPacketTypes()
    {
        // Confirms the two methods route to the right packet type via the shared
        // WriteDataAsync(streamId, ...) core.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await ch.WriteAsync(new byte[] { 0x01 }, TestContext.Current.CancellationToken);
        await ch.WriteStderrAsync(new byte[] { 0x02 }, TestContext.Current.CancellationToken);

        RawPacket stdout = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelData, stdout.Type);

        RawPacket stderr = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelExtendedData, stderr.Type);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
