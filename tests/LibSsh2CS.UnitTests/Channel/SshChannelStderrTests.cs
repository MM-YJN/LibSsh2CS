using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.ReadStderrAsync"/> and the three
/// <see cref="SshExtendedDataMode"/> values (Normal/Ignore/Merge). The router
/// delivery, Ignore-mode refund, and Merge-mode read path are exercised here.
/// </summary>
public class SshChannelStderrTests
{
    private const uint StderrDataTypeCode = 1;   // SSH_EXTENDED_DATA_STDERR (RFC 4254 §5.2)

    // ── NORMAL mode: stderr buffered separately ────────────────────────────

    [Fact]
    public async Task ReadStderrAsync_Normal_DrainsBufferedStderr()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 7);

        // Pre-buffer stderr via the router path (simulates server sending
        // CHANNEL_EXTENDED_DATA before the client reads).
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [0xE1, 0xE2, 0xE3])));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[16];
        int n = await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(3, n);
        Assert.Equal([0xE1, 0xE2, 0xE3], buf.AsSpan(0, 3).ToArray());
    }

    [Fact]
    public async Task ReadAsync_Normal_DoesNotReturnStderr()
    {
        // Stdout and stderr stay isolated in NORMAL mode.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xAA, 0xBB])),
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [0xCC])));
        h.CompleteInbound();

        // Route both packets.
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[16];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(2, n);
        Assert.Equal([0xAA, 0xBB], buf.AsSpan(0, 2).ToArray());

        // Stderr is still buffered.
        int nErr = await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(1, nErr);
        Assert.Equal(0xCC, buf[0]);
    }

    [Fact]
    public async Task ReadStderrAsync_Normal_ReadsAcrossPackets()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [1, 2, 3])),
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [4, 5])));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[5];
        int n = await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(5, n);
        Assert.Equal([1, 2, 3, 4, 5], buf);
    }

    [Fact]
    public async Task ReadStderrAsync_Normal_PartialWithinPacket()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [1, 2, 3, 4, 5])));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] small = new byte[2];
        int n1 = await ch.ReadStderrAsync(small, TestContext.Current.CancellationToken);
        Assert.Equal(2, n1);
        Assert.Equal([1, 2], small);

        int n2 = await ch.ReadStderrAsync(small, TestContext.Current.CancellationToken);
        Assert.Equal(2, n2);
        Assert.Equal([3, 4], small);

        int n3 = await ch.ReadStderrAsync(small, TestContext.Current.CancellationToken);
        Assert.Equal(1, n3);
        Assert.Equal(5, small[0]);
    }

    [Fact]
    public async Task ReadStderrAsync_Normal_ReturnsZeroOnEof()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[4];
        int n = await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(0, n);
    }

    [Fact]
    public async Task ReadStderrAsync_Normal_DecrementsWindow()
    {
        // channel.c:2221-2222 — read_avail -= bytes_read; remote.window_size -= bytes_read.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [1, 2, 3, 4])));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        uint readAvailBefore = ch.ReadAvail;
        uint windowBefore = ch.InboundWindow;

        byte[] buf = new byte[3];
        int n = await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(3, n);

        Assert.Equal(readAvailBefore - 3, ch.ReadAvail);
        Assert.Equal(windowBefore - 3, ch.InboundWindow);
    }

    // ── IGNORE mode: stderr dropped + refunded ─────────────────────────────

    [Fact]
    public async Task ReadStderrAsync_Ignore_AlwaysReturnsZero()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, TestContext.Current.CancellationToken);

        byte[] buf = new byte[4];
        int n = await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(0, n);
    }

    [Fact]
    public async Task SetExtendedDataMode_ToIgnore_FlushesExistingBufferAndRefundsPeer()
    {
        // Transitioning to Ignore flushes the buffer
        // (parity intent of channel.c:2010-2016) and sends WINDOW_ADJUST.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 11);

        // Pre-buffer 4 bytes of stderr.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [1, 2, 3, 4])));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(4u, ch.ReadAvail);

        // Transition to Ignore — should flush + refund.
        Task setTask = ch.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, TestContext.Current.CancellationToken);

        // Expect a WINDOW_ADJUST on the wire for the 4 freed bytes.
        RawPacket adjust = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelWindowAdjust, adjust.Type);
        Assert.Equal(11u, BinaryPrimitives.ReadUInt32BigEndian(adjust.Payload.AsSpan(1, 4)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32BigEndian(adjust.Payload.AsSpan(5, 4)));

        await setTask;

        Assert.Equal(0u, ch.ReadAvail);

        byte[] buf = new byte[4];
        Assert.Equal(0, await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IgnoreMode_DropsNewStderrAtDeliveryAndRefundsPeer()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // packet.c:994-1030 — NEW stderr arriving while in Ignore is dropped
        // at delivery time, with WINDOW_ADJUST refunded immediately.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, cancellationToken);
        Assert.Equal(0u, ch.ReadAvail);

        // Server sends stderr → router should drop + refund, not buffer.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [0xAB, 0xCD, 0xEF])));
        h.CompleteInbound();

        // Pump the router — this routes the stderr packet via the Ignore path,
        // which writes a WINDOW_ADJUST before returning.
        var pumpTask = Task.Run(async () =>
        {
            try
            {
                await h.Router.PumpOnceAsync(cancellationToken);
            }
            catch (SshException)
            {
                // Pipe completed — fine.
            }
        }, cancellationToken);

        RawPacket adjust = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelWindowAdjust, adjust.Type);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32BigEndian(adjust.Payload.AsSpan(1, 4)));
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(adjust.Payload.AsSpan(5, 4)));

        await pumpTask;

        // read_avail never bumped (data was dropped, not buffered).
        Assert.Equal(0u, ch.ReadAvail);
    }

    [Fact]
    public async Task IgnoreMode_StdoutStillDeliveredNormally()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, cancellationToken);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [0xEE])),
            BuildCleartext(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(0, [0x42])));
        h.CompleteInbound();

        // Pump both packets.
        var pumpTask = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                try
                {
                    await h.Router.PumpOnceAsync(cancellationToken);
                }
                catch (SshException) { }
            }
        }, cancellationToken);

        // Drain the WINDOW_ADJUST from the stderr drop.
        _ = await h.ServerReader.ReadPacketAsync(cancellationToken);
        await pumpTask;

        byte[] buf = new byte[4];
        int n = await ch.ReadAsync(buf, cancellationToken);
        Assert.Equal(1, n);
        Assert.Equal(0x42, buf[0]);
    }

    // ── MERGE mode: stderr returned via ReadAsync ──────────────────────────

    [Fact]
    public async Task ReadAsync_Merge_AlsoReturnsStderr()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xA1])),
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [0xB2])));
        h.CompleteInbound();

        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        byte[] buf = new byte[8];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(2, n);
        Assert.Equal(0xA1, buf[0]);
        Assert.Equal(0xB2, buf[1]);
    }

    [Fact]
    public async Task ReadAsync_Merge_DrainsStdoutBeforeStderr()
    {
        // Documented divergence: Merge drains stdout FIFO before stderr FIFO.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [1, 2])),
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [3, 4])),
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [5, 6])));
        h.CompleteInbound();

        for (int i = 0; i < 3; i++)
        {
            await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        }

        byte[] buf = new byte[8];
        int n = await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(6, n);
        // Stdout [1,2] + [5,6] first, then stderr [3,4].
        Assert.Equal([1, 2, 5, 6, 3, 4], buf.AsSpan(0, 6).ToArray());
    }

    // ── Mode transitions ───────────────────────────────────────────────────

    [Fact]
    public async Task ExtendedDataMode_DefaultIsNormal()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        Assert.Equal(SshExtendedDataMode.Normal, ch.ExtendedDataMode);
    }

    [Fact]
    public async Task SetExtendedDataMode_NormalToMerge_NoFlush()
    {
        // Transitioning between non-Ignore values should NOT touch the buffer.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelExtendedData,
            ChannelTestHarness.BuildChannelExtendedDataPayload(0, StderrDataTypeCode, [1, 2])));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2u, ch.ReadAvail);

        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, TestContext.Current.CancellationToken);
        Assert.Equal(2u, ch.ReadAvail);
        Assert.Equal(SshExtendedDataMode.Merge, ch.ExtendedDataMode);

        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Normal, TestContext.Current.CancellationToken);
        Assert.Equal(2u, ch.ReadAvail);
        Assert.Equal(SshExtendedDataMode.Normal, ch.ExtendedDataMode);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
