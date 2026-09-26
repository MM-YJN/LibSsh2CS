using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Regression tests for channel window exhaustion and receive-window refunds.
/// </summary>
public class ChannelWindowRefundTests
{
    // ── WaitEofAsync must surface CHANNEL_WINDOW_FULL ───────────────

    /// <summary>
    /// The C's <c>libssh2_channel_wait_eof</c> returns
    /// <c>CHANNEL_WINDOW_FULL</c> when the receive window holds no free bytes
    /// (channel.c:2607-2611) — with a full window of unread data the peer can
    /// never deliver the EOF, so the pre-fix port's block-until-EOF loop
    /// waited for a packet that cannot arrive. Post-fix the exhausted window
    /// is detected up front and surfaced as
    /// <see cref="SshErrorCode.ChannelWindowFull"/>.
    /// </summary>
    [Fact]
    public async Task WaitEof_FullInboundWindow_ThrowsChannelWindowFull()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        // Fill the inbound window (2 MiB default) with unread DATA — the
        // pumper routes it into the channel's FIFO; read_avail reaches the
        // window and the peer's data credit is exhausted. Feed and pump per
        // packet: the pipe's 64 KiB backpressure would block the feed loop if
        // nothing drained it.
        const int PacketPayload = 32 * 1024;
        int packets = (int)(ChannelConstants.WindowDefault / PacketPayload);
        for (int i = 0; i < packets; i++)
        {
            byte[] body = new byte[PacketPayload];
            Array.Fill(body, (byte)i);
            await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, body)));
            await h.Router.WaitForStateChangeAsync(ch, null, ct);
        }

        Assert.True(ch.InboundWindow <= ch.ReadAvail,
            $"window {ch.InboundWindow} should be exhausted by read_avail {ch.ReadAvail}");

        // Pre-fix WaitEofAsync blocked forever here (no EOF can arrive — the
        // peer's data credit is gone) — the bounded wait turns that into a
        // failure.
        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            ch.WaitEofAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct));
        Assert.Equal(SshErrorCode.ChannelWindowFull, ex.ErrorCode);
    }

    [Fact]
    public async Task WaitEof_NormalWindow_StillWaitsForEof()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        // With an empty window, WaitEofAsync blocks (no window-full) until the
        // peer's EOF arrives — the normal path still works.
        Task wait = ch.WaitEofAsync(ct);
        await Task.Delay(50, ct);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        await wait.WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    // ── ignore-mode refund skips the packet-size truncation ─────────

    /// <summary>
    /// The C's <c>EXTENDED_DATA_IGNORE</c> branch (packet.c:994-1030) refunds
    /// the window-truncated <c>datalen − 13</c> and deliberately does NOT apply
    /// the packet-size (<c>remote.packet_size</c>) truncation; the pre-fix port
    /// truncated to <c>InboundMaxPacket</c> first and refunded less credit than
    /// the peer granted. Post-fix the refund is the full window-truncated
    /// payload length past the 13-byte header.
    /// </summary>
    [Fact]
    public async Task ExtendedDataIgnore_RefundsFullPayloadBeyondHeader()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, ct);

        // An extended-data payload whose data section (35,000 B) exceeds the
        // advertised InboundMaxPacket (32,768) but stays under the 40,000-byte
        // wire cap and fits the 2 MiB window.
        const int DataLen = 35_000;
        byte[] payload = new byte[13 + DataLen];
        payload[0] = (byte)PacketType.ChannelExtendedData;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 0);      // recip
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), 1);      // stderr
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), (uint)DataLen);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelExtendedData, payload));

        // Pump: routes the extended data → IGNORE mode → sends the refund
        // WINDOW_ADJUST.
        await h.Router.WaitForStateChangeAsync(ch, null, ct);

        RawPacket adjust = await h.ServerReader.ReadPacketAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(PacketType.ChannelWindowAdjust, adjust.Type);
        uint refunded = BinaryPrimitives.ReadUInt32BigEndian(adjust.Payload.AsSpan(5, 4));

        // packet.c:1008-1025 — refund = datalen − 13, window-truncated only
        // (the packet-size truncation is deliberately NOT applied in the
        // IGNORE branch). Pre-fix the InboundMaxPacket truncation refunded
        // 32,768 instead.
        Assert.Equal((uint)DataLen, refunded);
    }

    /// <summary>
    /// The refund is still window-truncated: an extended-data payload past the
    /// REMAINING window credit refunds only the window remainder (packet.c:1003-1006).
    /// </summary>
    [Fact]
    public async Task ExtendedDataIgnore_WindowTruncatedRefund_RefundsWindowRemainder()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();

        // Custom 100,000-byte inbound window so the window remainder can be
        // smaller than the 40,000-byte wire cap (with the default 2 MiB window
        // a single wire-legal packet can never exceed the remaining credit).
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5,
            inboundWindow: 100_000);
        await ch.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, ct);

        // Consume 65,536 bytes of the window with unread stdout data: the
        // remainder is 34,464 — NOT the 32,768 packet-size cap, so the pre-fix
        // cap-truncation and the post-fix window-truncation produce
        // distinguishable refunds. (Feed + pump per packet — the pipe's 64 KiB
        // backpressure would block a bare feed loop.)
        for (int i = 0; i < 2; i++)
        {
            byte[] body = new byte[32 * 1024];
            Array.Fill(body, (byte)i);
            await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, body)));
            await h.Router.WaitForStateChangeAsync(ch, null, ct);
        }

        // An ignored extended-data packet (35,000 B data) larger than the
        // remaining credit (34,464) but under the 40,000-byte wire cap.
        const int DataLen = 35_000;
        byte[] payload = new byte[13 + DataLen];
        payload[0] = (byte)PacketType.ChannelExtendedData;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), (uint)DataLen);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelExtendedData, payload));

        await h.Router.WaitForStateChangeAsync(ch, null, ct);

        RawPacket adjust = await h.ServerReader.ReadPacketAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(PacketType.ChannelWindowAdjust, adjust.Type);
        uint refunded = BinaryPrimitives.ReadUInt32BigEndian(adjust.Payload.AsSpan(5, 4));

        // The refund is the window remainder (window − read_avail), the C's
        // packet.c:1003-1006 truncation. Pre-fix the InboundMaxPacket
        // truncation kicked in FIRST and refunded 32,768.
        Assert.Equal(ch.InboundWindow - ch.ReadAvail, refunded);
    }
}
