using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.RequestPtyAsync"/> (CHANNEL_REQUEST
/// <c>"pty-req"</c>) and <see cref="SshChannel.RequestPtyWindowSizeAsync"/>
/// (CHANNEL_REQUEST <c>"window-change"</c>). Mirror <c>channel_request_pty</c>
/// (<c>channel.c:1011-1110</c>) and <c>channel_request_pty_size</c>
/// (<c>channel.c:1289-1345</c>).
/// </summary>
public class SshChannelPtyTests
{
    // ── pty-req wire payload ───────────────────────────────────────────────

    [Fact]
    public async Task RequestPtyAsync_SendsPtyReqPayload()
    {
        // channel.c:1042-1055 — [98][u32 remote.id][string "pty-req"][0x01 want_reply]
        //                                [string term][u32 w][u32 h][u32 wpx][u32 hpx][string modes].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        byte[] modes = [0x01, 0x00];   // TTY_OP_END only (RFC 4254 §8)
        Task t = ch.RequestPtyAsync("xterm", width: 80, height: 24,
            widthPx: 640, heightPx: 384, terminalModes: modes,
            cancellationToken: TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);

        int o = 1 + 4;   // skip type + recip
        Assert.Equal("pty-req", ReadStringAt(req.Payload, o));
        o += 4 + 7;      // skip strlen + "pty-req"
        Assert.Equal(1, req.Payload[o]);   // want_reply = TRUE
        o += 1;

        Assert.Equal("xterm", ReadStringAt(req.Payload, o));
        o += 4 + 5;      // skip strlen + "xterm"

        Assert.Equal(80u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(24u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(640u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(384u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;

        // Trailing modes string.
        uint modesLen = BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4));
        Assert.Equal((uint)modes.Length, modesLen);
        byte[] actualModes = new byte[modes.Length];
        Buffer.BlockCopy(req.Payload, o + 4, actualModes, 0, actualModes.Length);
        Assert.Equal(modes, actualModes);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task RequestPtyAsync_DefaultArgs_ZeroPxAndNoModes()
    {
        // Defaults: widthPx=0, heightPx=0, terminalModes=null (empty string).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestPtyAsync("dumb", 40, 13, cancellationToken: TestContext.Current.CancellationToken);
        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        int o = 1 + 4 + 4 + 7 + 1;   // type + recip + strlen + "pty-req" + want_reply
        Assert.Equal("dumb", ReadStringAt(req.Payload, o));
        o += 4 + 4;                  // strlen + "dumb"

        Assert.Equal(40u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(13u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));   // widthPx
        o += 4;
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));   // heightPx
        o += 4;
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));   // empty modes

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task RequestPtyAsync_Success_DoesNotThrow()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestPtyAsync("xterm", 80, 24, cancellationToken: TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task RequestPtyAsync_Failure_ThrowsChannelRequestDenied()
    {
        // channel.c:1101-1102 — non-SUCCESS reply → CHANNEL_REQUEST_DENIED.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestPtyAsync("xterm", 80, 24, cancellationToken: TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await t);
        Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
    }

    [Fact]
    public async Task RequestPtyAsync_TermPlusModesTooLarge_ThrowsInval()
    {
        // channel.c:1027-1030 — term_len + modes_len > 256 → INVAL.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        string hugeTerm = new('x', 200);
        byte[] hugeModes = new byte[100];

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.RequestPtyAsync(hugeTerm, 80, 24, terminalModes: hugeModes,
                cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
    }

    [Fact]
    public async Task RequestPtyAsync_ExactlyAtLimit_Succeeds()
    {
        // Boundary: term + modes == 256 is allowed (strict-less-than).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        string term = new('x', 200);
        byte[] modes = new byte[56];

        Task t = ch.RequestPtyAsync(term, 80, 24, terminalModes: modes,
            cancellationToken: TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task RequestPtyAsync_NullTerm_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ch.RequestPtyAsync(null!, 80, 24, cancellationToken: TestContext.Current.CancellationToken));
    }

    // ── window-change wire payload ─────────────────────────────────────────

    [Fact]
    public async Task RequestPtyWindowSizeAsync_SendsWindowChange_WithWantReplyFalse()
    {
        // channel.c:1310-1320 — [98][u32 remote.id][string "window-change"][0x00 want_reply=FALSE]
        //                                [u32 w][u32 h][u32 wpx][u32 hpx].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 3);

        Task t = ch.RequestPtyWindowSizeAsync(120, 40, 800, 600, TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);

        int o = 1 + 4;   // skip type + recip
        Assert.Equal("window-change", ReadStringAt(req.Payload, o));
        o += 4 + 13;     // skip strlen + "window-change"
        Assert.Equal(0, req.Payload[o]);   // want_reply = FALSE
        o += 1;

        Assert.Equal(120u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(40u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(800u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));
        o += 4;
        Assert.Equal(600u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4)));

        // No reply expected — fire-and-forget per channel.c:1316 (want_reply=FALSE).
        await t;
    }

    [Fact]
    public async Task RequestPtyWindowSizeAsync_DoesNotWaitForReply()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        // Confirms the method returns immediately after send — no transport
        // pump, no WaitAsync call. If it did wait, the completed-inbound pipe
        // (no packets to feed) would make the await hang until cancellation.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // Complete the inbound pipe with NO packets — a wait-for-reply would
        // throw SocketDisconnect here. The fire-and-forget path just returns.
        h.CompleteInbound();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(2));
        await ch.RequestPtyWindowSizeAsync(100, 30, cancellationToken: cts.Token);

        // The outbound packet still went out.
        RawPacket req = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string ReadStringAt(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        return System.Text.Encoding.ASCII.GetString(buf, (int)(offset + 4), (int)len);
    }

    private static byte[] BuildSimpleReplyPayload(int type, uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
