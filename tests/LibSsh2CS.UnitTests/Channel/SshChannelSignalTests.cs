using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.SignalAsync(string, CancellationToken)"/> and
/// <see cref="SshChannel.SignalAsync(SshSignal, CancellationToken)"/>:
/// <c>SSH_MSG_CHANNEL_REQUEST "signal"</c> send with <c>want_reply=FALSE</c>
/// (fire-and-forget per RFC 4254 §6.9). Mirrors <c>channel_signal</c>
/// (<c>channel.c:3007-3060</c>).
/// </summary>
public class SshChannelSignalTests
{
    // ── wire payload ───────────────────────────────────────────────────────

    [Fact]
    public async Task SignalAsync_StringOverload_SendsSignalPayload_WantReplyFalse()
    {
        // channel.c:3029-3033 — [98][u32 remote.id][string "signal"][0x00 want_reply=FALSE]
        //                                [string signame].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 7);

        Task t = ch.SignalAsync("TERM", TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);

        Assert.Equal((byte)PacketType.ChannelRequest, req.Payload[0]);
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(1, 4)));
        Assert.Equal("signal", ReadStringAt(req.Payload, 5));

        // After [string "signal"]: offset 5 + 4 (strlen) + 6 ("signal") = 15 → want_reply.
        Assert.Equal(0, req.Payload[15]);   // want_reply = FALSE

        Assert.Equal("TERM", ReadStringAt(req.Payload, 16));

        // Fire-and-forget: must complete without any inbound packet.
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task SignalAsync_EnumOverload_MapsToUppercaseWireName()
    {
        // The enum overload must delegate to ToWireName + the string overload.
        // Covers the integration end-to-end (the unit-level mapping is in
        // SshSignalTests).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 2);

        Task t = ch.SignalAsync(SshSignal.Kill, TestContext.Current.CancellationToken);
        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Skip type(1) + recip(4) + strlen(4) + "signal"(6) + want_reply(1) = 16.
        Assert.Equal("KILL", ReadStringAt(req.Payload, 16));

        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task SignalAsync_DoesNotWaitForReply()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        // Confirms the method returns immediately after send — no transport
        // pump, no WaitAsync call. If it did wait, the completed-inbound pipe
        // (no packets to feed) would make the await hang until cancellation.
        // Parity with RequestPtyWindowSizeAsync_DoesNotWaitForReply.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // Complete the inbound pipe with NO packets — a wait-for-reply would
        // throw SocketDisconnect here. The fire-and-forget path just returns.
        h.CompleteInbound();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(2));
        await ch.SignalAsync("HUP", cts.Token);

        // The outbound packet still went out.
        RawPacket req = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);
    }

    [Fact]
    public async Task SignalAsync_NullSigName_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ch.SignalAsync((string)null!, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SignalAsync_EmptySigName_StillSends()
    {
        // Parity: libssh2's channel_signal has no length check — an empty
        // signal name is a valid (if useless) wire payload. Documents that we
        // do NOT add validation the C lacks.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.SignalAsync(string.Empty, TestContext.Current.CancellationToken);
        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Empty string still encodes a 4-byte length prefix of 0.
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(16, 4)));
        Assert.Equal(20, req.Payload.Length);   // type(1)+recip(4)+strlen(4)+"signal"(6)+reply(1)+strlen(4)

        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task SignalAsync_AfterClose_ThrowsChannelClosed()
    {
        // Parity with WriteAsync's post-close guard (SshChannelCloseTests). The
        // _localClose guard lives in SendChannelRequestAsync (added 3.6.2) so
        // all CHANNEL_REQUEST senders (exec/setenv/pty/signal/auth-agent/etc.)
        // reject cleanly instead of writing into a closed channel.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        // Drive the close handshake to completion: client sends EOF+CLOSE,
        // server replies with CLOSE.
        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.SignalAsync("TERM", TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.ChannelClosed, ex.ErrorCode);
    }

    [Fact]
    public async Task SignalAsync_RoutesInterleavedDataForOtherChannels()
    {
        // Channel invariant: any operation must route channel-async packets
        // for OTHER channels while waiting. Signal is fire-and-forget so this
        // test instead drives the router pump explicitly and confirms a DATA
        // packet for a sibling channel is delivered.
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        // Send signal on A — completes immediately (fire-and-forget).
        await chA.SignalAsync("TERM", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Feed a DATA packet for B (recipient = client's local id for B = 1)
        // and pump the router — B's read should see it.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(recipientChannel: 1, data: "hello"u8.ToArray())));
        h.CompleteInbound();

        byte[] buf = new byte[16];
        int n = await chB.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(5, n);
        Assert.Equal("hello", System.Text.Encoding.ASCII.GetString(buf, 0, 5));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string ReadStringAt(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        return System.Text.Encoding.ASCII.GetString(buf, (int)(offset + 4), (int)len);
    }
}
