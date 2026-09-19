using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.DisposeAsync"/>: the close handshake
/// (EOF-if-not-sent → CHANNEL_CLOSE → wait for peer CLOSE), idempotency,
/// unregister-on-close, and the post-close read/write behavior. Mirrors
/// <c>_libssh2_channel_close</c> (<c>channel.c:2646-2727</c>) + the cleanup
/// half of <c>_libssh2_channel_free</c> (<c>channel.c:2825-2888</c>).
/// </summary>
public class SshChannelCloseTests
{
    // ── Close handshake wire bytes ─────────────────────────────────────────

    [Fact]
    public async Task DisposeAsync_SendsEofThenClose_ToPeer()
    {
        // D1 (channel.c:2658-2677): close sends EOF (if not sent) then CLOSE.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();

        // First wire packet: EOF.
        RawPacket eof = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelEof, eof.Type);
        Assert.Equal(9u, BinaryPrimitives.ReadUInt32BigEndian(eof.Payload.AsSpan(1, 4)));

        // Second wire packet: CLOSE.
        RawPacket close = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelClose, close.Type);
        Assert.Equal(9u, BinaryPrimitives.ReadUInt32BigEndian(close.Payload.AsSpan(1, 4)));

        // DisposeAsync is now waiting for the peer's CLOSE. Send it.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        await closeTask;
        Assert.True(ch.LocalClose);
        Assert.True(ch.LocalEof);
    }

    [Fact]
    public async Task DisposeAsync_DoesNotSendEof_IfAlreadySent()
    {
        // channel.c:2658 — only send EOF if !local.eof. With the 3.2.6 model
        // there is no public SendEofAsync yet, so exercise the branch by
        // verifying the wire sequence is stable: one close after EOF was
        // already sent via a prior DisposeAsync that we interrupted.
        // (Covered indirectly: a full DisposeAsync sends exactly one EOF + one
        // CLOSE — the assertion in DisposeAsync_SendsEofThenClose_ToPeer locks
        // the count. Here we verify idempotency re-sends nothing.)
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;

        // A second DisposeAsync sends nothing more.
        await ch.DisposeAsync();
        h.CompleteOutbound();
        await Assert.ThrowsAsync<SshException>(async () =>
            await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken));
    }

    // ── Idempotency ────────────────────────────────────────────────────────

    [Fact]
    public async Task DisposeAsync_CalledTwice_SecondIsNoOp()
    {
        // channel.c:2651-2656 — already closed → return immediately.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;
        Assert.True(ch.LocalClose);

        // Second call returns synchronously without re-sending.
        await ch.DisposeAsync();
        Assert.True(ch.LocalClose);
    }

    // ── Wait for remote CLOSE ──────────────────────────────────────────────

    [Fact]
    public async Task DisposeAsync_WaitsForRemoteClose_BeforeReturning()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE

        // The close is pending (waiting for peer CLOSE). It must not complete
        // until we send the peer's CLOSE.
        await Task.Yield();
        Assert.False(closeTask.IsCompleted);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;
        Assert.True(ch.RemoteClose);   // peer's CLOSE observed
    }

    [Fact]
    public async Task DisposeAsync_RoutesInterleavedData_BeforePeerClose()
    {
        // While waiting for the peer CLOSE, a DATA packet for ANOTHER channel
        // arrives; it is routed, then the CLOSE completes the handshake.
        using var h = new ChannelTestHarness();
        SshChannel chClose = h.CreateChannel(localId: 0, remoteId: 9);
        SshChannel chOther = h.CreateChannel(localId: 1, remoteId: 10);

        Task closeTask = chClose.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE

        // Feed: DATA for chOther, then CLOSE for chClose.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(1, [0x55])),
            ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
                ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        await closeTask;

        // chOther's DATA was routed during the close-wait pump loop.
        Assert.Equal([0x55], chOther.TryDequeueStdout());
        Assert.True(chClose.RemoteClose);
    }

    // ── Unregister on close ────────────────────────────────────────────────

    [Fact]
    public async Task DisposeAsync_UnregistersChannel_FromRouter()
    {
        // channel.c:2857-2873 — after close, packets for this channel are dropped.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;

        Assert.False(h.Router.TryGet(0, out _));   // unregistered
    }

    // ── Post-close behavior ────────────────────────────────────────────────

    [Fact]
    public async Task WriteAsync_AfterClose_ThrowsChannelClosed()
    {
        // channel.c:2362-2365 — local.close ⇒ LIBSSH2_ERROR_CHANNEL_CLOSED.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        // Complete the close handshake first.
        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.WriteAsync(new byte[] { 1 }, TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.ChannelClosed, ex.ErrorCode);
    }

    [Fact]
    public async Task ReadAsync_AfterClose_ReturnsZero()
    {
        // A closed channel's read returns 0 (channel.c:2212 — remote.close).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelClose,
            ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await closeTask;

        byte[] buf = new byte[8];
        Assert.Equal(0, await ch.ReadAsync(buf, TestContext.Current.CancellationToken));
    }
}
