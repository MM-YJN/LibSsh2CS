using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for the public EOF/CLOSE surface added in 3.3.6:
/// <see cref="SshChannel.SendEofAsync"/> (promoted from private),
/// <see cref="SshChannel.IsEof"/>, <see cref="SshChannel.WaitEofAsync"/>,
/// <see cref="SshChannel.WaitClosedAsync"/>. Mirrors <c>channel_send_eof</c>
/// (<c>channel.c:2495-2519</c>), <c>libssh2_channel_eof</c>
/// (<c>channel.c:2543-2578</c>), <c>channel_wait_eof</c>
/// (<c>channel.c:2585-2627</c>), <c>channel_wait_closed</c>
/// (<c>channel.c:2751-2788</c>).
/// </summary>
public class SshChannelEofCloseTests
{
    // ── SendEofAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task SendEofAsync_SendsEofAndSetsLocalEof()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        await ch.SendEofAsync(TestContext.Current.CancellationToken);

        RawPacket pkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelEof, pkt.Type);
        Assert.Equal((byte)PacketType.ChannelEof, pkt.Payload[0]);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4)));
        Assert.True(ch.LocalEof);
    }

    [Fact]
    public async Task SendEofAsync_Twice_SecondIsNoOp()
    {
        // Idempotent — parity channel.c:2516 (local.eof set on first success).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await ch.SendEofAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Second call should not send anything on the wire.
        await ch.SendEofAsync(TestContext.Current.CancellationToken);

        h.CompleteOutbound();
        await Assert.ThrowsAsync<SshException>(async () =>
            await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SendEofAsync_BlocksFurtherWrites()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await ch.SendEofAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.WriteAsync(new byte[] { 1 }, TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.ChannelEofSent, ex.ErrorCode);
    }

    // ── IsEof ──────────────────────────────────────────────────────────────

    [Fact]
    public void IsEof_FalseByDefault()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        Assert.False(ch.IsEof);
    }

    [Fact]
    public async Task IsEof_FalseWhenBufferedDataRemains()
    {
        // channel.c:2567-2573 — buffered data masks the EOF status.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // Buffer some stdout + signal EOF from peer.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xAA])),
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.True(ch.RemoteEof);
        Assert.False(ch.IsEof);   // data still buffered

        // Drain stdout → now IsEof returns true.
        byte[] buf = new byte[4];
        await ch.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.True(ch.IsEof);
    }

    [Fact]
    public async Task IsEof_FalseWhenStderrBuffered()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelExtendedData,
                ChannelTestHarness.BuildChannelExtendedDataPayload(0, 1, [0xBB])),
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.True(ch.RemoteEof);
        Assert.False(ch.IsEof);   // stderr still buffered

        byte[] buf = new byte[4];
        await ch.ReadStderrAsync(buf, TestContext.Current.CancellationToken);
        Assert.True(ch.IsEof);
    }

    [Fact]
    public async Task IsEof_TrueAfterRemoteEofAndBuffersDrained()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.True(ch.RemoteEof);
        Assert.True(ch.IsEof);
    }

    // ── WaitEofAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task WaitEofAsync_ReturnsImmediatelyIfAlreadyEof()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(cancellationToken);

        // Already at EOF — returns without pumping.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        await ch.WaitEofAsync(cts.Token);
        Assert.True(ch.RemoteEof);
    }

    [Fact]
    public async Task WaitEofAsync_BlocksUntilPeerEofArrives()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        Assert.False(ch.RemoteEof);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)));
        h.CompleteInbound();

        // WaitEofAsync pumps the transport until remote.eof is set.
        await ch.WaitEofAsync(TestContext.Current.CancellationToken);
        Assert.True(ch.RemoteEof);
    }

    // ── WaitClosedAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task WaitClosedAsync_ThrowsInval_WhenNotAtEof()
    {
        // channel.c:2756-2760 — !remote.eof → INVAL.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        Assert.False(ch.RemoteEof);

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.WaitClosedAsync(TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
    }

    [Fact]
    public async Task WaitClosedAsync_BlocksUntilPeerCloseArrives()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // EOF first (required precondition), then CLOSE.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)),
            BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        // WaitEofAsync pumps EOF through → sets _remoteEof (precondition).
        await ch.WaitEofAsync(TestContext.Current.CancellationToken);
        Assert.True(ch.RemoteEof);

        // WaitClosedAsync now pumps CLOSE through → sets _remoteClose.
        await ch.WaitClosedAsync(TestContext.Current.CancellationToken);
        Assert.True(ch.RemoteClose);
    }

    [Fact]
    public async Task WaitClosedAsync_ReturnsImmediately_WhenAlreadyClosed()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)),
            BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(cancellationToken);
        await h.Router.PumpOnceAsync(cancellationToken);

        // Already at EOF + CLOSE — returns without further pumping.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        await ch.WaitClosedAsync(cts.Token);
        Assert.True(ch.RemoteClose);
    }

    // ── DisposeAsync interplay (SendEofAsync refactor regression guard) ────

    [Fact]
    public async Task DisposeAsync_StillSendsEofAndCloseAfterRefactor()
    {
        // Regression: DisposeAsync must still emit EOF+CLOSE on the wire after
        // the SendEofAsync refactor moved _localEof inside the method.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 7);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        await ch.DisposeAsync();

        RawPacket eof = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelEof, eof.Type);
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32BigEndian(eof.Payload.AsSpan(1, 4)));

        RawPacket close = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelClose, close.Type);
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32BigEndian(close.Payload.AsSpan(1, 4)));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
