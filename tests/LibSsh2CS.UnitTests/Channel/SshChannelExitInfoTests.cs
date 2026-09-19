using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.GetExitStatusAsync"/> and
/// <see cref="SshChannel.ExitSignal"/>. The router captures exit-status /
/// exit-signal into channel state at delivery time; these
/// tests cover the public getter surface.
/// </summary>
public class SshChannelExitInfoTests
{
    [Fact]
    public async Task GetExitStatusAsync_ReturnsImmediately_WhenStatusAlreadyCaptured()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // Feed + route an exit-status request.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 42, wantReply: false)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(cancellationToken);

        // Returns without pumping (status is already captured).
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        int status = await ch.GetExitStatusAsync(cts.Token);
        Assert.Equal(42, status);
    }

    [Fact]
    public async Task GetExitStatusAsync_PumpsUntilStatusArrives()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 7, wantReply: false)));
        h.CompleteInbound();

        // GetExitStatusAsync pumps through the router; the status arrives mid-wait.
        int status = await ch.GetExitStatusAsync(TestContext.Current.CancellationToken);
        Assert.Equal(7, status);
    }

    [Fact]
    public async Task GetExitStatusAsync_ReturnsZero_OnChannelCloseWithoutStatus()
    {
        // Defensive: peer closes without sending exit-status → return 0 (parity
        // libssh2_channel_get_exit_status default).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        // EOF + CLOSE (no exit-status).
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)),
            BuildCleartext(PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(0)));
        h.CompleteInbound();

        int status = await ch.GetExitStatusAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, status);
    }

    [Fact]
    public async Task GetExitStatusAsync_ReturnsZero_WhenProcessKilledBySignal()
    {
        // exit-signal captures the signal name; exit-status stays null → return 0.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitSignalPayload(0, signal: "TERM", wantReply: false)));
        h.CompleteInbound();

        int status = await ch.GetExitStatusAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, status);
    }

    [Fact]
    public async Task ExitSignal_ReturnsNull_ByDefault()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        Assert.Null(ch.ExitSignal);
    }

    [Fact]
    public async Task ExitSignal_ReturnsCapturedSignal()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitSignalPayload(0, signal: "KILL", wantReply: false)));
        h.CompleteInbound();
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);

        Assert.Equal("KILL", ch.ExitSignal);
    }

    [Fact]
    public async Task GetExitStatusAsync_WithWantReplyTrue_ReceivesStatusAndSendsFailure()
    {
        // packet.c:1196-1205 — CHANNEL_REQUEST with want_reply=TRUE gets a
        // CHANNEL_FAILURE reply. The exit-status is captured before the reply.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelRequest,
            ChannelTestHarness.BuildExitStatusPayload(0, exitStatus: 13, wantReply: true)));
        h.CompleteInbound();

        Task<int> statusTask = Task.Run(async () => await ch.GetExitStatusAsync(TestContext.Current.CancellationToken));

        // Expect a CHANNEL_FAILURE on the wire (router auto-reply for want_reply=TRUE).
        RawPacket reply = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelFailure, reply.Type);
        Assert.Equal(9u, BinaryPrimitives.ReadUInt32BigEndian(reply.Payload.AsSpan(1, 4)));

        Assert.Equal(13, await statusTask);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static byte[] BuildCleartext(int type, byte[] payload)
        => ChannelTestHarness.BuildCleartextPacket(type, payload);
}
