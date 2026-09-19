using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for the shared <c>ProcessStartupAsync</c> core
/// (<c>_libssh2_channel_process_startup</c>, <c>channel.c:1526-1626</c>) via its
/// three public wrappers: <see cref="SshChannel.ExecAsync"/>,
/// <see cref="SshChannel.ShellAsync"/>, <see cref="SshChannel.SubsystemAsync"/>.
/// The exec-specific success/failure/non-reusable coverage lives in
/// <see cref="SshChannelExecTests"/>; this file focuses on the shell/subsystem
/// wire format and the cross-method non-reusable contract.
/// </summary>
public class SshChannelProcessStartupTests
{
    // ── Shell wire payload ─────────────────────────────────────────────────

    [Fact]
    public async Task ShellAsync_SendsShellRequest_WithWantReplyTrue_NoMessage()
    {
        // channel.c:1563-1569 with request="shell" and message=NULL:
        // [98][u32 remote.id][string "shell"][0x01 want_reply].
        // No trailing [u32 len][message] block — that is gated on message!=NULL.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 42);

        Task shellTask = ch.ShellAsync(TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);
        Assert.Equal((byte)PacketType.ChannelRequest, req.Payload[0]);
        Assert.Equal(42u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(1, 4)));
        Assert.Equal("shell", ReadStringAt(req.Payload, 5));

        // offset 5 + 4 (strlen) + 5 ("shell") = 14 → want_reply byte.
        Assert.Equal(1, req.Payload[14]);

        // Total payload length: 1 (type) + 4 (recip) + 4+5 ("shell") + 1 = 15.
        // No [u32 msglen][msg] trailer.
        Assert.Equal(15, req.Payload.Length);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await shellTask;
    }

    [Fact]
    public async Task ShellAsync_OnSuccess_DoesNotThrow()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.ShellAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task ShellAsync_OnFailure_ThrowsChannelRequestDenied()
    {
        // channel.c:1623-1625 — CHANNEL_FAILURE → CHANNEL_REQUEST_DENIED.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.ShellAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await t);
        Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
    }

    // ── Subsystem wire payload ─────────────────────────────────────────────

    [Fact]
    public async Task SubsystemAsync_SendsSubsystemRequest_WithName()
    {
        // [98][u32 remote.id][string "subsystem"][0x01 want_reply][string name].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 7);

        Task t = ch.SubsystemAsync("sftp", TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(1, 4)));
        Assert.Equal("subsystem", ReadStringAt(req.Payload, 5));

        // After [string "subsystem"]: offset 5 + 4 (strlen) + 9 ("subsystem") = 18 → want_reply.
        Assert.Equal(1, req.Payload[18]);
        Assert.Equal("sftp", ReadStringAt(req.Payload, 19));

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task SubsystemAsync_OnFailure_ThrowsChannelRequestDenied()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.SubsystemAsync("sftp", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await t);
        Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
    }

    [Fact]
    public async Task SubsystemAsync_NullName_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ch.SubsystemAsync(null!, TestContext.Current.CancellationToken));
    }

    // ── Cross-method non-reusable contract (process_state == end) ──────────

    [Fact]
    public async Task ShellAsync_AfterExec_Throws()
    {
        // process_state=end is set on a successful exec; shell must reject.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task execTask = ch.ExecAsync("first", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await execTask;

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await ch.ShellAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExecAsync_AfterFailedShell_Throws()
    {
        // process_state=end is set on the failure path too (channel.c:1610/1617
        // runs before the FAILURE branch).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task shellTask = ch.ShellAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();
        await Assert.ThrowsAsync<SshException>(async () => await shellTask);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await ch.ExecAsync("after", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SubsystemAsync_AfterShell_Throws()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task shellTask = ch.ShellAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await shellTask;

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await ch.SubsystemAsync("sftp", TestContext.Current.CancellationToken));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string ReadStringAt(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        return System.Text.Encoding.ASCII.GetString(buf, (int)(offset + 4), (int)len);
    }

    /// <summary>Builds a SUCCESS(99)/FAILURE(100) payload: [type][u32 recip].</summary>
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
