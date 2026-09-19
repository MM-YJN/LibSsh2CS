using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.ExecAsync"/>: <c>SSH_MSG_CHANNEL_REQUEST
/// "exec"</c> send (with <c>want_reply=TRUE</c>), the
/// <c>CHANNEL_SUCCESS</c>/<c>CHANNEL_FAILURE</c> wait, and the non-reusable
/// channel contract. Mirrors <c>_libssh2_channel_process_startup</c>
/// (<c>channel.c:1526-1626</c>).
/// </summary>
public class SshChannelExecTests
{
    // ── Exec success ───────────────────────────────────────────────────────

    [Fact]
    public async Task ExecAsync_SendsExecRequest_WithWantReplyTrue()
    {
        // channel.c:1563-1569 — [98][u32 remote.id][string "exec"][0x01][string cmd].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 77);

        Task execTask = ch.ExecAsync("ls -la", TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);

        // Parse: [98][u32 remoteId=77][string "exec"][bool want_reply][string cmd].
        Assert.Equal((byte)PacketType.ChannelRequest, req.Payload[0]);
        Assert.Equal(77u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(1, 4)));
        Assert.Equal("exec", ReadStringAt(req.Payload, 5));
        // After [string "exec"]: offset 5 + 4 (strlen) + 4 ("exec") = 13 → want_reply.
        Assert.Equal(1, req.Payload[13]);   // want_reply = TRUE
        Assert.Equal("ls -la", ReadStringAt(req.Payload, 14));

        // Reply SUCCESS.
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();

        await execTask;   // completes without throwing
    }

    [Fact]
    public async Task ExecAsync_Success_DoesNotThrow()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task execTask = ch.ExecAsync("echo hi", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // consume exec request

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();

        await execTask;   // no exception
    }

    // ── Exec failure ───────────────────────────────────────────────────────

    [Fact]
    public async Task ExecAsync_Failure_ThrowsChannelRequestDenied()
    {
        // channel.c:1623-1625 — CHANNEL_FAILURE → CHANNEL_REQUEST_DENIED.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task execTask = ch.ExecAsync("rm -rf /", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await execTask);
        Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
    }

    // ── Non-reusable channel ───────────────────────────────────────────────

    [Fact]
    public async Task ExecAsync_Twice_OnSameChannel_Throws()
    {
        // channel.c:1536-1538 — process_state == end → BAD_USE. process_state
        // is set to end on BOTH success and failure (channel.c:1610, 1617).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task execTask = ch.ExecAsync("first", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await execTask;

        // A second exec on the same channel throws (even though the inbound
        // pipe is completed, the check happens BEFORE sending).
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await ch.ExecAsync("second", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExecAsync_AfterFailedExec_StillMarksChannelNonReusable()
    {
        // process_state=end is set on the failure path too (channel.c:1617
        // runs before the FAILURE branch), so a retry after denial throws.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task execTask = ch.ExecAsync("denied", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();
        await Assert.ThrowsAsync<SshException>(async () => await execTask);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await ch.ExecAsync("retry", TestContext.Current.CancellationToken));
    }

    // ── Exec routes interleaved channel packets ────────────────────────────

    [Fact]
    public async Task ExecAsync_RoutesInterleavedDataForOtherChannels()
    {
        // While awaiting exec SUCCESS, a DATA packet for ANOTHER channel
        // arrives; the router must route it (not stash or mis-deliver).
        using var h = new ChannelTestHarness();
        SshChannel chExec = h.CreateChannel(localId: 0, remoteId: 1);
        SshChannel chOther = h.CreateChannel(localId: 1, remoteId: 2);

        Task execTask = chExec.ExecAsync("cmd", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // exec request

        // Feed: DATA for chOther(1), then SUCCESS for chExec(0).
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(1, [0xAB, 0xCD])),
            BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();

        await execTask;   // routes the DATA for chOther, then returns SUCCESS

        // chOther got its DATA (not chExec).
        Assert.Null(chExec.TryDequeueStdout());
        Assert.Equal([0xAB, 0xCD], chOther.TryDequeueStdout());
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
