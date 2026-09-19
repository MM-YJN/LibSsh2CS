using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.RequestAuthAgentAsync"/>: sends
/// <c>SSH_MSG_CHANNEL_REQUEST "auth-agent-req@openssh.com"</c> with
/// <c>want_reply=TRUE</c>, awaits <c>CHANNEL_SUCCESS</c>/<c>CHANNEL_FAILURE</c>,
/// and on denial falls back to the RFC-draft name <c>"auth-agent-req"</c>.
/// Mirrors <c>libssh2_channel_request_auth_agent</c>
/// (<c>channel.c:1222-1265</c>).
/// </summary>
public class SshChannelAuthAgentTests
{
    // ── first-attempt (OpenSSH variant) ────────────────────────────────────

    [Fact]
    public async Task RequestAuthAgentAsync_FirstAttemptUsesOpenSshVariant()
    {
        // channel.c:1235-1239 + 1146-1155 — [98][u32 remote.id][string "auth-agent-req@openssh.com"][0x01 want_reply].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        Task t = ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);

        Assert.Equal((byte)PacketType.ChannelRequest, req.Payload[0]);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(1, 4)));
        Assert.Equal("auth-agent-req@openssh.com", ReadStringAt(req.Payload, 5));

        // want_reply byte right after the request-type string.
        int wantReplyOffset = 5 + 4 + "auth-agent-req@openssh.com".Length;
        Assert.Equal(1, req.Payload[wantReplyOffset]);   // want_reply = TRUE

        // No extra fields beyond the request-type string + want_reply byte.
        Assert.Equal(wantReplyOffset + 1, req.Payload.Length);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task RequestAuthAgentAsync_FirstAttemptSuccess_NoSecondPacket()
    {
        // If a fallback attempt had fired, the await would hang waiting for a
        // second reply. Feeding only SUCCESS for the first attempt + completing
        // the inbound pipe is sufficient to verify the fallback never ran: a
        // hung await would time out (or the second SendChannelRequestAsync
        // would throw SocketDisconnect on the completed-empty pipe).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;   // completes cleanly without needing a second reply
    }

    // ── fallback to RFC-draft variant ──────────────────────────────────────

    [Fact]
    public async Task RequestAuthAgentAsync_FirstAttemptFailure_FallsBackToRfcVariant()
    {
        // channel.c:1248-1251 — FAILURE on OpenSSH variant → retry with "auth-agent-req".
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken);

        // Consume the first attempt, reply FAILURE.
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));

        // Consume the second attempt and assert wire shape.
        RawPacket req2 = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req2.Type);
        Assert.Equal("auth-agent-req", ReadStringAt(req2.Payload, 5));

        int wantReplyOffset = 5 + 4 + "auth-agent-req".Length;
        Assert.Equal(1, req2.Payload[wantReplyOffset]);
        Assert.Equal(wantReplyOffset + 1, req2.Payload.Length);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task RequestAuthAgentAsync_SecondAttemptSuccess_Completes()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();

        await t;   // must complete without throwing.
    }

    [Fact]
    public async Task RequestAuthAgentAsync_BothFail_ThrowsChannelRequestDenied()
    {
        // channel.c:1209-1210 — second attempt FAILURE → CHANNEL_REQUEST_DENIED.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await t);
        Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
    }

    // ── parity-critical: error filtering on the catch ─────────────────────

    [Fact]
    public async Task RequestAuthAgentAsync_TransportErrorOnFirst_Propagates_NoSecondAttempt()
    {
        // The `when (ex.ErrorCode == ChannelRequestDenied)` filter is the
        // critical parity surface — transport errors / disconnects MUST
        // propagate without triggering the fallback. Feeding a DISCONNECT
        // mid-wait produces a non-ChannelRequestDenied exception from the
        // router; the fallback must not fire.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // A DISCONNECT in the inbound stream produces SocketDisconnect from
        // PacketQueue (parity with how live servers tear down the transport).
        await h.FeedInboundAsync(BuildCleartextDisconnect());
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await t);
        Assert.NotEqual(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);

        // No-second-packet proof: the await above completed by propagating the
        // first-attempt exception, NOT by waiting for a second reply. If the
        // fallback had fired, the await would either hang (no second reply
        // fed) or surface a second-attempt exception — neither happens.
    }

    // ── close guard + interleaved routing ──────────────────────────────────

    [Fact]
    public async Task RequestAuthAgentAsync_AfterClose_ThrowsChannelClosed()
    {
        // The _localClose guard lives in SendChannelRequestAsync (3.6.2 hardening).
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 9);

        Task closeTask = ch.DisposeAsync().AsTask();
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // EOF
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);   // CLOSE
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelClose, BuildSimpleReplyPayload(PacketType.ChannelClose, 0)));
        h.CompleteInbound();
        await closeTask;

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await ch.RequestAuthAgentAsync(TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.ChannelClosed, ex.ErrorCode);
    }

    [Fact]
    public async Task RequestAuthAgentAsync_InterleavedDataForOtherChannels_Routed()
    {
        // While waiting for the SUCCESS reply on the auth-agent channel, the
        // router must route channel-async packets for OTHER channels.
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        Task t = chA.RequestAuthAgentAsync(TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Feed a DATA packet for B (recipient = B's local id = 1) and the
        // SUCCESS for A together. The router must route B's data even though
        // A is the one awaiting a reply.
        await h.FeedInboundAsync(
            BuildCleartext(PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload(recipientChannel: 1, data: "hi"u8.ToArray())),
            BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;

        // B's read should return the routed data.
        byte[] buf = new byte[16];
        int n = await chB.ReadAsync(buf, TestContext.Current.CancellationToken);
        Assert.Equal(2, n);
        Assert.Equal("hi", System.Text.Encoding.ASCII.GetString(buf, 0, 2));
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

    /// <summary>
    /// Builds a minimal <c>SSH_MSG_DISCONNECT</c> (type 1) cleartext packet.
    /// Payload: [1][u32 reason=2 (PROTOCOL_ERROR)][string "bye"][string ""].
    /// </summary>
    private static byte[] BuildCleartextDisconnect()
    {
        byte[] msg = System.Text.Encoding.ASCII.GetBytes("bye");
        byte[] payload = new byte[1 + 4 + 4 + msg.Length + 4];
        payload[0] = 1;   // SSH_MSG_DISCONNECT
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 2);   // reason
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), (uint)msg.Length);
        Buffer.BlockCopy(msg, 0, payload, 9, msg.Length);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9 + msg.Length, 4), 0u);   // empty lang
        return ChannelTestHarness.BuildCleartextPacket(1, payload);
    }
}
