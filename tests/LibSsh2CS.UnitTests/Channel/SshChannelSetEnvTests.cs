using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Tests for <see cref="SshChannel.SetEnvAsync"/>: <c>SSH_MSG_CHANNEL_REQUEST
/// "env"</c> send (with <c>want_reply=TRUE</c>), the
/// <c>CHANNEL_SUCCESS</c>/<c>CHANNEL_FAILURE</c> wait. Mirrors
/// <c>channel_setenv</c> (<c>channel.c:883-984</c>).
/// </summary>
public class SshChannelSetEnvTests
{
    [Fact]
    public async Task SetEnvAsync_SendsEnvRequest_WithNameAndValue()
    {
        // channel.c:916-921 — [98][u32 remote.id][string "env"][0x01 want_reply]
        //                                [string varname][string value].
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        Task t = ch.SetEnvAsync("FOO", "bar baz", TestContext.Current.CancellationToken);

        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelRequest, req.Type);

        Assert.Equal((byte)PacketType.ChannelRequest, req.Payload[0]);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(1, 4)));
        Assert.Equal("env", ReadStringAt(req.Payload, 5));

        // After [string "env"]: offset 5 + 4 (strlen) + 3 ("env") = 12 → want_reply.
        Assert.Equal(1, req.Payload[12]);

        Assert.Equal("FOO", ReadStringAt(req.Payload, 13));
        int valueOffset = 13 + 4 + 3;   // strlen + "FOO"
        Assert.Equal("bar baz", ReadStringAt(req.Payload, valueOffset));

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task SetEnvAsync_Success_DoesNotThrow()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.SetEnvAsync("PATH", "/bin:/usr/bin", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
    }

    [Fact]
    public async Task SetEnvAsync_Failure_ThrowsChannelRequestDenied()
    {
        // channel.c:981-983 — CHANNEL_FAILURE → CHANNEL_REQUEST_DENIED.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.SetEnvAsync("LANG", "C", TestContext.Current.CancellationToken);
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelFailure, BuildSimpleReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await t);
        Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
    }

    [Fact]
    public async Task SetEnvAsync_NullName_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ch.SetEnvAsync(null!, "v", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SetEnvAsync_NullValue_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ch.SetEnvAsync("n", null!, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SetEnvAsync_EncodesValueAsUtf8()
    {
        // UTF-8 multibyte value round-trip — the value should appear verbatim
        // in the wire payload as UTF-8 bytes.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 1);

        Task t = ch.SetEnvAsync("GREETING", "héllo", TestContext.Current.CancellationToken);
        RawPacket req = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Parse the payload sequentially with a cursor.
        int o = 1 + 4;   // skip type + recip
        Assert.Equal("env", ReadStringAt(req.Payload, o));
        o += 4 + 3;      // skip strlen + "env"
        o += 1;          // skip want_reply
        Assert.Equal("GREETING", ReadStringAt(req.Payload, o));
        o += 4 + 8;      // skip strlen + "GREETING"

        byte[] expectedValue = System.Text.Encoding.UTF8.GetBytes("héllo");
        uint declaredLen = BinaryPrimitives.ReadUInt32BigEndian(req.Payload.AsSpan(o, 4));
        Assert.Equal((uint)expectedValue.Length, declaredLen);
        byte[] actual = new byte[expectedValue.Length];
        Buffer.BlockCopy(req.Payload, o + 4, actual, 0, actual.Length);
        Assert.Equal(expectedValue, actual);

        await h.FeedInboundAsync(BuildCleartext(PacketType.ChannelSuccess, BuildSimpleReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();
        await t;
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
