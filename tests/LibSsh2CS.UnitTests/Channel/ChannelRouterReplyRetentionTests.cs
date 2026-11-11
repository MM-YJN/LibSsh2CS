using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Regression tests for reply-slot retention: replies are accepted only for
/// registered channels, truncated replies are dropped, the slot dictionary is
/// capped, and unregister/dispose clear retained slots.
/// </summary>
public class ChannelRouterReplyRetentionTests
{
    private const int MaxPendingReplies = 1024;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ReplyToUnregisteredRecipient_IsDropped()
    {
        using var h = new ChannelTestHarness();
        await h.FeedInboundAsync(ReplyPacket(PacketType.ChannelSuccess, 99));
        h.CompleteInbound();

        await h.Router.PumpOneBatchForTestAsync(Token);

        Assert.False(h.Router.TryTakePendingReply(99, out _));
    }

    [Fact]
    public async Task TruncatedReply_IsDropped_AndDoesNotOccupyChannelZero()
    {
        using var h = new ChannelTestHarness();
        _ = h.CreateChannel(localId: 0);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelSuccess, [PacketType.ChannelSuccess]));
        h.CompleteInbound();

        await h.Router.PumpOneBatchForTestAsync(Token);

        Assert.False(h.Router.TryTakePendingReply(0, out _));
    }

    [Fact]
    public async Task ReplyToRegisteredChannel_IsStillRouted()
    {
        using var h = new ChannelTestHarness();
        _ = h.CreateChannel(localId: 5);
        await h.FeedInboundAsync(ReplyPacket(PacketType.ChannelSuccess, 5));
        h.CompleteInbound();

        await h.Router.PumpOneBatchForTestAsync(Token);

        Assert.True(h.Router.TryTakePendingReply(5, out RawPacket reply));
        Assert.Equal(PacketType.ChannelSuccess, reply.Type);
        reply.Dispose();
    }

    [Fact]
    public async Task PendingReplyCap_DropsReplyBeyondLimit()
    {
        using var h = new ChannelTestHarness();
        for (int i = 0; i <= MaxPendingReplies; i++)
        {
            _ = h.CreateChannel(localId: (uint)i);
        }

        byte[][] replies = new byte[MaxPendingReplies + 1][];
        for (int i = 0; i < replies.Length; i++)
        {
            replies[i] = ReplyPacket(PacketType.ChannelSuccess, (uint)i);
        }

        await h.FeedInboundAsync(replies);
        h.CompleteInbound();
        await h.Router.PumpOneBatchForTestAsync(Token);

        int retained = 0;
        for (int i = 0; i < MaxPendingReplies; i++)
        {
            if (h.Router.TryTakePendingReply((uint)i, out RawPacket reply))
            {
                reply.Dispose();
                retained++;
            }
        }

        Assert.Equal(MaxPendingReplies, retained);
        Assert.False(h.Router.TryTakePendingReply((uint)MaxPendingReplies, out _));
    }

    [Fact]
    public async Task Unregister_LeavesNoPendingReplySlot()
    {
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel(localId: 0);
        await h.FeedInboundAsync(ReplyPacket(PacketType.ChannelSuccess, 0));
        h.CompleteInbound();
        await h.Router.PumpOneBatchForTestAsync(Token);

        h.Router.Unregister(channel);

        Assert.False(h.Router.TryTakePendingReply(0, out _));
    }

    [Fact]
    public async Task RouterDispose_ClearsPendingReplies()
    {
        using var h = new ChannelTestHarness();
        _ = h.CreateChannel(localId: 0);
        await h.FeedInboundAsync(ReplyPacket(PacketType.ChannelSuccess, 0));
        h.CompleteInbound();
        await h.Router.PumpOneBatchForTestAsync(Token);

        h.Router.Dispose();

        Assert.False(h.Router.TryTakePendingReply(0, out _));
    }

    private static byte[] ReplyPacket(int type, uint recipient)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipient);
        return ChannelTestHarness.BuildCleartextPacket(type, payload);
    }
}
