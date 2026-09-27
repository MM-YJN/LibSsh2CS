using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

public class WaiterCancellationTests
{
    [Theory]
    [InlineData("state")]
    [InlineData("reply")]
    [InlineData("global")]
    public async Task ParkedWait_CancellationPreservesToken_AndNextWaitSucceeds(string kind)
    {
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel(localId: 0);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        Task blocker = h.Router.PumpOneBatchForTestAsync(TestContext.Current.CancellationToken);
        Task wait = Start(h.Router, channel, kind, cts.Token);
        Assert.False(wait.IsCompleted);
        await cts.CancelAsync();
        OperationCanceledException error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wait);
        Assert.Equal(cts.Token, error.CancellationToken);
        Task next = Start(h.Router, channel, kind, TestContext.Current.CancellationToken);
        Assert.False(next.IsCompleted);
        await h.FeedInboundAsync(Reply(channel, kind));
        await blocker.WaitAsync(TestContext.Current.CancellationToken);
        await next.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("state", false)]
    [InlineData("reply", false)]
    [InlineData("global", false)]
    [InlineData("state", true)]
    [InlineData("reply", true)]
    [InlineData("global", true)]
    public async Task SignalAndCancellation_CompleteWithoutStrandingWaiters(string kind, bool race)
    {
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel(localId: 0);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        Task blocker = h.Router.PumpOneBatchForTestAsync(TestContext.Current.CancellationToken);
        Task wait = Start(h.Router, channel, kind, cts.Token);
        Assert.False(wait.IsCompleted);
        Task cancel = race ? Task.Run(() => cts.Cancel(), TestContext.Current.CancellationToken) : Task.CompletedTask;
        await h.FeedInboundAsync(Reply(channel, kind));
        try
        {
            await wait.WaitAsync(TestContext.Current.CancellationToken);
        }
        catch (OperationCanceledException error) when (race)
        {
            Assert.Equal(cts.Token, error.CancellationToken);
        }
        await cancel;
        await blocker.WaitAsync(TestContext.Current.CancellationToken);
        // Disposed registrations cannot cancel a subsequent operation.
        await cts.CancelAsync();
        DiscardPendingReply(h.Router, channel.LocalId);
        Task next = Start(h.Router, channel, kind, TestContext.Current.CancellationToken);
        await h.FeedInboundAsync(Reply(channel, kind));
        await next.WaitAsync(TestContext.Current.CancellationToken);
    }

    private static void DiscardPendingReply(ChannelRouter router, uint localId)
    {
        if (router.TryTakePendingReply(localId, out RawPacket packet))
        {
            packet.Dispose();
        }
    }

    private static Task Start(ChannelRouter router, SshChannel channel, string kind, CancellationToken token) => kind switch
    {
        "state" => router.WaitForStateChangeAsync(channel, canProceed: null, token),
        "reply" => router.WaitForReplyAsync(channel, [PacketType.ChannelSuccess], token),
        _ => router.SendGlobalRequestAsync("keepalive@libssh2.org", ReadOnlyMemory<byte>.Empty, true, token),
    };

    private static byte[] BuildChannelReply(uint localId)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelSuccess;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), localId);
        return payload;
    }

    private static byte[] Reply(SshChannel channel, string kind)
    {
        byte[] payload = kind == "global"
            ? [(byte)PacketType.RequestSuccess]
            : BuildChannelReply(channel.LocalId);
        return ChannelTestHarness.BuildCleartextPacket(payload[0], payload);
    }
}
