using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Regression tests: <c>ChannelRouter.WaitForReplyAsync</c>'s
/// wrong-type re-stash ran OUTSIDE the pump lock — <c>TryRemove</c> → type check
/// → indexer re-stash — so a pumper stashing the waiter's correct reply between
/// the remove and the re-stash had it overwritten and permanently lost. The fix
/// never overwrites: the re-stash uses <c>TryAdd</c>, and if a newer entry won
/// the slot the loop re-checks it.
/// </summary>
/// <remarks>
/// <para>
/// The overwrite is a two-instruction race (remove → re-stash) between two
/// genuinely concurrent tasks, so a deterministic pre-fix repro would require
/// instruction-level interleaving control the test surface does not expose.
/// The tests below pin the CONTRACT the fix guarantees — a wrong-type reply
/// already in the slot must never prevent the correct reply from being
/// consumed — which holds pre- and post-fix in the sequential case and is the
/// invariant the never-overwrite re-stash preserves under concurrency.
/// </para>
/// </remarks>
public class WaitForReplyRestashTests
{
    [Fact]
    public async Task WrongTypeReplyInSlot_ThenCorrectReplyArrives_ReturnsCorrect()
    {
        // Wrong-type reply (CHANNEL_FAILURE) routed first, then the correct one
        // (CHANNEL_SUCCESS). The waiter removes the FAILURE, re-stashes it
        // (TryAdd), pumps, and consumes the SUCCESS the pumper stashed. The
        // re-stash must not clobber the SUCCESS.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelFailure, BuildReplyPayload(PacketType.ChannelFailure, 0)),
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelSuccess, BuildReplyPayload(PacketType.ChannelSuccess, 0)));
        h.CompleteInbound();

        using RawPacket got = await h.Router.WaitForReplyAsync(
            ch,
            [PacketType.ChannelSuccess, PacketType.ChannelFailure],
            TestContext.Current.CancellationToken)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(PacketType.ChannelSuccess, got.Type);
    }

    [Fact]
    public async Task WrongTypeReplyOnly_ThenRejectTypeReply_ReturnsReject()
    {
        // Same shape with the roles reversed: the waiter wants
        // [SUCCESS, FAILURE]; the slot gets an OPEN_CONFIRMATION (91, wrong),
        // then a FAILURE. The re-stashed wrong-type entry must be overwritten
        // by the routed FAILURE and the waiter must return the FAILURE.
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0);

        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelOpenConfirmation,
                ChannelTestHarness.BuildOpenConfirmationPayload(0, 1, 100, 1000)),
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelFailure, BuildReplyPayload(PacketType.ChannelFailure, 0)));
        h.CompleteInbound();

        using RawPacket got = await h.Router.WaitForReplyAsync(
            ch,
            [PacketType.ChannelSuccess, PacketType.ChannelFailure],
            TestContext.Current.CancellationToken)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(PacketType.ChannelFailure, got.Type);
    }

    [Theory]
    [InlineData(PacketType.ChannelSuccess)]
    [InlineData(PacketType.ChannelFailure)]
    public async Task StashedMatchingReply_CompletesSynchronously_AndIsConsumedOnce(int type)
    {
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel(localId: 0);
        CancellationToken ct = TestContext.Current.CancellationToken;
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(type, BuildReplyPayload(type, 0)));
        await h.Router.PumpOneBatchForTestAsync(ct);

        ValueTask<RawPacket> wait = h.Router.WaitForReplyAsync(channel,
            [PacketType.ChannelSuccess, PacketType.ChannelFailure], ct);
        Assert.True(wait.IsCompletedSuccessfully);
        using RawPacket reply = await wait;
        Assert.Equal(type, reply.Type);
        Assert.False(h.Router.TryTakePendingReply(channel.LocalId, out _));
    }

    [Fact]
    public async Task StashedWrongType_DoesNotSatisfyFastPath_AndLaterMatchingReplySucceeds()
    {
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel(localId: 0);
        CancellationToken ct = TestContext.Current.CancellationToken;
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelFailure, BuildReplyPayload(PacketType.ChannelFailure, 0)));
        await h.Router.PumpOneBatchForTestAsync(ct);

        ValueTask<RawPacket> wait = h.Router.WaitForReplyAsync(channel, [PacketType.ChannelSuccess], ct);
        Assert.False(wait.IsCompleted);
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelSuccess, BuildReplyPayload(PacketType.ChannelSuccess, 0)));
        using RawPacket reply = await wait;
        Assert.Equal(PacketType.ChannelSuccess, reply.Type);
        Assert.False(h.Router.TryTakePendingReply(channel.LocalId, out _));
    }

    private static byte[] BuildReplyPayload(int type, uint recipient)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipient);
        return payload;
    }
}
