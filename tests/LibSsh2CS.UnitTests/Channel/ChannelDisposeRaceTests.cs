using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Regression test for channel disposal:
/// <c>SshChannel.DisposeAsync</c> guarded re-entry with a plain-bool
/// check-then-set on <c>_localClose</c>, which is only set at the END of the
/// teardown — so a second concurrent disposer saw <c>_localClose</c> still
/// false and ran the full teardown AGAIN (duplicate EOF + CHANNEL_CLOSE on the
/// wire). The C is single-threaded and cannot race; the fix is an atomic
/// dispose-started guard at the top of the teardown.
/// </summary>
public class ChannelDisposeRaceTests
{
    /// <summary>
    /// Deterministic double-dispose: the first disposer parks in the
    /// peer-CLOSE wait (after sending EOF + CLOSE) with <c>_localClose</c>
    /// still false, so a second concurrent disposer always passes the old
    /// guard and sends a duplicate EOF + CLOSE. Post-fix the atomic guard
    /// makes the second call a no-op: exactly one EOF and one CLOSE hit the
    /// wire. The duplicate is deterministic pre-fix (no thread timing
    /// involved: the second disposer's check happens while the first is
    /// parked).
    /// </summary>
    [Fact]
    public async Task Dispose_ConcurrentSecondCaller_SendsOnlyOneEofAndClose()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        // First disposer: sends EOF + CLOSE, then parks waiting for the peer's
        // CHANNEL_CLOSE (which the test sends only at the end).
        Task t1 = ch.DisposeAsync().AsTask();

        // Wait until the first EOF + CLOSE are on the wire (the first disposer
        // is now parked in the peer-close wait).
        RawPacket eof1 = await h.ServerReader.ReadPacketAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(PacketType.ChannelEof, eof1.Type);
        RawPacket close1 = await h.ServerReader.ReadPacketAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(PacketType.ChannelClose, close1.Type);

        // Second concurrent disposer: pre-fix it sees _localClose == false
        // (set only at teardown end) and re-runs the whole teardown, sending a
        // duplicate EOF + CLOSE. Post-fix it is a no-op.
        Task t2 = ch.DisposeAsync().AsTask();

        // A further server-side read must find NOTHING (post-fix). Pre-fix it
        // returns the duplicate EOF.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            h.ServerReader.ReadPacketAsync(cts.Token));

        // Let the disposer(s) finish the handshake: peer CLOSE.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelClose, BuildClosePayload(ch.LocalId)));

        await Task.WhenAll(t1, t2).WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    private static byte[] BuildClosePayload(uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelClose;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }
}
