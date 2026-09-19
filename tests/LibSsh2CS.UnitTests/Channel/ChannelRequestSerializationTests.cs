using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Regression test: the per-channel reply slot in
/// <see cref="ChannelRouter"/> is a single entry, and SSH replies carry no
/// request id — only the message type — so two concurrent
/// <c>want_reply</c> requests on the SAME channel are indistinguishable at the
/// routing layer: the second reply overwrites the slot and a waiter consumes
/// the wrong reply (or hangs). The C's per-channel <c>waiting_for</c> state
/// machine never has concurrent requests because the C API is single-threaded.
/// The managed fix serializes same-channel request/reply cycles with a
/// per-channel send lock (documented limitation: concurrent <c>want_reply</c>
/// requests on one channel are serialized; full-duplex reads/writes stay
/// concurrent).
/// </summary>
public class ChannelRequestSerializationTests
{
    /// <summary>
    /// 16 concurrent <c>SetEnvAsync</c> requests on ONE channel. The server
    /// replies SUCCESS to even-indexed requests and FAILURE to odd-indexed
    /// ones, so ANY reply misdelivery (the pre-fix overwrite) surfaces as a
    /// wrong per-caller outcome — an even caller throwing
    /// <c>ChannelRequestDenied</c> or an odd caller succeeding. Pre-fix the
    /// back-to-back replies overwrote the slot before the parked waiters
    /// consumed it, misrouting replies (and stranding the last waiter on the
    /// completed pipe); post-fix the requests serialize, each reply is consumed
    /// by its own caller, and every outcome matches its request.
    /// </summary>
    [Fact]
    public async Task SetEnv_ConcurrentWantReplyRequests_EveryCallerGetsItsOwnReply()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 5);

        const int RequestCount = 16;
        var requests = new Task[RequestCount];
        for (int i = 0; i < RequestCount; i++)
        {
            requests[i] = ch.SetEnvAsync($"KEY{i}", $"value{i}", ct);
        }

        // Read each request and reply to it in order. Post-fix the requests
        // arrive strictly one at a time (each is only written after the
        // previous reply was consumed); pre-fix all 16 are already buffered and
        // the replies are fed back-to-back, racing the parked waiters.
        for (int i = 0; i < RequestCount; i++)
        {
            RawPacket req = await h.ServerReader.ReadPacketAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(PacketType.ChannelRequest, req.Type);

            int replyType = i % 2 == 0 ? PacketType.ChannelSuccess : PacketType.ChannelFailure;
            await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
                replyType, BuildReplyPayload(replyType, recipient: 0)));
        }

        h.CompleteInbound();

        // Collect every request's outcome (odd requests are SUPPOSED to fault
        // with ChannelRequestDenied, so no WhenAll — a per-request await).
        var outcomes = new Exception?[RequestCount];
        for (int i = 0; i < RequestCount; i++)
        {
            try
            {
                await requests[i].WaitAsync(TimeSpan.FromSeconds(30), ct);
            }
            catch (Exception e)
            {
                outcomes[i] = e;
            }
        }

        for (int i = 0; i < RequestCount; i++)
        {
            if (i % 2 == 0)
            {
                // Even requests: SUCCESS — must not throw.
                Assert.Null(outcomes[i]);
            }
            else
            {
                // Odd requests: FAILURE — must throw ChannelRequestDenied.
                SshException ex = Assert.IsType<SshException>(outcomes[i]);
                Assert.Equal(SshErrorCode.ChannelRequestDenied, ex.ErrorCode);
            }
        }
    }

    private static byte[] BuildReplyPayload(int type, uint recipient)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipient);
        return payload;
    }
}
