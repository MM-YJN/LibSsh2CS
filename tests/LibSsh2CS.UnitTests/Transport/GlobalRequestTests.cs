using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Phase 5.3 <c>SSH_MSG_GLOBAL_REQUEST</c> send/reply plumbing tests.
/// Verifies the global-request machinery on <see cref="ChannelRouter"/>:
/// <list type="bullet">
/// <item>Outbound payload byte-exactness for keepalive@libssh2.org,
/// tcpip-forward, cancel-tcpip-forward.</item>
/// <item>wantReply=true round-trip: REQUEST_SUCCESS returns the reply;
/// REQUEST_FAILURE throws <see cref="SshErrorCode.RequestDenied"/>.</item>
/// <item>wantReply=false is fire-and-forget (no await).</item>
/// <item>Inbound SSH_MSG_GLOBAL_REQUEST (80) from the server is auto-failed
/// with REQUEST_FAILURE (libssh2 parity).</item>
/// <item>Single-slot serialization: concurrent wantReply=true callers do not
/// crosstalk.</item>
/// </list>
/// </summary>
public class GlobalRequestTests
{
    // ── GlobalRequest.BuildPayload wire-format tests ──────────────────────

    [Fact]
    public void BuildPayload_NameOnly_NoExtra_MatchesKeepaliveShape()
    {
        byte[] payload = GlobalRequest.BuildPayload("keepalive@libssh2.org", default, wantReply: false);

        // [80][u32 21][21-byte name][0x00 wantReply]
        Assert.Equal(1 + 4 + 21 + 1, payload.Length);
        Assert.Equal((byte)PacketType.GlobalRequest, payload[0]);
        Assert.Equal(21u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
        Assert.Equal("keepalive@libssh2.org", Encoding.ASCII.GetString(payload, 5, 21));
        Assert.Equal(0, payload[26]);
    }

    [Fact]
    public void BuildPayload_WantReplyTrue_SetsWantReplyByte()
    {
        byte[] payload = GlobalRequest.BuildPayload("keepalive@libssh2.org", default, wantReply: true);
        Assert.Equal(1, payload[26]);
    }

    [Fact]
    public void BuildPayload_TcpipForwardExtra_HostAndPortAppendedAfterHeader()
    {
        // tcpip-forward extra: [string host][u32 port]
        byte[] host = Encoding.ASCII.GetBytes("0.0.0.0");
        byte[] extra = new byte[4 + host.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(extra.AsSpan(0, 4), (uint)host.Length);
        Buffer.BlockCopy(host, 0, extra, 4, host.Length);
        BinaryPrimitives.WriteUInt32BigEndian(extra.AsSpan(4 + host.Length, 4), 22u);

        byte[] payload = GlobalRequest.BuildPayload("tcpip-forward", extra, wantReply: true);

        // [80][u32 13][13-byte name][0x01 wantReply][4+host+4 extra]
        Assert.Equal(1 + 4 + 13 + 1 + extra.Length, payload.Length);
        Assert.Equal("tcpip-forward", Encoding.ASCII.GetString(payload, 5, 13));
        Assert.Equal(1, payload[1 + 4 + 13]);   // wantReply

        // Extra starts at offset 1 + 4 + 13 + 1 = 19.
        byte[] actualExtra = payload.AsSpan(19, extra.Length).ToArray();
        Assert.Equal(extra, actualExtra);
    }

    // ── End-to-end SendGlobalRequestAsync over cleartext pipes ────────────

    /// <summary>
    /// Builds a ChannelRouter over a paired pipe harness (mirrors
    /// ChannelTestHarness but lives in the Transport test namespace).
    /// </summary>
    private sealed class GlobalRequestHarness : IDisposable
    {
        private readonly Pipe _c2s = new();
        private readonly Pipe _s2c = new();

        public GlobalRequestHarness()
        {
            ClientWriter = new PacketWriter(_c2s.Writer);
            Queue = new PacketQueue(new PacketReader(_s2c.Reader));
            Router = new ChannelRouter(Queue, ClientWriter);
            ServerReader = new PacketReader(_c2s.Reader);
        }

        public PacketWriter ClientWriter { get; }
        public PacketQueue Queue { get; }
        public ChannelRouter Router { get; }
        public PacketReader ServerReader { get; }
        public PipeWriter ServerWriter => _s2c.Writer;

        public void CompleteInbound() => _s2c.Writer.Complete();

        public void Dispose()
        {
            try
            {
                _c2s.Writer.Complete();
            }
            catch (InvalidOperationException) { }
            try
            {
                _s2c.Writer.Complete();
            }
            catch (InvalidOperationException) { }
            Router.Dispose();
        }

        public static byte[] FrameCleartextPacket(int type, byte[] payload)
        {
            if (payload.Length == 0 || payload[0] != type)
            {
                byte[] withType = new byte[payload.Length + 1];
                withType[0] = (byte)type;
                Buffer.BlockCopy(payload, 0, withType, 1, payload.Length);
                payload = withType;
            }

            int withHeader = payload.Length + 1 + 4;
            int padding = 8 - (withHeader % 8);
            if (padding < 4)
            {
                padding += 8;
            }

            int packetLength = payload.Length + 1 + padding;
            byte[] wire = new byte[4 + packetLength];
            BinaryPrimitives.WriteUInt32BigEndian(wire, (uint)packetLength);
            wire[4] = (byte)padding;
            Buffer.BlockCopy(payload, 0, wire, 5, payload.Length);
            return wire;
        }
    }

    [Fact]
    public async Task SendGlobalRequest_WantReplyFalse_FireAndForgetsAndReturnsDefault()
    {
        using var h = new GlobalRequestHarness();

        // No background pumper — the call must complete without one.
        RawPacket reply = await h.Router.SendGlobalRequestAsync(
            "keepalive@libssh2.org", default, wantReply: false,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(default, reply);

        // The wire bytes should show want_reply=0.
        RawPacket wirePkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.GlobalRequest, wirePkt.Type);
        Assert.Equal(0, wirePkt.Payload[26]);
    }

    [Fact]
    public async Task SendGlobalRequest_WantReplyTrue_Success_ReturnsReplyPacket()
    {
        using var h = new GlobalRequestHarness();

        // Drive the SendGlobalRequestAsync call in a background task so the
        // test thread can feed the inbound reply.
        Task<RawPacket> sendTask = Task.Run(async () => await h.Router.SendGlobalRequestAsync(
            "keepalive@libssh2.org", default, wantReply: true,
            cancellationToken: TestContext.Current.CancellationToken));

        // Wait for the client to send the GLOBAL_REQUEST.
        RawPacket sent = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.GlobalRequest, sent.Type);
        Assert.Equal(1, sent.Payload[26]);   // wantReply=1

        // Feed the reply: REQUEST_SUCCESS (81) with empty body.
        byte[] replyPayload = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            TestContext.Current.CancellationToken);
        h.CompleteInbound();

        RawPacket reply = await sendTask;
        Assert.Equal(PacketType.RequestSuccess, reply.Type);
    }

    [Fact]
    public async Task SendGlobalRequest_WantReplyTrue_Failure_ThrowsRequestDenied()
    {
        using var h = new GlobalRequestHarness();

        Task sendTask = Task.Run(async () => await h.Router.SendGlobalRequestAsync(
            "tcpip-forward", default, wantReply: true,
            cancellationToken: TestContext.Current.CancellationToken));

        // Let the GLOBAL_REQUEST hit the wire.
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Feed a REQUEST_FAILURE (82).
        byte[] replyPayload = new byte[] { (byte)PacketType.RequestFailure };
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestFailure, replyPayload),
            TestContext.Current.CancellationToken);
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(() => sendTask);
        Assert.Equal(SshErrorCode.RequestDenied, ex.ErrorCode);
    }

    [Fact]
    public async Task SendGlobalRequest_WantReplyTrue_SuccessWithBody_ReturnsBodyForParsing()
    {
        // tcpip-forward with port=0 returns the server-assigned port in the
        // REQUEST_SUCCESS body (a u32). The caller parses it.
        using var h = new GlobalRequestHarness();

        Task<RawPacket> sendTask = Task.Run(async () => await h.Router.SendGlobalRequestAsync(
            "tcpip-forward", default, wantReply: true,
            cancellationToken: TestContext.Current.CancellationToken));

        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Reply: REQUEST_SUCCESS with a u32 body = port 22222.
        byte[] replyPayload = new byte[5];
        replyPayload[0] = (byte)PacketType.RequestSuccess;
        BinaryPrimitives.WriteUInt32BigEndian(replyPayload.AsSpan(1, 4), 22222u);
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            TestContext.Current.CancellationToken);
        h.CompleteInbound();

        RawPacket reply = await sendTask;
        Assert.Equal(PacketType.RequestSuccess, reply.Type);
        Assert.Equal(5, reply.Payload.Length);
        Assert.Equal(22222u, BinaryPrimitives.ReadUInt32BigEndian(reply.Payload.AsSpan(1, 4)));
    }

    [Fact]
    public async Task SendGlobalRequest_Cancellation_CancelsAwait()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using var h = new GlobalRequestHarness();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Task sendTask = Task.Run(async () => await h.Router.SendGlobalRequestAsync(
            "keepalive@libssh2.org", default, wantReply: true,
            cancellationToken: cts.Token));

        // Let the GLOBAL_REQUEST hit the wire, then cancel before replying.
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sendTask);
    }

    // ── Inbound SSH_MSG_GLOBAL_REQUEST (80) from server ──────────────────

    [Fact]
    public async Task InboundGlobalRequest_AutoFailsWithRequestFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        // libssh2 parity: the C library does not implement any inbound
        // global-request handler. The C# router mirrors this by auto-sending
        // REQUEST_FAILURE for an inbound 80 packet carrying want_reply=1
        // (packet.c:917-943 — a want_reply=0 request gets NO reply).
        //
        // Test flow:
        //   1. Pre-feed an inbound GLOBAL_REQUEST (want_reply=1) from the server.
        //   2. The next outbound pump cycle (triggered by our own
        //      SendGlobalRequestAsync wantReply=true) routes the inbound 80
        //      via RouteRoutableAsync, which sends REQUEST_FAILURE on the
        //      client's outbound pipe.
        //   3. We then feed our keepalive reply and assert the wire shows
        //      BOTH the auto-fail REQUEST_FAILURE AND the keepalive
        //      GLOBAL_REQUEST.
        using var h = new GlobalRequestHarness();

        // 1. Feed an inbound GLOBAL_REQUEST (server→client).
        byte[] inbound = BuildGlobalRequestPayload("no-more-sessions@openssh.com", wantReply: true);
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.GlobalRequest, inbound),
            cancellationToken);

        // 2. Trigger a pump cycle via our own SendGlobalRequestAsync call.
        Task<RawPacket> sendTask = Task.Run(async () => await h.Router.SendGlobalRequestAsync(
            "keepalive@libssh2.org", default, wantReply: true,
            cancellationToken: cancellationToken));

        // 3. The pump routes the inbound 80 → auto-sends REQUEST_FAILURE (82).
        //    Our keepalive GLOBAL_REQUEST is also written — before the pump
        //    runs, so it is always first on the wire. Awaiting the send
        //    guarantees BOTH packets are flushed before we drain: under
        //    full-suite parallel load the Task.Run'd send might not have been
        //    scheduled yet, and a drain started first would time out on an
        //    empty pipe (flaky empty-collection failure).
        byte[] replyPayload = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            cancellationToken);
        h.CompleteInbound();
        await sendTask;

        // Drain whatever the client sent. (At least the keepalive GLOBAL_REQUEST
        // and the auto-fail REQUEST_FAILURE.) Bound with a short timeout per
        // read — the two expected packets are the only legitimate output.
        var outboundTypes = new List<int>();
        for (int i = 0; i < 4; i++)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromMilliseconds(300));
            try
            {
                RawPacket p = await h.ServerReader.ReadPacketAsync(cts.Token);
                outboundTypes.Add(p.Type);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        // The keepalive GLOBAL_REQUEST must have been sent.
        Assert.Contains(PacketType.GlobalRequest, outboundTypes);

        // The router must have auto-sent REQUEST_FAILURE for the inbound 80.
        Assert.Contains(PacketType.RequestFailure, outboundTypes);
    }

    private static byte[] BuildGlobalRequestPayload(string name, bool wantReply)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        byte[] payload = new byte[1 + 4 + nameBytes.Length + 1];
        payload[0] = (byte)PacketType.GlobalRequest;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), (uint)nameBytes.Length);
        Buffer.BlockCopy(nameBytes, 0, payload, 5, nameBytes.Length);
        payload[5 + nameBytes.Length] = (byte)(wantReply ? 1 : 0);
        return payload;
    }

    [Fact]
    public async Task InboundGlobalRequest_WantReplyFalse_SendsNoReply()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        // C parity (packet.c:917-943): an inbound GLOBAL_REQUEST with
        // want_reply=0 (e.g. OpenSSH's no-more-sessions@openssh.com) must NOT
        // receive a REQUEST_FAILURE. The previous implementation replied
        // unconditionally — unsolicited protocol noise.
        using var h = new GlobalRequestHarness();

        // Feed an inbound GLOBAL_REQUEST with want_reply=0.
        byte[] inbound = BuildGlobalRequestPayload("no-more-sessions@openssh.com", wantReply: false);
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.GlobalRequest, inbound),
            cancellationToken);

        // Trigger a pump cycle via our own SendGlobalRequestAsync call so the
        // inbound 80 is routed.
        Task<RawPacket> sendTask = Task.Run(async () => await h.Router.SendGlobalRequestAsync(
            "keepalive@libssh2.org", default, wantReply: true,
            cancellationToken: cancellationToken));

        // Reply to OUR keepalive so the send completes. Awaiting the send
        // guarantees the keepalive GLOBAL_REQUEST is flushed before we drain:
        // under full-suite parallel load the Task.Run'd send might not have
        // been scheduled yet, and a drain started first would time out on an
        // empty pipe (flaky empty-collection failure).
        byte[] replyPayload = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            cancellationToken);
        h.CompleteInbound();
        await sendTask;

        // Drain what the client sent: the keepalive GLOBAL_REQUEST only.
        // No REQUEST_FAILURE may appear for the want_reply=0 inbound request.
        var outboundTypes = new List<int>();
        for (int i = 0; i < 4; i++)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromMilliseconds(300));
            try
            {
                RawPacket p = await h.ServerReader.ReadPacketAsync(cts.Token);
                outboundTypes.Add(p.Type);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        Assert.Contains(PacketType.GlobalRequest, outboundTypes);
        Assert.DoesNotContain(PacketType.RequestFailure, outboundTypes);
    }

    // ── Single-slot serialization ────────────────────────────────────────

    [Fact]
    public async Task SendGlobalRequest_ConcurrentWantReplyTrueCallers_SerializeViaLock()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // Two concurrent wantReply=true callers must not crosstalk. The
        // _globalReplyLock serializes them: whichever call acquires the lock
        // first sends its GLOBAL_REQUEST and awaits its reply; the second
        // call is blocked at the lock until the first completes. The order
        // is non-deterministic (Task.Run doesn't guarantee scheduling), so
        // we just assert both names appear and the wire output has exactly
        // two GLOBAL_REQUEST packets with no interleaving.
        using var h = new GlobalRequestHarness();

        var call1Done = new TaskCompletionSource<bool>();
        var call2Done = new TaskCompletionSource<bool>();

        Task<RawPacket> t1 = Task.Run(async () =>
        {
            RawPacket result = await h.Router.SendGlobalRequestAsync(
                "first-request", default, wantReply: true,
                cancellationToken: cancellationToken);
            call1Done.TrySetResult(true);
            return result;
        }, cancellationToken);

        Task<RawPacket> t2 = Task.Run(async () =>
        {
            RawPacket result = await h.Router.SendGlobalRequestAsync(
                "second-request", default, wantReply: true,
                cancellationToken: cancellationToken);
            call2Done.TrySetResult(true);
            return result;
        }, cancellationToken);

        // Give both tasks a moment to enter SendGlobalRequestAsync and contest
        // the lock. The pump itself runs inside SendGlobalRequestAsync.
        await Task.WhenAny(t1, Task.Delay(50, cancellationToken));
        await Task.WhenAny(t2, Task.Delay(50, cancellationToken));

        // Read the first GLOBAL_REQUEST off the wire.
        RawPacket first = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.GlobalRequest, first.Type);
        string firstName = ReadNameAt(first.Payload, 1);
        Assert.True(firstName is "first-request" or "second-request");

        // Reply to whoever went first.
        byte[] reply1 = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestSuccess, reply1),
            cancellationToken);

        // Wait briefly for the lock to release + the second caller to send.
        await Task.WhenAny(Task.WhenAll(call1Done.Task, call2Done.Task), Task.Delay(500, cancellationToken));

        // Read the second GLOBAL_REQUEST.
        RawPacket second = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.GlobalRequest, second.Type);
        string secondName = ReadNameAt(second.Payload, 1);
        Assert.True(secondName is "first-request" or "second-request");
        Assert.NotEqual(firstName, secondName);

        // Reply to the second caller.
        byte[] reply2 = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            GlobalRequestHarness.FrameCleartextPacket(PacketType.RequestSuccess, reply2),
            cancellationToken);
        h.CompleteInbound();

        await Task.WhenAll(t1, t2);
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static string ReadNameAt(byte[] payload, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
        return Encoding.ASCII.GetString(payload, offset + 4, (int)len);
    }
}
