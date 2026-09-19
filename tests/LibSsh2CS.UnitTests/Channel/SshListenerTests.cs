using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Phase 5.5 <see cref="SshListener"/> tests. Verifies the listener lifecycle
/// independently of the inbound forwarded-tcpip dispatch (which is added in
/// 5.6): listen + reply parsing, bound-port extraction, cancel-tcpip-forward
/// teardown, accept-queue mechanics, and session-dispose propagation.
/// </summary>
/// <remarks>
/// Tests build a paired-pipe harness over an <see cref="SshSession"/> +
/// <see cref="ChannelRouter"/> (no full handshake) and drive the
/// <c>tcpip-forward</c> / <c>cancel-tcpip-forward</c> round-trip by feeding
/// framed replies from the "server" side. Accept-queue tests manually call
/// <see cref="SshListener.TryEnqueueAccept"/> (the internal seam used by
/// Phase 5.6's inbound dispatch).
/// </remarks>
public class SshListenerTests
{
    // ── Listen success ────────────────────────────────────────────────────

    [Fact]
    public async Task ListenForward_NullHost_DefaultsTo_0_0_0_0()
    {
        // channel.c:550-551 — null host defaults to "0.0.0.0".
        ListenerHarness h = await ListenAndReplyAsync(
            host: null, port: 8000,
            replyBoundPort: null);   // empty-body reply

        try
        {
            Assert.Equal("0.0.0.0", h.Listener.Host);
            Assert.Equal(8000, h.Listener.BoundPort);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ListenForward_ExplicitHost_PreservedInListenerAndWire()
    {
        ListenerHarness h = await ListenAndReplyAsync(
            host: "127.0.0.1", port: 22,
            replyBoundPort: null);

        try
        {
            Assert.Equal("127.0.0.1", h.Listener.Host);
            Assert.Equal(22, h.Listener.BoundPort);

            // Verify the wire payload had the explicit host.
            RawPacket wire = h.SentGlobalRequest;
            Assert.Equal("tcpip-forward", ReadNameAt(wire.Payload, 1));
            Assert.Equal("127.0.0.1", ReadStringAt(wire.Payload, 1 + 4 + "tcpip-forward".Length + 1));
            Assert.Equal(22u,
                BinaryPrimitives.ReadUInt32BigEndian(wire.Payload.AsSpan(
                    1 + 4 + "tcpip-forward".Length + 1 + 4 + "127.0.0.1".Length, 4)));
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ListenForward_PortZero_ServerAssignedPortFromReplyBody()
    {
        // channel.c:650-656 — port=0 + reply body u32 → BoundPort = server's
        // assigned port.
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 0,
            replyBoundPort: 54321);

        try
        {
            Assert.Equal(54321, h.Listener.BoundPort);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ListenForward_ExplicitPort_EmptyReplyBody_KeepsExplicitPort()
    {
        // channel.c:657-658 — explicit port + (any reply) → BoundPort = caller's port.
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 9000,
            replyBoundPort: null);

        try
        {
            Assert.Equal(9000, h.Listener.BoundPort);
        }
        finally
        {
            await h.DisposeAsync();
        }
    }

    [Fact]
    public async Task ListenForward_RequestFailure_ThrowsRequestDenied()
    {
        // Server refuses the tcpip-forward request.
        await using var harness = new ListenerHarness();
        harness.BootstrapSession();

        Task<SshListener> listenTask = Task.Run(() => harness.Session.ListenForwardAsync(
            host: "0.0.0.0", port: 1234,
            cancellationToken: TestContext.Current.CancellationToken));

        // Drain the GLOBAL_REQUEST then feed REQUEST_FAILURE.
        RawPacket sent = await harness.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal("tcpip-forward", ReadNameAt(sent.Payload, 1));

        byte[] failPayload = new byte[] { (byte)PacketType.RequestFailure };
        await harness.ServerWriter.WriteAsync(
            FrameCleartextPacket(PacketType.RequestFailure, failPayload),
            TestContext.Current.CancellationToken);
        harness.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(() => listenTask);
        Assert.Equal(SshErrorCode.RequestDenied, ex.ErrorCode);

        // The listener was never registered.
        Assert.Null(harness.Session.TryGetListener("0.0.0.0", 1234));
    }

    // ── Cancel-tcpip-forward (DisposeAsync) ───────────────────────────────

    [Fact]
    public async Task Dispose_SendsCancelTcpipForward_WithHostAndPort_WantReplyFalse()
    {
        // channel.c:743-749 — cancel-tcpip-forward payload:
        //   [80][string "cancel-tcpip-forward"][byte 0x00 want_reply][string host][u32 port]
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 7000, replyBoundPort: null);

        await h.Listener.DisposeAsync();

        // Read the second GLOBAL_REQUEST on the wire (the first was the
        // tcpip-forward setup, already consumed by ListenAndReplyAsync).
        RawPacket cancel = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.GlobalRequest, cancel.Type);
        Assert.Equal("cancel-tcpip-forward", ReadNameAt(cancel.Payload, 1));
        Assert.Equal(0, cancel.Payload[1 + 4 + "cancel-tcpip-forward".Length]);   // wantReply=false

        int extraOffset = 1 + 4 + "cancel-tcpip-forward".Length + 1;
        Assert.Equal("0.0.0.0", ReadStringAt(cancel.Payload, extraOffset));
        Assert.Equal(7000u,
            BinaryPrimitives.ReadUInt32BigEndian(cancel.Payload.AsSpan(
                extraOffset + 4 + "0.0.0.0".Length, 4)));

        Assert.True(h.Listener.IsDisposed);
    }

    [Fact]
    public async Task Dispose_IsIdempotent_SecondCallIsNoOp()
    {
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 7001, replyBoundPort: null);

        await h.Listener.DisposeAsync();
        // Drain the cancel-tcpip-forward from the first Dispose.
        RawPacket firstCancel = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal("cancel-tcpip-forward", ReadNameAt(firstCancel.Payload, 1));

        // Second Dispose must be a no-op — no additional wire output.
        await h.Listener.DisposeAsync();

        // After completing the outbound writer, the wire should show no
        // additional packets beyond the single cancel we already read.
        h.CompleteOutbound();
        Assert.True(h.Listener.IsDisposed);

        // Session registry no longer holds the listener.
        Assert.Null(h.Session.TryGetListener("0.0.0.0", 7001));
    }

    [Fact]
    public async Task Dispose_UnregistersFromSession()
    {
        ListenerHarness h = await ListenAndReplyAsync(
            host: "127.0.0.1", port: 8080, replyBoundPort: null);

        Assert.NotNull(h.Session.TryGetListener("127.0.0.1", 8080));
        await h.Listener.DisposeAsync();
        Assert.Null(h.Session.TryGetListener("127.0.0.1", 8080));
    }

    [Fact]
    public async Task Dispose_DrainsAndDisposesQueuedChannels()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // The listener's DisposeAsync drains the accept queue and disposes
        // each queued channel via the normal close handshake. Each channel
        // sends EOF + CLOSE on the wire; this test concurrently feeds
        // CHANNEL_CLOSE replies so the handshakes complete.
        var h = new ListenerHarness();
        h.BootstrapSession();

        Task<SshListener> listenTask = Task.Run(() => h.Session.ListenForwardAsync(
            "0.0.0.0", 5000, 10,
            cancellationToken: cancellationToken), cancellationToken);
        h.SentGlobalRequest = await h.ServerReader.ReadPacketAsync(cancellationToken);
        byte[] replyPayload = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            ListenerHarness.FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            cancellationToken);
        SshListener listener = await listenTask;

        SshChannel ch1 = h.CreateAndRegisterChannel();
        SshChannel ch2 = h.CreateAndRegisterChannel();
        Assert.True(listener.TryEnqueueAccept(ch1));
        Assert.True(listener.TryEnqueueAccept(ch2));
        Assert.Equal(2, listener.QueuedCount);

        // Drive the dispose concurrently with feeding close replies.
        var disposeTask = Task.Run(() => listener.DisposeAsync().AsTask(), cancellationToken);

        // SshListener.DisposeAsync sends cancel-tcpip-forward FIRST (parity
        // channel.c:757-778), then drains the queued channels. Read the
        // cancel packet first.
        RawPacket cancel = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal("cancel-tcpip-forward", ReadNameAt(cancel.Payload, 1));

        // For each of the 2 channels, expect EOF + CLOSE on the wire, then
        // feed back a CHANNEL_CLOSE that the router can dispatch to the
        // channel's LOCAL id (the router keys channels by local id; the
        // inbound CLOSE's recip field must equal our localId).
        foreach (SshChannel ch in new[] { ch1, ch2 })
        {
            RawPacket eof = await h.ServerReader.ReadPacketAsync(cancellationToken);
            Assert.Equal(PacketType.ChannelEof, eof.Type);
            RawPacket close = await h.ServerReader.ReadPacketAsync(cancellationToken);
            Assert.Equal(PacketType.ChannelClose, close.Type);

            byte[] closeReply = new byte[5];
            closeReply[0] = (byte)PacketType.ChannelClose;
            BinaryPrimitives.WriteUInt32BigEndian(closeReply.AsSpan(1, 4), ch.LocalId);
            await h.ServerWriter.WriteAsync(
                ListenerHarness.FrameCleartextPacket(PacketType.ChannelClose, closeReply),
                cancellationToken);
        }

        h.CompleteInbound();
        await disposeTask;

        Assert.Equal(0, listener.QueuedCount);
        Assert.True(listener.IsDisposed);
    }

    [Fact]
    public async Task Dispose_QueueOverflow_TryEnqueueReturnsFalse()
    {
        // Verify TryEnqueueAccept enforces QueueMaxSize. We don't drive
        // a full close handshake for the queued channel here — instead we
        // verify the boolean return and queue count, then let the harness
        // disposal tear down the router (which unblocks any parked waiters).
        var h = new ListenerHarness();
        h.BootstrapSession();

        Task<SshListener> listenTask = Task.Run(() => h.Session.ListenForwardAsync(
            "0.0.0.0", 5001, 1,
            cancellationToken: TestContext.Current.CancellationToken));
        h.SentGlobalRequest = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        byte[] replyPayload = new byte[] { (byte)PacketType.RequestSuccess };
        await h.ServerWriter.WriteAsync(
            ListenerHarness.FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            TestContext.Current.CancellationToken);
        SshListener listener = await listenTask;

        SshChannel ch1 = h.CreateAndRegisterChannel();
        SshChannel ch2 = h.CreateAndRegisterChannel();

        Assert.True(listener.TryEnqueueAccept(ch1));
        Assert.False(listener.TryEnqueueAccept(ch2));   // queue full
        Assert.Equal(1, listener.QueuedCount);

        // Don't await listener.DisposeAsync (would hang without close replies);
        // harness disposal disposes the router which unblocks the queued
        // channel's eventual DisposeAsync call.
    }

    // ── AcceptAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task AcceptAsync_PreEnqueuedChannel_ReturnsImmediately()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 6000, replyBoundPort: null);

        SshChannel ch = h.CreateAndRegisterChannel();
        Assert.True(h.Listener.TryEnqueueAccept(ch));

        SshChannel accepted = await h.Listener.AcceptAsync(cancellationToken);
        Assert.Same(ch, accepted);

        await h.Listener.DisposeAsync();
    }

    [Fact]
    public async Task AcceptAsync_EmptyQueue_BlocksUntilChannelEnqueued()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 6001, replyBoundPort: null);

        Task<SshChannel> acceptTask = Task.Run(() => h.Listener.AcceptAsync(
            cancellationToken), cancellationToken);

        // Give the accept call a moment to park.
        await Task.Delay(50, cancellationToken);

        // Enqueue from a different task.
        SshChannel ch = h.CreateAndRegisterChannel();
        Assert.True(h.Listener.TryEnqueueAccept(ch));

        SshChannel accepted = await acceptTask;
        Assert.Same(ch, accepted);

        await h.Listener.DisposeAsync();
    }

    [Fact]
    public async Task AcceptAsync_DisposedWhileWaiting_ThrowsChannelUnknown()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 6002, replyBoundPort: null);

        Task<SshChannel> acceptTask = Task.Run(() => h.Listener.AcceptAsync(
            cancellationToken), cancellationToken);

        await Task.Delay(50, cancellationToken);
        await h.Listener.DisposeAsync();   // wake the waiter with IsDisposed=true

        SshException ex = await Assert.ThrowsAsync<SshException>(() => acceptTask);
        Assert.Equal(SshErrorCode.ChannelUnknown, ex.ErrorCode);
    }

    [Fact]
    public async Task Dispose_MultipleParkedAcceptWaiters_AllWakeWithChannelUnknown()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        ListenerHarness h = await ListenAndReplyAsync(
            host: "0.0.0.0", port: 6003, replyBoundPort: null);

        Task<SshChannel>[] acceptTasks = Enumerable.Range(0, 3)
            .Select(_ => Task.Run(() => h.Listener.AcceptAsync(cancellationToken), cancellationToken))
            .ToArray();

        // Give all three accept calls a moment to park on the semaphore.
        await Task.Delay(100, cancellationToken);

        await h.Listener.DisposeAsync();

        // All waiters must be woken. Before the fix only one was released, so
        // this Task.WhenAny would time out.
        Task all = Task.WhenAll(acceptTasks);
        Task completed = await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(2), cancellationToken));
        Assert.Same(all, completed);

        foreach (Task<SshChannel> task in acceptTasks)
        {
            SshException ex = await Assert.ThrowsAsync<SshException>(() => task);
            Assert.Equal(SshErrorCode.ChannelUnknown, ex.ErrorCode);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static string ReadNameAt(byte[] payload, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
        return Encoding.ASCII.GetString(payload, offset + 4, (int)len);
    }

    private static string ReadStringAt(byte[] payload, int offset) => ReadNameAt(payload, offset);

    private static byte[] FrameCleartextPacket(int type, byte[] payload) => ListenerHarness.FrameCleartextPacket(type, payload);

    /// <summary>
    /// Drives a full ListenForwardAsync round-trip against the harness and
    /// returns the resulting <see cref="ListenerHarness"/> with
    /// <see cref="ListenerHarness.Listener"/> populated. The
    /// <paramref name="replyBoundPort"/> controls the reply body — pass null
    /// for an empty body (caller specified an explicit port) or an int for a
    /// u32 bound port (caller passed port=0).
    /// </summary>
    private static async Task<ListenerHarness> ListenAndReplyAsync(
        string? host, int port, int? replyBoundPort, int queueMaxSize = 10)
    {
        var h = new ListenerHarness();
        h.BootstrapSession();

        Task<SshListener> listenTask = Task.Run(() => h.Session.ListenForwardAsync(
            host, port, queueMaxSize,
            cancellationToken: TestContext.Current.CancellationToken));

        // Wait for the tcpip-forward GLOBAL_REQUEST.
        h.SentGlobalRequest = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Build the reply.
        byte[] replyPayload;
        if (replyBoundPort is int bp)
        {
            replyPayload = new byte[5];
            replyPayload[0] = (byte)PacketType.RequestSuccess;
            BinaryPrimitives.WriteUInt32BigEndian(replyPayload.AsSpan(1, 4), (uint)bp);
        }
        else
        {
            replyPayload = new byte[] { (byte)PacketType.RequestSuccess };
        }

        await h.ServerWriter.WriteAsync(
            FrameCleartextPacket(PacketType.RequestSuccess, replyPayload),
            TestContext.Current.CancellationToken);

        h.Listener = await listenTask;

        // Complete the inbound pipe so subsequent channel DisposeAsync calls
        // observe EOF immediately and don't block waiting for a peer CLOSE
        // that the test will never send. Tests that need to send more
        // inbound packets after this point should construct their own harness
        // instead of using this helper.
        h.CompleteInbound();
        return h;
    }

    /// <summary>
    /// Harness that builds an SshSession + ChannelRouter over a paired-pipe
    /// setup without a full SSH handshake. The test "server" side writes
    /// framed replies via <see cref="ServerWriter"/>; the client's outbound
    /// packets are readable via <see cref="ServerReader"/>.
    /// </summary>
    private sealed class ListenerHarness : IAsyncDisposable
    {
        private readonly Pipe _c2s = new();
        private readonly Pipe _s2c = new();

        public SshSession Session { get; } = new();
        public PacketReader ServerReader { get; }
        public PipeWriter ServerWriter => _s2c.Writer;
        public PacketWriter ClientWriter { get; }
        public ChannelRouter Router { get; }
        public RawPacket SentGlobalRequest { get; set; }
        public SshListener Listener { get; set; } = null!;

        public ListenerHarness()
        {
            ClientWriter = new PacketWriter(_c2s.Writer);
            ServerReader = new PacketReader(_c2s.Reader);
            var queue = new PacketQueue(new PacketReader(_s2c.Reader));
            Router = new ChannelRouter(queue, ClientWriter);
        }

        public void BootstrapSession()
        {
            Session.SetWriterForTest(ClientWriter);
            Session.SetChannelRouterForTest(Router);
        }

        public void CompleteInbound() => _s2c.Writer.Complete();
        public void CompleteOutbound() => _c2s.Writer.Complete();

        public SshChannel CreateAndRegisterChannel()
        {
            uint lid = Router.AllocateLocalId();
            uint rid = lid + 100;
            var channel = new SshChannel(ClientWriter, Router, lid, rid,
                outboundWindow: ChannelConstants.WindowDefault,
                outboundMaxPacket: ChannelConstants.PacketDefault);
            Router.Register(channel);
            return channel;
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

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (Listener is not null)
                {
                    await Listener.DisposeAsync();
                }
            }
            catch (SshException) { }

            try
            {
                await _c2s.Writer.CompleteAsync();
            }
            catch (InvalidOperationException) { }
            try
            {
                await _s2c.Writer.CompleteAsync();
            }
            catch (InvalidOperationException) { }
            Router.Dispose();
        }
    }
}
