using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Text;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Phase 5.1 keepalive tests — verifies the caller-driven keepalive config
/// state machine + wire-format parity with libssh2's <c>keepalive.c:45-101</c>.
/// </summary>
/// <remarks>
/// All tests use the internal <see cref="SshSession(TimeProvider)"/> constructor
/// with <see cref="FakeTimeProvider"/> so the elapsed-time gate in
/// <see cref="SshSession.SendKeepAliveAsync"/> is deterministic. The send path
/// writes to a cleartext <see cref="Pipe"/>; tests read the wire bytes back and
/// assert exact byte-for-byte equality with the libssh2 payload literal.
/// </remarks>
public class KeepAliveTests
{
    // The exact 27-byte keepalive payload from keepalive.c:74-80 with
    // want_reply=0 substituted into the trailing 'W' placeholder.
    //
    //   0x50               SSH_MSG_GLOBAL_REQUEST (80)
    //   0x00 0x00 0x00 0x15 name length = 21
    //   "keepalive@libssh2.org" (21 bytes)
    //   0x00               want_reply = false
    private static readonly byte[] s_wantReplyFalsePayload =
    [
        0x50, 0x00, 0x00, 0x00, 0x15,
        (byte)'k', (byte)'e', (byte)'e', (byte)'p', (byte)'a',
        (byte)'l', (byte)'i', (byte)'v', (byte)'e', (byte)'@',
        (byte)'l', (byte)'i', (byte)'b', (byte)'s', (byte)'s',
        (byte)'h', (byte)'2', (byte)'.', (byte)'o', (byte)'r',
        (byte)'g',
        0x00,
    ];

    // Same as above with want_reply=1.
    private static readonly byte[] s_wantReplyTruePayload =
    [
        0x50, 0x00, 0x00, 0x00, 0x15,
        (byte)'k', (byte)'e', (byte)'e', (byte)'p', (byte)'a',
        (byte)'l', (byte)'i', (byte)'v', (byte)'e', (byte)'@',
        (byte)'l', (byte)'i', (byte)'b', (byte)'s', (byte)'s',
        (byte)'h', (byte)'2', (byte)'.', (byte)'o', (byte)'r',
        (byte)'g',
        0x01,
    ];

    // ── BuildPayload wire-format tests ────────────────────────────────────

    [Fact]
    public void BuildPayload_WantReplyFalse_MatchesKeepaliveLiteral()
    {
        byte[] payload = KeepAlive.BuildPayload(false);
        Assert.Equal(s_wantReplyFalsePayload, payload);
    }

    [Fact]
    public void BuildPayload_WantReplyTrue_SetsTrailingByteToOne()
    {
        byte[] payload = KeepAlive.BuildPayload(true);
        Assert.Equal(s_wantReplyTruePayload, payload);
    }

    [Fact]
    public void BuildPayload_AlwaysReturns27Bytes()
    {
        Assert.Equal(27, KeepAlive.BuildPayload(false).Length);
        Assert.Equal(27, KeepAlive.BuildPayload(true).Length);
    }

    [Fact]
    public void RequestName_Is21BytesKeepaliveAtLibssh2DotOrg()
    {
        Assert.Equal(21, KeepAlive.RequestNameBytes.Length);
        Assert.Equal("keepalive@libssh2.org", Encoding.ASCII.GetString(KeepAlive.RequestNameBytes.Span));
    }

    // ── ConfigureKeepAlive state + interval=1 → 2 quirk ──────────────────

    [Fact]
    public async Task ConfigureKeepAlive_DisablesWhenIntervalZero()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);

        session.ConfigureKeepAlive(true, 0);

        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        Assert.Equal(0, seconds);
    }

    [Theory]
    [InlineData(0, 0)]     // disabled — fast-path, no quirk
    [InlineData(1, 2)]     // the keepalive.c:50-51 quirk
    [InlineData(2, 2)]     // 2 is unchanged
    [InlineData(30, 30)]   // a typical value is unchanged
    [InlineData(3600, 3600)]   // 1 hour is unchanged
    public async Task ConfigureKeepAlive_IntervalOneIsRewrittenToTwo(int input, int expectedSeconds)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        session.ConfigureKeepAlive(false, input);

        // Advance past the configured interval and call SendKeepAliveAsync.
        // The returned "seconds to next" is the *effective* interval after the
        // quirk rewrite — it tells the caller when to schedule the next send.
        time.Advance(TimeSpan.FromSeconds(expectedSeconds + 1));
        (PacketWriter? writer, Pipe _) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        Assert.Equal(expectedSeconds, seconds);
    }

    // ── SendKeepAliveAsync — disabled fast-path ──────────────────────────

    [Fact]
    public async Task SendKeepAlive_Disabled_ReturnsZeroWithoutSending()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe? pipe) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        session.ConfigureKeepAlive(false, 0);
        time.Advance(TimeSpan.FromMinutes(5));
        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        Assert.Equal(0, seconds);

        // Nothing was written.
        await pipe.Writer.CompleteAsync();
        ReadResult read = await pipe.Reader.ReadAsync(cancellationToken);
        Assert.True(read.IsCompleted && read.Buffer.IsEmpty);
    }

    // ── SendKeepAliveAsync — sends when interval elapsed ─────────────────

    [Fact]
    public async Task SendKeepAlive_IntervalElapsed_SendsPacketAndReturnsInterval()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe? pipe) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        session.ConfigureKeepAlive(false, 30);
        time.Advance(TimeSpan.FromSeconds(45));   // > interval

        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        Assert.Equal(30, seconds);   // full interval returned
        await AssertClientSentKeepaliveAsync(pipe, wantReply: false, cancellationToken);
    }

    [Fact]
    public async Task SendKeepAlive_WantReplyTrue_SendsFireAndForget()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // C parity (keepalive.c:82-93): keepalive is fire-and-forget even with
        // want_reply=1 — libssh2 sends the packet with the want_reply flag set
        // but NEVER reads the reply. The port previously routed wantReply=true
        // through ChannelRouter.SendGlobalRequestAsync and awaited the 81/82
        // reply, which could hang forever against a server that ignores the
        // request. This test verifies the
        // want_reply=1 wire byte and that NO reply is required for completion.
        var time = new FakeTimeProvider();
        var session = new SshSession(time);

        // Build the router + paired pipes (mirrors ChannelTestHarness without
        // taking a dependency on the Channel test namespace). The router is
        // wired so a late reply (if the server sends one) routes safely.
        var c2s = new Pipe();
        var s2c = new Pipe();
        var writer = new PacketWriter(c2s.Writer);
        var queue = new PacketQueue(new PacketReader(s2c.Reader));
        var router = new ChannelRouter(queue, writer);
        session.SetWriterForTest(writer);
        session.SetChannelRouterForTest(router);

        session.ConfigureKeepAlive(true, 10);

        // No inbound reply is fed at all — the send must complete anyway
        // (fire-and-forget).
        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        Assert.Equal(10, seconds);

        // Drain the client's outbound pipe and verify the keepalive packet has
        // want_reply=1 (the trailing byte of the 27-byte payload).
        await c2s.Writer.CompleteAsync();
        ReadResult read = await c2s.Reader.ReadAsync(cancellationToken);
        byte[] wireBytes = read.Buffer.ToArray();
        Assert.True(wireBytes.Length >= 32, "expected keepalive wire bytes");
        // Skip the 4-byte length + 1-byte padlen to reach the payload.
        Assert.Equal((byte)PacketType.GlobalRequest, wireBytes[5]);
        Assert.Equal(0x01, wireBytes[5 + 26]);   // wantReply=1 at payload offset 26
    }

    // ── SendKeepAliveAsync — first call always sends (C parity) ─────────

    [Fact]
    public async Task SendKeepAlive_FirstCallAlwaysSends()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // C parity (keepalive.c:71): keepalive_last_sent starts at 0 (calloc),
        // so the FIRST libssh2_keepalive_send always fires regardless of the
        // interval. The port previously seeded the baseline at session
        // construction, delaying the first keepalive by a full interval.
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe? pipe) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        session.ConfigureKeepAlive(false, 30);
        // Zero elapsed time — the first call must still send.
        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        Assert.Equal(30, seconds);
        await AssertClientSentKeepaliveAsync(pipe, wantReply: false, cancellationToken);
    }

    // ── SendKeepAliveAsync — does NOT send when not enough time elapsed ──

    [Fact]
    public async Task SendKeepAlive_NotEnoughElapsed_ReturnsRemainingAndDoesNotSend()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe? pipe) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        session.ConfigureKeepAlive(false, 30);

        // First call always sends (C parity), establishing last_sent.
        await session.SendKeepAliveAsync(cancellationToken);

        // Consume the first keepalive packet so the pipe is empty again.
        ReadResult firstRead = await pipe.Reader.ReadAsync(cancellationToken);
        pipe.Reader.AdvanceTo(firstRead.Buffer.End);

        // Advance only 10 seconds since the send — < interval.
        time.Advance(TimeSpan.FromSeconds(10));
        int seconds = await session.SendKeepAliveAsync(cancellationToken);

        // 30 - 10 = 20 seconds remaining until the next send is due.
        Assert.Equal(20, seconds);

        // Nothing was written by the second call.
        await pipe.Writer.CompleteAsync();
        ReadResult read = await pipe.Reader.ReadAsync(cancellationToken);
        Assert.True(read.IsCompleted && read.Buffer.IsEmpty);
    }

    // ── SendKeepAliveAsync — last_sent updates after each send ───────────

    [Fact]
    public async Task SendKeepAlive_SecondCallTooSoon_DoesNotResend()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe _) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        session.ConfigureKeepAlive(false, 30);

        time.Advance(TimeSpan.FromSeconds(35));
        int first = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(30, first);

        // Advance only 5 seconds since the last send.
        time.Advance(TimeSpan.FromSeconds(5));
        int second = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(25, second);   // 30 - 5 = 25 remaining
    }

    [Fact]
    public async Task SendKeepAlive_CatchesUpAfterLongGap_ThenResumesCadence()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe _) = MakeCleartextPipe();
        session.SetWriterForTest(writer);

        session.ConfigureKeepAlive(false, 30);

        // Skip far past the interval — still just ONE send (no catch-up burst,
        // matching libssh2 which sends at most one keepalive per call).
        time.Advance(TimeSpan.FromSeconds(120));
        int first = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(30, first);

        // Immediately after, only 0 seconds elapsed since last_sent — return
        // full interval.
        int second = await session.SendKeepAliveAsync(cancellationToken);
        Assert.Equal(30, second);
    }

    // ── Guard clauses ────────────────────────────────────────────────────

    [Fact]
    public async Task SendKeepAlive_BeforeHandshake_ThrowsInvalidOperation()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var session = new SshSession(new FakeTimeProvider());
        session.ConfigureKeepAlive(false, 30);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => session.SendKeepAliveAsync(cancellationToken).AsTask());
    }

    [Fact]
    public async Task SendKeepAlive_AfterDispose_ThrowsObjectDisposed()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var time = new FakeTimeProvider();
        var session = new SshSession(time);
        (PacketWriter? writer, Pipe _) = MakeCleartextPipe();
        session.SetWriterForTest(writer);
        session.ConfigureKeepAlive(false, 30);

        await session.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => session.SendKeepAliveAsync(cancellationToken).AsTask());
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// <summary>
    /// Frames a cleartext SSH packet (length|padlen|payload|padding) carrying
    /// the given payload. Mirrors <c>ChannelTestHarness.BuildCleartextPacket</c>.
    /// </summary>
    private static byte[] FrameCleartextPacket(byte[] payload)
    {
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

    /// <summary>
    /// Builds a cleartext SSH pipe pair: a <see cref="PacketWriter"/> for the
    /// session under test to write into, paired with the underlying
    /// <see cref="Pipe"/> the test consumes to assert wire bytes. Mirrors the
    /// <see cref="ChannelTestHarness"/> pattern without the router (keepalive
    /// is a session-level send, no router is needed for 5.1).
    /// </summary>
    private static (PacketWriter writer, Pipe pipe) MakeCleartextPipe()
    {
        var pipe = new Pipe();
        return (new PacketWriter(pipe.Writer), pipe);
    }

    /// <summary>
    /// Reads exactly one packet from the client's outbound pipe and asserts its
    /// cleartext payload (after the 5-byte SSH header) matches one of the two
    /// keepalive payload literals.
    /// </summary>
    private static async Task AssertClientSentKeepaliveAsync(Pipe pipe, bool wantReply, CancellationToken cancellationToken)
    {
        ReadResult read = await pipe.Reader.ReadAsync(cancellationToken);
        ReadOnlySequence<byte> buffer = read.Buffer;

        // Find the packet length (first 4 bytes BE). packet_length does NOT
        // include itself — it covers [padlen + payload + padding] only.
        Assert.True(buffer.Length >= 4, "no packet was written");
        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(0, 4).FirstSpan);

        // Total wire bytes = 4 (length field) + packetLength.
        Assert.True(buffer.Length >= 4 + packetLength,
            $"partial packet: buffer={buffer.Length}, declared packetLength={packetLength}");

        // The SSH payload begins at offset 5 (4-byte length + 1-byte padlen).
        ReadOnlySequence<byte> payloadSlice = buffer.Slice(5, 27);
        byte[] actual = payloadSlice.ToArray();
        byte[] expected = wantReply ? s_wantReplyTruePayload : s_wantReplyFalsePayload;
        Assert.Equal(expected, actual);
    }
}
