using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Increment 3.4.4 — rekey auto-trigger in <see cref="ChannelRouter"/>. The
/// router checks per-direction byte/packet counters and the elapsed time
/// against the configured <see cref="RekeyPolicy"/> at the top of every
/// <see cref="ChannelRouter.PumpOnceAsync"/> / <see cref="ChannelRouter.WaitAsync"/>
/// call; if exceeded, invokes the rekey callback (which drives
/// <see cref="SshSession.RekeyAsync"/>).
/// </summary>
/// <remarks>
/// Tests use the cleartext mock-pipe pattern (the channel protocol is
/// cipher-agnostic). The rekey callback is a counting stub — actual rekey
/// execution is exercised in 3.4.5 (full session integration) and 3.4.6
/// (end-to-end under load).
/// </remarks>
public class RekeyAutoTriggerTests
{
    // ── Byte threshold ──────────────────────────────────────────────────

    [Fact]
    public async Task PumpOnceAsync_InboundByteThresholdExceeded_TriggersRekey()
    {
        // Tiny byte threshold (4 bytes). Reading 2 packets (~32 bytes each
        // cleartext) exceeds the inbound threshold → rekey fires before the
        // next pump.
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 4, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // Feed a DATA packet; first pump: counters are 0 at start, no trigger;
        // reads the DATA packet (counters go > 4 after the read).
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, h.RekeyCalls);

        // Feed a second packet; next pump should fire the trigger (counters
        // exceeded after the first read) BEFORE reading the second packet.
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x02]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, h.RekeyCalls);
    }

    [Fact]
    public async Task PumpOnceAsync_OutboundByteThresholdExceeded_TriggersRekey()
    {
        // Outbound threshold exceeded by writing packets via the writer that
        // the router also reads. The router consults BOTH directions.
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 4, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // Write a packet to bump the outbound counter (16 bytes cleartext).
        // Drain the c2s pipe so the channel's WriteAsync FlushAsync completes.
        await h.Channel.WriteAsync(new byte[] { 0xAB }, TestContext.Current.CancellationToken);
        await h.DrainC2SAsync();

        // Now feed a DATA packet for inbound; next pump should fire trigger
        // (outbound bytes already exceed the threshold) before reading.
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, h.RekeyCalls);
    }

    // ── Packet threshold ────────────────────────────────────────────────

    [Fact]
    public async Task PumpOnceAsync_InboundPacketThresholdExceeded_TriggersRekey()
    {
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = long.MaxValue, MaxPackets = 1, MaxInterval = TimeSpan.MaxValue },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // First pump: feed a DATA packet; 0 packets at start, no trigger;
        // reads the DATA (counters go to 1 packet).
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, h.RekeyCalls);

        // Second pump: 1 packet at start → at threshold (>=). Trigger fires
        // before the next read.
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x02]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, h.RekeyCalls);
    }

    // ── Time threshold ─────────────────────────────────────────────────

    [Fact]
    public async Task PumpOnceAsync_TimeThresholdExceeded_TriggersRekey()
    {
        // Simulated elapsed time is 2 hours (the policy's MaxInterval is 1 hour).
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = long.MaxValue, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.FromHours(1) },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.FromHours(2));

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, h.RekeyCalls);
    }

    [Fact]
    public async Task PumpOnceAsync_TimeBelowThreshold_DoesNotTrigger()
    {
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = long.MaxValue, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.FromHours(1) },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.FromMinutes(30));

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, h.RekeyCalls);
    }

    // ── Never policy ───────────────────────────────────────────────────

    [Fact]
    public async Task PumpOnceAsync_NeverPolicy_NeverTriggers()
    {
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(RekeyPolicy.Never, h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.MaxValue);

        // Pump several packets — counters grow but Never disables all checks.
        for (int i = 0; i < 3; i++)
        {
            await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [(byte)i]));
            await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        }

        Assert.Equal(0, h.RekeyCalls);
    }

    // ── Both entry points check ─────────────────────────────────────────

    [Fact]
    public async Task WaitAsync_AlsoChecksRekeyThreshold()
    {
        // WaitAsync (used by open/exec/close) must also fire the trigger, not
        // just PumpOnceAsync (used by read/write).
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 1, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // WaitAsync for a ChannelSuccess — but counters start at 0 and the
        // inbound packet will be a ChannelData (channel-async, routed) — feed
        // a ChannelSuccess so it returns, but trigger should fire first
        // because the byte threshold is 1 and the writer/reader cross it
        // trivially. Actually counters start at 0; no trigger on first pump.
        // Feed a ChannelSuccess so WaitAsync returns.
        await h.FeedInboundAsync(
            RouterHarness.BuildCleartext(PacketType.ChannelSuccess, RouterHarness.BuildReply(PacketType.ChannelSuccess, 0)));

        // WaitAsync: the first iteration's MaybeRekey sees 0 counters (no fire);
        // it reads the SUCCESS packet and returns.
        RawPacket got = await h.Router.WaitAsync(
            [PacketType.ChannelSuccess, PacketType.ChannelFailure],
            TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelSuccess, got.Type);
        Assert.Equal(0, h.RekeyCalls);

        // Feed another packet; now the previous SUCCESS read bumped the
        // inbound counter past 1 byte. The next WaitAsync iteration fires
        // the trigger before reading.
        await h.FeedInboundAsync(
            RouterHarness.BuildCleartext(PacketType.ChannelSuccess, RouterHarness.BuildReply(PacketType.ChannelSuccess, 0)));
        // Rekey callback doesn't actually rekey (just counts); next read
        // picks up the SUCCESS packet.
        got = await h.Router.WaitAsync(
            [PacketType.ChannelSuccess, PacketType.ChannelFailure],
            TestContext.Current.CancellationToken);
        Assert.Equal(1, h.RekeyCalls);
        Assert.Equal(PacketType.ChannelSuccess, got.Type);
    }

    // ── Trigger fires once per excess (not per pump) ───────────────────

    [Fact]
    public async Task Trigger_FiresOncePerPumpCycle_NotPerPacket()
    {
        // The threshold is exceeded; the trigger fires exactly once per
        // PumpOnceAsync/WaitAsync iteration (the rekey callback is responsible
        // for actually resetting counters via RekeyAsync; if it doesn't,
        // every subsequent pump also fires — but each pump fires at most once).
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 1, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        // First pump: 0 bytes at start, no fire. Then reads packet → counters > 1.
        Assert.Equal(0, h.RekeyCalls);

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x02]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        // Second pump: counters > 1 at start; fire once before read.
        Assert.Equal(1, h.RekeyCalls);

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x03]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        // Third pump: still over threshold (callback didn't reset counters
        // — real RekeyAsync would); fires once more.
        Assert.Equal(2, h.RekeyCalls);
    }

    // ── Per-direction max (not sum) ─────────────────────────────────────

    [Fact]
    public async Task Trigger_UsesPerDirectionMax_NotSum()
    {
        // Each direction can be below the threshold alone but combined exceed
        // it; the trigger must NOT fire in that case (per-direction max, not
        // sum). With MaxBytes=64 and each direction ~32 bytes, neither side
        // alone exceeds 64.
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 64, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // First pump: reads a DATA packet (~32 bytes inbound). Below 64.
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, h.RekeyCalls);
    }

    // ── Exception propagation ──────────────────────────────────────────

    [Fact]
    public async Task RekeyCallbackException_PropagatesToPumpCaller()
    {
        var h = new RouterHarness();
        int calls = 0;
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 1, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            ct =>
            {
                calls++;
                throw new SshException(SshErrorCode.KeyExchangeFailure, "test");
            });
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // First pump: feed + read a DATA packet (counters at 0, no fire).
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, calls);

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
        Assert.Equal(1, calls);
    }

    // ── No config = no fire ─────────────────────────────────────────────

    [Fact]
    public async Task NoRekeyConfigured_NeverFires()
    {
        // The router's public ctor (for unit tests) does not call
        // ConfigureRekeyTrigger; PumpOnceAsync/WaitAsync must short-circuit.
        var h = new RouterHarness();
        // No ConfigureRekeyTrigger call.
        for (int i = 0; i < 3; i++)
        {
            await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [(byte)i]));
            await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        }

        Assert.Equal(0, h.RekeyCalls);
    }

    // ── Mixed thresholds: bytes OK, time exceeded ───────────────────────

    [Fact]
    public async Task Mixed_BytesOk_TimeExceeded_TriggersRekey()
    {
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = long.MaxValue, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.FromMinutes(30) },
            h.MakeRekeyCallback());
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.FromHours(2));

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, h.RekeyCalls);
    }

    // ── Cancellation propagation ───────────────────────────────────────

    [Fact]
    public async Task RekeyCallback_ReceivesCallingCancellationToken()
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        CancellationToken seen = default;
        var h = new RouterHarness();
        h.Router.ConfigureRekeyTrigger(
            new RekeyPolicy { MaxBytes = 1, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
            ct =>
            {
                seen = ct;
                return Task.CompletedTask;
            });
        h.Router.SetElapsedSinceHandshakeAccessor(() => TimeSpan.Zero);

        // First pump at zero counters — no fire. Feed + read DATA.
        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x01]));
        await h.Router.PumpOnceAsync(cts.Token);

        await h.FeedInboundAsync(RouterHarness.BuildChannelData(0, [0x02]));
        await h.Router.PumpOnceAsync(cts.Token);
        Assert.Equal(cts.Token, seen);
    }

    // ── Harness ─────────────────────────────────────────────────────────

    /// <summary>
    /// A minimal router test harness: cleartext pipes + a registered channel
    /// (local id 0, remote id 100) + a counting rekey callback. Mirrors the
    /// <see cref="ChannelTestHarness"/> pattern but tailored for rekey tests
    /// (the existing harness doesn't expose ConfigureRekeyTrigger).
    /// </summary>
    private sealed class RouterHarness : IDisposable
    {
        private readonly Pipe _c2s = new();
        private readonly Pipe _s2c = new();
        private readonly PacketQueue _queue;
        private readonly ChannelRouter _router;

        public RouterHarness()
        {
            ClientWriter = new PacketWriter(_c2s.Writer);
            _queue = new PacketQueue(new PacketReader(_s2c.Reader));
            _router = new ChannelRouter(_queue, ClientWriter);
            Channel = new SshChannel(ClientWriter, _router, localId: 0, remoteId: 100,
                outboundWindow: ChannelConstants.WindowDefault,
                outboundMaxPacket: ChannelConstants.PacketDefault,
                inboundWindow: ChannelConstants.WindowDefault,
                inboundMaxPacket: ChannelConstants.PacketDefault);
            _router.Register(Channel);
            ServerReader = new PacketReader(_c2s.Reader);
        }

        public PacketWriter ClientWriter { get; }
        public ChannelRouter Router => _router;
        public SshChannel Channel { get; }
        public PacketReader ServerReader { get; }
        public int RekeyCalls { get; private set; }

        public Func<CancellationToken, Task> MakeRekeyCallback()
            => ct =>
            {
                RekeyCalls++;
                return Task.CompletedTask;
            };

        public async Task FeedInboundAsync(params byte[][] packets)
        {
            foreach (byte[] pkt in packets)
            {
                await _s2c.Writer.WriteAsync(pkt, TestContext.Current.CancellationToken);
            }
        }

        /// <summary>
        /// Drains the client→server pipe so the channel's <see cref="SshChannel.WriteAsync"/>
        /// <c>FlushAsync</c> completes. Used after writing to the channel to
        /// observe the outbound counter bump without blocking on backpressure.
        /// </summary>
        public async Task DrainC2SAsync()
        {
            ReadResult rr = await _c2s.Reader.ReadAsync(TestContext.Current.CancellationToken);
            _c2s.Reader.AdvanceTo(rr.Buffer.End);
        }

        public static byte[] BuildChannelData(uint recipient, byte[] data)
            => BuildCleartext(PacketType.ChannelData, BuildChannelDataPayload(recipient, data));

        public static byte[] BuildCleartext(int type, byte[] payload)
            => BuildCleartextPacket(type, payload);

        public static byte[] BuildReply(int type, uint recipientChannel)
        {
            byte[] payload = new byte[5];
            payload[0] = (byte)type;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
            return payload;
        }

        private static byte[] BuildChannelDataPayload(uint recipientChannel, byte[] data)
        {
            byte[] payload = new byte[1 + 4 + 4 + data.Length];
            payload[0] = (byte)PacketType.ChannelData;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), (uint)data.Length);
            Buffer.BlockCopy(data, 0, payload, 9, data.Length);
            return payload;
        }

        private static byte[] BuildCleartextPacket(int type, byte[] payload)
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

        public void Dispose()
        {
            try
            {
                _router.Dispose();
            }
            catch (ObjectDisposedException) { }
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
            try
            {
                _c2s.Reader.Complete();
            }
            catch (InvalidOperationException) { }
            try
            {
                _s2c.Reader.Complete();
            }
            catch (InvalidOperationException) { }
        }
    }
}
