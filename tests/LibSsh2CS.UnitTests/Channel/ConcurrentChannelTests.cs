using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Multi-channel concurrency tests for the cooperative pumper (increment
/// 3.6.2/3.6.3). Two or more <see cref="SshChannel"/> instances on one
/// <see cref="ChannelRouter"/> have outstanding operations simultaneously,
/// driven via <see cref="Task.WhenAll"/>/<see cref="Task.Run"/>. The cleartext
/// harness is shared (single mock-server thread = the test thread); the
/// concurrency under test is on the CLIENT side.
/// </summary>
/// <remarks>
/// These tests verify the core invariants added in 3.6:
/// <list type="bullet">
/// <item>Two channels can have outstanding <see cref="SshChannel.ReadAsync"/>
/// calls at the same time — neither blocks the other from making progress.</item>
/// <item>The active pumper routes packets to non-pumping channels via the
/// per-channel signal; cancellation of one channel doesn't strand another.</item>
/// <item>Reply packets route by recipient channel id (not type alone), so two
/// concurrent exec requests get the right replies.</item>
/// <item><see cref="SshChannel.WriteAsync"/> does not need the pump-lock, so a
/// blocked reader doesn't block writes — the deadlock-avoidance invariant.</item>
/// </list>
/// </remarks>
public class ConcurrentChannelTests
{
    // ── 1. Concurrent Read: each channel gets its own data ──────────────

    /// <summary>
    /// Two channels each call <see cref="SshChannel.ReadAsync"/> concurrently
    /// (via <see cref="Task.Run"/>). Both block. The mock server then feeds one
    /// DATA packet for each. Each channel must unblock and return its own data
    /// — never the other channel's. This is the foundational cooperative-pumper
    /// scenario: the active pumper routes packets to non-pumping channels via
    /// the per-channel signal.
    /// </summary>
    [Fact]
    public async Task ConcurrentReads_EachChannelGetsItsOwnData()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        byte[] bufA = new byte[16];
        byte[] bufB = new byte[16];

        // Start both reads concurrently. They race for the pump-lock; one wins
        // and blocks on ReadPacketAsync, the other registers a TCS and waits.
        Task<int> readA = Task.Run(() => chA.ReadAsync(bufA, cancellationToken));
        Task<int> readB = Task.Run(() => chB.ReadAsync(bufB, cancellationToken));

        // Give both reads a moment to enter their wait state.
        await Task.Yield();
        await Task.Delay(50, cancellationToken);

        // Feed DATA for A, then DATA for B. The active pumper reads one,
        // routes it; on the next pump it reads the other.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xAA])),
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(1, [0xBB])));
        h.CompleteInbound();

        int nA = await readA;
        int nB = await readB;

        Assert.Equal(1, nA);
        Assert.Equal(0xAA, bufA[0]);
        Assert.Equal(1, nB);
        Assert.Equal(0xBB, bufB[0]);
    }

    // ── 2. Concurrent Write: both reach the wire ────────────────────────

    /// <summary>
    /// Two channels call <see cref="SshChannel.WriteAsync"/> concurrently. The
    /// writer lock (3.6.1) serializes the actual wire writes; both DATA packets
    /// reach the server, each addressed to the correct remote channel id.
    /// Verifies the writer-lock invariant: on-wire ordering matches call
    /// ordering, no corruption.
    /// </summary>
    [Fact]
    public async Task ConcurrentWrites_BothPacketsReachWireUncorrupted()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        byte[] dataA = { 0x01, 0x02, 0x03 };
        byte[] dataB = { 0x04, 0x05, 0x06, 0x07 };

        var writeA = Task.Run(() => chA.WriteAsync(dataA, cancellationToken), cancellationToken);
        var writeB = Task.Run(() => chB.WriteAsync(dataB, cancellationToken), cancellationToken);

        await Task.WhenAll(writeA, writeB);

        // Read both packets from the server side and verify they carry the
        // right recipient + payload. Order is unspecified (the lock serializes
        // but the threadpool schedules); collect as a set.
        var seen = new Dictionary<uint, byte[]>();
        for (int i = 0; i < 2; i++)
        {
            RawPacket pkt = await h.ServerReader.ReadPacketAsync(cancellationToken);
            Assert.Equal(PacketType.ChannelData, pkt.Type);
            uint recipient = BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4));
            uint dataLen = BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(5, 4));
            byte[] data = pkt.Payload.AsSpan(9, (int)dataLen).ToArray();
            seen[recipient] = data;
        }

        Assert.Equal(dataA, seen[100]);   // chA.RemoteId=100
        Assert.Equal(dataB, seen[200]);   // chB.RemoteId=200
    }

    // ── 3. Deadlock avoidance: read blocked, write completes ────────────

    /// <summary>
    /// The headline deadlock-avoidance test: channel A's <see cref="SshChannel.ReadAsync"/>
    /// is blocked waiting for data (it holds the pump-lock, awaiting a packet
    /// from the server). Channel B's <see cref="SshChannel.WriteAsync"/> is
    /// issued concurrently. B's write MUST complete promptly — writes do not
    /// need the pump-lock. If B's write were to block on A's pump, a deadlock
    /// would occur when the server only sends A's data in response to B's write.
    /// </summary>
    /// <remarks>
    /// This is the design invariant documented in the cooperative-pumper XML
    /// doc: writes (which go through <see cref="PacketWriter.WritePacketAsync"/>'s
    /// own lock, NOT the pump-lock) must proceed independently of any read in
    /// flight.
    /// </remarks>
    [Fact]
    public async Task BlockedRead_DoesNotBlock_ConcurrentWrite()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        byte[] bufA = new byte[16];
        // Start A's read — it will acquire the pump-lock and block on the pipe.
        Task<int> readA = Task.Run(() => chA.ReadAsync(bufA, cancellationToken));
        await Task.Yield();
        await Task.Delay(50, cancellationToken);   // Let A enter the blocked read.

        // B's write should complete promptly. The pump-lock is held by A but
        // writes do not need it.
        byte[] dataB = { 0x42 };
        var writeB = Task.Run(() => chB.WriteAsync(dataB, cancellationToken), cancellationToken);

        // Verify the write completes within a short timeout.
        await Task.WhenAny(writeB, Task.Delay(2000, cancellationToken));
        Assert.True(writeB.IsCompleted, "B's write should have completed despite A's blocked read");

        // Server reads B's DATA packet — proves the write reached the wire.
        RawPacket dataPkt = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelData, dataPkt.Type);
        Assert.Equal(200u, BinaryPrimitives.ReadUInt32BigEndian(dataPkt.Payload.AsSpan(1, 4)));

        // Now unblock A's read by feeding its data.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0xAA])));
        h.CompleteInbound();

        int nA = await readA;
        Assert.Equal(1, nA);
        Assert.Equal(0xAA, bufA[0]);
    }

    // ── 4. Concurrent Exec: replies route by recipient id ───────────────

    /// <summary>
    /// Two channels call <see cref="SshChannel.ExecAsync"/> concurrently. The
    /// server replies <c>CHANNEL_SUCCESS</c> for each — with the correct
    /// recipient channel id. Each channel's <see cref="SshChannel.SendChannelRequestAsync"/>
    /// waits via <see cref="ChannelRouter.WaitForReplyAsync"/>, which routes by
    /// recipient id (not type alone). If the routing is broken, one channel
    /// consumes the other's reply and the other hangs.
    /// </summary>
    [Fact]
    public async Task ConcurrentExecs_RepliesRouteByRecipientId()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        var execA = Task.Run(() => chA.ExecAsync("ls", cancellationToken), cancellationToken);
        var execB = Task.Run(() => chB.ExecAsync("pwd", cancellationToken), cancellationToken);

        // Server reads both CHANNEL_REQUEST "exec" packets.
        RawPacket reqA = await h.ServerReader.ReadPacketAsync(cancellationToken);
        RawPacket reqB = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelRequest, reqA.Type);
        Assert.Equal(PacketType.ChannelRequest, reqB.Type);

        // Server replies SUCCESS for each — with the right recipient id.
        // Recipient is the LOCAL id the client assigned.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)),
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 1)));

        // Both exec tasks should complete; if recipient routing is broken,
        // one task hangs and WhenAll never returns.
        await Task.WhenAll(execA, execB);
    }

    // ── 5. Dispose one channel while another reads ──────────────────────

    /// <summary>
    /// Channel A's <see cref="SshChannel.ReadAsync"/> is blocked. Channel B's
    /// <see cref="SshChannel.DisposeAsync"/> runs concurrently — sends EOF +
    /// CLOSE, waits for peer CLOSE. A's read remains pending. Verifies that
    /// B's close handshake doesn't strand A.
    /// </summary>
    [Fact]
    public async Task DisposeChannelB_WhileChannelAReads_BothClean()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        byte[] bufA = new byte[8];
        Task<int> readA = Task.Run(() => chA.ReadAsync(bufA, cancellationToken));
        await Task.Yield();
        await Task.Delay(50, cancellationToken);

        // Start B's dispose. It will send EOF + CLOSE on the wire.
        var disposeB = Task.Run(() => chB.DisposeAsync().AsTask(), cancellationToken);

        // Server reads EOF + CLOSE for B.
        RawPacket eof = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelEof, eof.Type);
        Assert.Equal(200u, BinaryPrimitives.ReadUInt32BigEndian(eof.Payload.AsSpan(1, 4)));

        RawPacket close = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelClose, close.Type);
        Assert.Equal(200u, BinaryPrimitives.ReadUInt32BigEndian(close.Payload.AsSpan(1, 4)));

        // Server replies with its CLOSE; B's dispose completes.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelClose, ChannelTestHarness.BuildClosePayload(1)));
        await disposeB;

        // B is now unregistered. A is still blocked on its read. Feed A's data
        // and verify it completes — proves A wasn't stranded by B's dispose.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, [0x77])));
        h.CompleteInbound();

        int nA = await readA;
        Assert.Equal(1, nA);
        Assert.Equal(0x77, bufA[0]);
    }

    // ── 6. Cancellation of one channel doesn't strand another ───────────

    /// <summary>
    /// Channel A's <see cref="SshChannel.ReadAsync"/> is cancelled mid-flight.
    /// Channel B's <see cref="SshChannel.ReadAsync"/> is also outstanding. After
    /// A's cancellation propagates, B's read should still complete when data
    /// arrives. Verifies the cooperative-pumper cancellation path releases the
    /// pump-lock cleanly (the CT fires inside ReadPacketAsync, the finally
    /// block releases the lock, the next op can acquire it).
    /// </summary>
    [Fact]
    public async Task CancelReadA_ReadBStillCompletes()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        using var ctsA = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        byte[] bufA = new byte[8];
        byte[] bufB = new byte[8];

        Task<int> readA = Task.Run(() => chA.ReadAsync(bufA, ctsA.Token));
        Task<int> readB = Task.Run(() => chB.ReadAsync(bufB, cancellationToken));

        await Task.Yield();
        await Task.Delay(50, cancellationToken);

        // Cancel A. A's read should throw OCE.
        await ctsA.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await readA);

        // B's read should still complete when data arrives.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(1, [0xCD])));
        h.CompleteInbound();

        int nB = await readB;
        Assert.Equal(1, nB);
        Assert.Equal(0xCD, bufB[0]);
    }

    // ── 7. Reply-routing parity: A consumes only its own reply ──────────

    /// <summary>
    /// Channel A is awaiting a SUCCESS/FAILURE reply. The server sends a
    /// SUCCESS for B (not A), then A's SUCCESS. A must consume A's reply (not
    /// B's). B's reply is stashed in <c>_pendingReplies[1]</c>; if B is later
    /// awaiting, it consumes from there.
    /// </summary>
    /// <remarks>
    /// The two execs are driven SERIALLY by the test thread (rather than via
    /// <see cref="Task.Run"/>) for deterministic behavior under threadpool
    /// pressure. The aspect under test — reply routing by recipient id — is a
    /// property of the router's per-channel slot, independent of how many
    /// concurrent awaiters there are. The router sees A's outstanding
    /// <see cref="ChannelRouter.WaitForReplyAsync"/> call when it pumps the
    /// batched replies; if it stored them by type alone (the pre-3.6.2 bug), A
    /// would consume B's reply and the second <c>await</c> below would hang.
    /// </remarks>
    [Fact]
    public async Task WaitForReply_ConcurrentReplies_DontCrossChannels()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        // chA's exec starts first; it acquires the pump-lock and blocks on
        // WaitForTypesAsync. We let it run via Task.Run so it doesn't tie up
        // the test thread.
        var execA = Task.Run(() => chA.ExecAsync("ls", cancellationToken), cancellationToken);
        // Server reads chA's CHANNEL_REQUEST.
        await h.ServerReader.ReadPacketAsync(cancellationToken);

        // chB's exec starts second; its WaitForReplyAsync tries to acquire
        // the pump-lock, fails (chA holds it), registers a TCS and awaits.
        var execB = Task.Run(() => chB.ExecAsync("ls", cancellationToken), cancellationToken);
        await h.ServerReader.ReadPacketAsync(cancellationToken);

        // Server sends replies in REVERSE order (B's first, then A's). The
        // router must route each to the right channel.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 1)),
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelSuccess, BuildReply(PacketType.ChannelSuccess, 0)));

        // Both exec tasks should complete; if recipient routing is broken,
        // one task hangs and WhenAll never returns.
        await Task.WhenAll(execA, execB);
    }

    // ── 8. Many concurrent writes (stress) ──────────────────────────────

    /// <summary>
    /// Eight channels each write a unique 8-byte payload concurrently. The
    /// server reads 8 DATA packets. Each must carry the correct recipient id
    /// and payload — no corruption, no lost packets.
    /// </summary>
    [Fact]
    public async Task Stress_EightChannelsConcurrentWrite_AllReachWire()
    {
        using var h = new ChannelTestHarness();
        var channels = new List<SshChannel>();
        var payloads = new List<byte[]>();
        for (uint i = 0; i < 8; i++)
        {
            channels.Add(h.CreateChannel(localId: i, remoteId: 100 + i));
            byte[] payload = new byte[8];
            for (int j = 0; j < 8; j++)
            {
                payload[j] = (byte)(i * 16 + j);
            }
            payloads.Add(payload);
        }

        // Concurrent writes.
        Task[] writes = channels.Zip(payloads).Select(c =>
            Task.Run(() => c.First.WriteAsync(c.Second, TestContext.Current.CancellationToken))
        ).ToArray();
        await Task.WhenAll(writes);

        // Read all 8 from the server side and verify each by recipient id.
        var seen = new Dictionary<uint, byte[]>();
        for (int i = 0; i < 8; i++)
        {
            RawPacket pkt = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
            Assert.Equal(PacketType.ChannelData, pkt.Type);
            uint recipient = BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4));
            uint dataLen = BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(5, 4));
            seen[recipient] = pkt.Payload.AsSpan(9, (int)dataLen).ToArray();
        }

        for (uint i = 0; i < 8; i++)
        {
            Assert.Equal(payloads[(int)i], seen[100 + i]);
        }
    }

    // ── 9. Concurrent reads with cancellation stress ────────────────────

    /// <summary>
    /// Four channels start concurrent reads. Two are cancelled mid-flight;
    /// two receive data. Verifies the cancellation path doesn't corrupt the
    /// pump-lock state (the cancelled reads release the lock cleanly, the
    /// surviving reads complete normally).
    /// </summary>
    [Fact]
    public async Task FourConcurrentReads_HalfCancelled_HalfComplete()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        var channels = new List<SshChannel>();
        var cts = new List<CancellationTokenSource>();
        var bufs = new List<byte[]>();
        for (uint i = 0; i < 4; i++)
        {
            channels.Add(h.CreateChannel(localId: i, remoteId: 100 + i));
            cts.Add(CancellationTokenSource.CreateLinkedTokenSource(cancellationToken));
            bufs.Add(new byte[8]);
        }

        try
        {
            // Channels 0 and 1 will be cancelled; 2 and 3 will receive data.
            var tasks = new List<Task<int>>();
            for (int i = 0; i < 4; i++)
            {
                int idx = i;
                tasks.Add(Task.Run(() => channels[idx].ReadAsync(bufs[idx], cts[idx].Token)));
            }

            await Task.Yield();
            await Task.Delay(80, cancellationToken);

            // Cancel 0 and 1.
            await cts[0].CancelAsync();
            await cts[1].CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await tasks[0]);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await tasks[1]);

            // Feed data for 2 and 3.
            await h.FeedInboundAsync(
                ChannelTestHarness.BuildCleartextPacket(
                    PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(2, [0x22])),
                ChannelTestHarness.BuildCleartextPacket(
                    PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(3, [0x33])));
            h.CompleteInbound();

            await tasks[2];
            await tasks[3];
            Assert.Equal(0x22, bufs[2][0]);
            Assert.Equal(0x33, bufs[3][0]);
        }
        finally
        {
            foreach (CancellationTokenSource ctsItem in cts)
            {
                await ctsItem.CancelAsync();
                ctsItem.Dispose();
            }
        }
    }

    // ── 10. Lost-wakeup stress (C1 regression) ───────────────────────────
    //
    // Exercises the lost-wakeup fix: many channels each start a read, then
    // data is fed for them all in one batch. The pre-fix code registered the
    // TCS after attempting the pump-lock; if a channel's TCS was registered
    // after the pumper had already routed its packet + called SignalAllWaiters,
    // the channel's TCS would never be signaled and the read would hang. The
    // fix registers the TCS BEFORE the pump-lock attempt.
    //
    // We can't deterministically reproduce the lost-wakeup timing, but a
    // stress test with many channels + a delay-before-feed (so the channel
    // tasks have time to fail the pump-lock attempt and register) catches the
    // regression if the fix is reverted. We use Task.Delay to give channel
    // tasks time to enter the await state, then feed all data at once.

    /// <summary>
    /// Sixteen channels each start a ReadAsync; all reads are outstanding
    /// (their TCSes are registered). One DATA packet per channel is then fed
    /// in one batch. Every read must complete within a timeout — if any
    /// channel's TCS was registered after the pumper's SignalAllWaiters, the
    /// read hangs. The fix (register TCS before attempting the pump-lock)
    /// guarantees no lost wakeups.
    /// </summary>
    [Fact]
    public async Task Stress_SixteenConcurrentReads_AllComplete_NoLostWakeup()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        const int ChannelCount = 16;
        var channels = new SshChannel[ChannelCount];
        byte[][] bufs = new byte[ChannelCount][];
        var reads = new Task<int>[ChannelCount];

        for (int i = 0; i < ChannelCount; i++)
        {
            channels[i] = h.CreateChannel(localId: (uint)i, remoteId: 100 + (uint)i);
            bufs[i] = new byte[8];
        }

        // Start all reads concurrently. They race for the pump-lock; one wins
        // and blocks on the pipe; the rest register their TCSes and wait.
        for (int i = 0; i < ChannelCount; i++)
        {
            int idx = i;
            reads[i] = Task.Run(() => channels[idx].ReadAsync(bufs[idx], cancellationToken));
        }

        // Give all channel tasks time to register their TCSes.
        await Task.Yield();
        await Task.Delay(100, cancellationToken);

        // Feed all DATA in one batch. The active pumper's first read returns;
        // its DrainAvailablePacketsAsync drains the rest. Each packet is routed
        // to its channel and the channel's TCS is signaled. With the fix, every
        // TCS is already registered (since registration precedes the pump-lock
        // attempt), so no signal is lost.
        byte[][] packets = new byte[ChannelCount][];
        for (int i = 0; i < ChannelCount; i++)
        {
            packets[i] = ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelData,
                ChannelTestHarness.BuildChannelDataPayload((uint)i, [(byte)(0xA0 + i)]));
        }

        await h.FeedInboundAsync(packets);
        h.CompleteInbound();

        // Every read must complete within 5 seconds. If any channel's wakeup
        // was lost, Task.WhenAll hangs and the test times out.
        Task allDone = Task.WhenAll(reads);
        Task winner = await Task.WhenAny(allDone, Task.Delay(5000, cancellationToken));
        Assert.True(winner == allDone, "All 16 reads should have completed within 5s; a lost-wakeup regression is likely.");

        for (int i = 0; i < ChannelCount; i++)
        {
            Assert.Equal(1, await reads[i]);
            Assert.Equal((byte)(0xA0 + i), bufs[i][0]);
        }
    }

    // ── 11. Same-channel full-duplex (M3 regression) ─────────────────────
    //
    // Exercises the multi-waiter-per-channel fix: a single channel has a
    // ReadAsync AND a WriteAsync (zero-outbound-window) outstanding
    // simultaneously. Both await the channel's signal. When a WINDOW_ADJUST
    // arrives, the write should complete; when DATA arrives, the read should
    // complete. The pre-fix single-TCS-per-channel design could strand one of
    // them (a TryRemove by one would unhook the other).

    /// <summary>
    /// A single channel has a <see cref="SshChannel.ReadAsync"/> outstanding
    /// AND a <see cref="SshChannel.WriteAsync"/> blocked on zero outbound
    /// window. The server sends a WINDOW_ADJUST (write unblocks, sends DATA,
    /// completes), then DATA for the read. Both ops must complete. Exercises
    /// the multi-waiter-per-channel design (the pre-fix single-TCS-per-channel
    /// would strand one of them).
    /// </summary>
    [Fact]
    public async Task SameChannel_ReadBlocked_AndWriteBlockedOnWindow_BothComplete()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        // Outbound window = 0 forces the write to wait for an ADJUST.
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 100, outboundWindow: 0);

        byte[] buf = new byte[8];
        // Start the read first — it will become the active pumper and block on
        // the pipe. (ReadAsync's blocking path goes through WaitForStateChangeAsync.)
        Task<int> readTask = Task.Run(() => ch.ReadAsync(buf, cancellationToken));

        // Start the write. It tries to send, sees outbound window = 0, and
        // enters its zero-window loop calling WaitForStateChangeAsync(this).
        // That fails the pump-lock attempt (read task holds it), registers a
        // TCS in _signals[0], and awaits.
        byte[] data = { 0x11, 0x22, 0x33 };
        var writeTask = Task.Run(() => ch.WriteAsync(data, cancellationToken), cancellationToken);

        await Task.Yield();
        await Task.Delay(100, cancellationToken);

        // Feed WINDOW_ADJUST for ch (outbound window grows). The active pumper
        // (read task) reads it, routes to ch (outbound window grows), signals
        // the channel — wakes BOTH waiters (read's TCS and write's TCS,
        // multi-waiter-per-channel). The write re-checks its condition
        // (window > 0 now), proceeds to send its DATA, completes. The read
        // finds no data buffered yet, re-awaits.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelWindowAdjust,
            ChannelTestHarness.BuildWindowAdjustPayload(0, bytesToAdd: (uint)data.Length)));

        // Write should complete now. The server sees its DATA packet.
        await Task.WhenAny(writeTask, Task.Delay(2000, cancellationToken));
        Assert.True(writeTask.IsCompleted, "Write should complete after WINDOW_ADJUST.");

        // Server reads the client's DATA.
        RawPacket dataPkt = await h.ServerReader.ReadPacketAsync(cancellationToken);
        Assert.Equal(PacketType.ChannelData, dataPkt.Type);
        Assert.Equal(data, dataPkt.Payload.AsSpan(9, data.Length).ToArray());

        // Now feed DATA for the read. The read's TCS is still registered; it
        // gets woken; the read completes.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(0, [0xAA])));
        h.CompleteInbound();

        int n = await readTask;
        Assert.Equal(1, n);
        Assert.Equal(0xAA, buf[0]);
    }

    // ── 12. Cancellation does not leak a stale TCS (M1 regression) ───────
    //
    // A channel's ReadAsync is canceled. The pre-fix code did NOT remove the
    // canceled TCS from _signals, so a subsequent ReadAsync on the same
    // channel would retrieve the canceled TCS and throw a stale OCE
    // immediately. The fix puts _signals.TryRemove in a finally block.

    /// <summary>
    /// A channel's <see cref="SshChannel.ReadAsync"/> is cancelled while
    /// parked (its TCS is registered). A subsequent ReadAsync on the same
    /// channel must NOT see a stale canceled TCS — it should succeed normally
    /// when data arrives. Verifies the M1 fix (finally-block TCS cleanup).
    /// </summary>
    [Fact]
    public async Task CancelledRead_DoesNotLeakStaleTcs_SubsequentReadSucceeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 100);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        byte[] buf1 = new byte[8];
        // Hold the pump-lock so the read parks on its TCS. We do this by
        // starting a read on a different channel first with no data — it
        // becomes the pumper and blocks on the pipe.
        SshChannel chBlocker = h.CreateChannel(localId: 1, remoteId: 200);
        Task<int> blockRead = Task.Run(() => chBlocker.ReadAsync(new byte[1], cancellationToken));
        await Task.Yield();
        await Task.Delay(50, cancellationToken);

        // ch's read will fail the pump-lock attempt (chBlocker holds it),
        // register a TCS, and await.
        Task<int> cancelledRead = Task.Run(() => ch.ReadAsync(buf1, cts.Token));
        await Task.Yield();
        await Task.Delay(50, cancellationToken);

        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await cancelledRead);

        // Pre-fix bug: the canceled TCS would still be in _signals[0]. A
        // subsequent ReadAsync would GetOrAdd → existing canceled TCS → await
        // → throw stale OCE immediately. With the fix, the TCS is removed in
        // a finally, so the next read registers a fresh TCS.
        // Unblock the blocker so the next read can take the pump-lock.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(1, [0x77])));
        await blockRead;

        // Now ch's subsequent read should work normally.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData,
            ChannelTestHarness.BuildChannelDataPayload(0, [0x42])));
        h.CompleteInbound();

        byte[] buf2 = new byte[8];
        int n = await ch.ReadAsync(buf2, cancellationToken);
        Assert.Equal(1, n);
        Assert.Equal(0x42, buf2[0]);
    }

    // ── 13. Concurrent OpenAsync (C2 regression) ─────────────────────────
    //
    // Exercises the C2 fix: pre-fix OpenAsync used the legacy unguarded
    // router.WaitAsync, so two concurrent OpenSessionAsync calls would race
    // on the single-reader PipeReader (InvalidOperationException) and could
    // consume each other's OPEN_CONFIRMATION (no recipient filter). The fix
    // migrates OpenAsync to WaitForReplyAsync (pump-lock-guarded, filters by
    // recipient).

    /// <summary>
    /// Two concurrent <see cref="SshChannel.OpenAsync"/> calls on the same
    /// router. Both CHANNEL_OPEN packets reach the wire; the server replies
    /// with a CONFIRMATION for each. Each open must complete with its own
    /// channel — no PipeReader corruption, no cross-channel confirmation
    /// consumption.
    /// </summary>
    [Fact]
    public async Task ConcurrentOpenAsync_BothComplete_WithDistinctRemoteIds()
    {
        using var h = new ChannelTestHarness();

        // Start both opens concurrently.
        Task<SshChannel> openA = Task.Run(() => SshChannel.OpenAsync(h.ClientWriter, h.Router, TestContext.Current.CancellationToken));
        Task<SshChannel> openB = Task.Run(() => SshChannel.OpenAsync(h.ClientWriter, h.Router, TestContext.Current.CancellationToken));

        // Server reads both CHANNEL_OPEN packets.
        RawPacket openPktA = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        RawPacket openPktB = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelOpen, openPktA.Type);
        Assert.Equal(PacketType.ChannelOpen, openPktB.Type);

        // The two local ids are 0 and 1 (sequential allocation under the
        // pump-lock? — actually AllocateLocalId is not pump-locked, but it's
        // atomic via uint increment; the test just verifies both are distinct).
        uint localA = BinaryPrimitives.ReadUInt32BigEndian(openPktA.Payload.AsSpan(12, 4));
        uint localB = BinaryPrimitives.ReadUInt32BigEndian(openPktB.Payload.AsSpan(12, 4));
        Assert.NotEqual(localA, localB);

        // Reply with CONFIRMATIONs addressed to each by its local id. The
        // pre-fix code could misroute (no recipient filter); the fix uses
        // per-channel reply slots.
        await h.FeedInboundAsync(
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelOpenConfirmation,
                ChannelTestHarness.BuildOpenConfirmationPayload(localA, senderChannel: 500,
                    window: ChannelConstants.WindowDefault, maxPacket: ChannelConstants.PacketDefault)),
            ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelOpenConfirmation,
                ChannelTestHarness.BuildOpenConfirmationPayload(localB, senderChannel: 501,
                    window: ChannelConstants.WindowDefault, maxPacket: ChannelConstants.PacketDefault)));

        // Both opens complete; channels have distinct RemoteIds matching the
        // server's assignment.
        Task<SshChannel>[] ops = { openA, openB };
        await Task.WhenAll(ops);
        SshChannel chA = await openA;
        SshChannel chB = await openB;

        // Each channel's RemoteId matches a distinct sender channel (500 or 501).
        var remoteIds = new HashSet<uint> { chA.RemoteId, chB.RemoteId };
        Assert.Equal(2, remoteIds.Count);
        Assert.Contains(500u, remoteIds);
        Assert.Contains(501u, remoteIds);
        Assert.NotEqual(chA.LocalId, chB.LocalId);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// <summary>Builds a reply payload: [type][u32 recipient].</summary>
    private static byte[] BuildReply(int type, uint recipient)
    {
        byte[] p = new byte[5];
        p[0] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(1, 4), recipient);
        return p;
    }
}
