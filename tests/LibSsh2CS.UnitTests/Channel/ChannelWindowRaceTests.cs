using System.Buffers.Binary;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Regression tests: the per-channel window /
/// read-avail counters (<c>_readAvail</c>, <c>_inboundWindow</c>,
/// <c>_outboundWindow</c>) and the stdout/stderr FIFOs are read-modify-written
/// by two genuinely concurrent tasks — the cooperative pumper (routing inbound
/// packets) and the channel's own read/write continuations (which resume on
/// their own task after a signal). Pre-fix, the plain fields lose updates:
/// a lost <c>WINDOW_ADJUST</c> increment hangs <see cref="SshChannel.WriteAsync"/>
/// forever; a lost decrement over-sends past the peer's granted window; stale
/// reads produce wrong truncation and wrong adjust amounts; two concurrent
/// readers double-adjust.
/// </summary>
/// <remarks>
/// <para>
/// Every test forces the racing configuration: channel B's blocked
/// <see cref="SshChannel.ReadAsync"/> becomes the active pumper (it holds the
/// pump lock parked inside the pipe read), so all inbound routing for channel
/// A happens on B's task while A's reader/writer continuations run
/// concurrently on their own tasks — exactly the interleaving the C reference
/// (single-threaded) never sees.
/// </para>
/// <para>
/// All completion waits are timeout-guarded: the primary pre-fix failure mode
/// is a permanent hang (lost adjust increment / lost signal), which must fail
/// the test rather than stall the run.
/// </para>
/// </remarks>
public class ChannelWindowRaceTests
{
    // ── 1. Pumper-delivery vs concurrent reader (inbound books) ────────────

    /// <summary>
    /// One reader drains a 256 KiB batch (1024 × 256 B DATA packets fed in one
    /// pipe write) while the pumper task (channel B's blocked read) routes the
    /// batch. Pre-fix, the pumper's <c>_readAvail +=</c> races the reader's
    /// <c>_readAvail -=</c> / <c>_inboundWindow -=</c> and the FIFO
    /// Enqueue/Dequeue pair: a lost update leaves
    /// <see cref="SshChannel.ReadAvail"/> non-zero (or uint-underflowed) at
    /// the end, and a torn FIFO corrupts the byte stream. Post-fix every
    /// read-modify-write is atomic under the per-channel window lock.
    /// </summary>
    /// <remarks>
    /// The 2 MiB default inbound window never crosses the adjust threshold
    /// (2 MiB − 256 KiB = 1.75 MiB &gt; 1.5 MiB + 1 KiB), so no
    /// <c>WINDOW_ADJUST</c> interferes — this isolates the delivery-vs-read
    /// race. The final window must be exactly
    /// <c>WindowDefault − TotalBytes</c>.
    /// </remarks>
    [Fact]
    public async Task Stress_DeliverWhileConcurrentRead_BooksStayConsistent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        const int PacketCount = 1024;
        const int PacketSize = 256;
        const int TotalBytes = PacketCount * PacketSize;

        // Expected stream: packet i is filled with (byte)(i & 0xFF).
        byte[] expected = new byte[TotalBytes];
        for (int i = 0; i < PacketCount; i++)
        {
            expected.AsSpan(i * PacketSize, PacketSize).Fill((byte)(i & 0xFF));
        }

        // Build the whole wire batch up front (one pipe write → one large
        // drain cycle on the pumper).
        byte[][] packets = new byte[PacketCount][];
        for (int i = 0; i < PacketCount; i++)
        {
            byte[] body = new byte[PacketSize];
            Array.Fill(body, (byte)(i & 0xFF));
            packets[i] = ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, body));
        }

        int batchLength = packets.Sum(p => p.Length);
        byte[] batch = new byte[batchLength];
        int offset = 0;
        foreach (byte[] pkt in packets)
        {
            Buffer.BlockCopy(pkt, 0, batch, offset, pkt.Length);
            offset += pkt.Length;
        }

        // B's blocked read becomes the active pumper and parks on the pipe.
        byte[] bufB = new byte[8];
        Task<int> readB = Task.Run(() => chB.ReadAsync(bufB, ct), ct);
        await Task.Delay(100, ct);

        // A's reader drains on its own task; the pumper routes the batch
        // concurrently — the channel window race.
        var sink = new MemoryStream();
        var readTask = Task.Run(async () =>
        {
            byte[] buf = new byte[1024];
            int got = 0;
            while (got < TotalBytes)
            {
                int n = await chA.ReadAsync(buf, ct);
                if (n == 0)
                {
                    throw new InvalidOperationException(
                        $"Channel EOF/close before all {TotalBytes} bytes arrived (got {got}).");
                }

                await sink.WriteAsync(buf.AsMemory(0, n), ct);
                got += n;
            }
        }, ct);

        await Task.Delay(100, ct);
        await h.ServerWriter.WriteAsync(batch, ct);

        Task finished = await Task.WhenAny(readTask, Task.Delay(15000, ct));
        Assert.True(readTask.IsCompleted, "Reader hung — lost wakeup or stuck books (H-1).");
        await readTask;

        // Books + integrity.
        Assert.Equal(TotalBytes, (int)sink.Length);
        Assert.Equal(expected, sink.ToArray());
        Assert.Equal(0u, chA.ReadAvail);
        Assert.Equal(ChannelConstants.WindowDefault - (uint)TotalBytes, chA.InboundWindow);

        // Release the pumper: feed B's data, then complete inbound.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(1, [0xBB])));
        h.CompleteInbound();
        await WithTimeoutAsync(readB, TimeSpan.FromSeconds(15), "pumper (B) never released", ct);
        Assert.Equal(1, await readB);
    }

    // ── 2. Pumper-routed WINDOW_ADJUST vs concurrent writer (outbound books) ──

    /// <summary>
    /// An 8 MiB <see cref="SshChannel.WriteAsync"/> through a 512-byte
    /// outbound window / 256-byte max packet (32768 chunks, 32766+ adjust
    /// round-trips). The mock server refunds each chunk with a
    /// <c>WINDOW_ADJUST</c> routed by the pumper task (B's blocked read) while
    /// the writer continues on its own task. Pre-fix, the pumper's
    /// <c>_outboundWindow +=</c> races the writer's
    /// <c>_outboundWindow -=</c>: a lost increment strands the writer spinning
    /// in <c>while (_outboundWindow == 0)</c> forever (test fails on the
    /// timeout guard); a lost decrement over-credits the window (final value
    /// above the legitimate leftover range) and lets the writer exceed the
    /// granted credit.
    /// </summary>
    /// <remarks>
    /// Adjust accounting: initial window 512 covers chunks 1–2; each later
    /// chunk needs one consumed 256-byte adjust; the server feeds at most one
    /// trailing adjust beyond the writer's need — so the legitimate final
    /// window is 0 or 256. Values above that indicate lost decrements.
    /// </remarks>
    [Fact]
    public async Task Stress_WriteWithConcurrentAdjusts_CompletesAndBooksStayExact()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(
            localId: 0, remoteId: 100, outboundWindow: 512, outboundMaxPacket: 256);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        const int ChunkSize = 256;
        const int TotalBytes = 8 * 1024 * 1024;   // 32768 chunks — enough rounds that the
                                                  // pre-fix RMW overlap (a few ns per
                                                  // round) is hit with near-certainty

        byte[] data = new byte[TotalBytes];
        for (int i = 0; i < TotalBytes; i++)
        {
            data[i] = (byte)(i & 0xFF);
        }

        // B's blocked read = the pumper routing adjusts while the writer races.
        byte[] bufB = new byte[8];
        Task<int> readB = Task.Run(() => chB.ReadAsync(bufB, ct), ct);
        await Task.Delay(100, ct);

        // The writer on its own task.
        var writeTask = Task.Run(() => chA.WriteAsync(data, ct), ct);

        // Mock server: read every DATA chunk (verify order + content), refund
        // one 256-byte adjust per chunk except after the final one.
        var serverTask = Task.Run(async () =>
        {
            int got = 0;
            while (got < TotalBytes)
            {
                RawPacket pkt = await h.ServerReader.ReadPacketAsync(ct);
                Assert.Equal(PacketType.ChannelData, pkt.Type);
                Assert.Equal(100u, BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4)));
                Assert.Equal((uint)ChunkSize,
                    BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(5, 4)));
                Assert.Equal(
                    data.AsSpan(got, ChunkSize).ToArray(),
                    pkt.Payload.AsSpan(9, ChunkSize).ToArray());
                got += ChunkSize;

                if (got < TotalBytes)
                {
                    await h.ServerWriter.WriteAsync(ChannelTestHarness.BuildCleartextPacket(
                        PacketType.ChannelWindowAdjust,
                        ChannelTestHarness.BuildWindowAdjustPayload(0, ChunkSize)), ct);
                }
            }
        }, ct);

        Task finished = await Task.WhenAny(writeTask, Task.Delay(30000, ct));
        Assert.True(writeTask.IsCompleted,
            $"Write hung — lost WINDOW_ADJUST increment (H-1); window={chA.OutboundWindow}.");
        await writeTask;
        await WithTimeoutAsync(serverTask, TimeSpan.FromSeconds(15), "mock server stalled", ct);

        // Books: 0 or 256 (at most one unconsumed trailing adjust). Anything
        // higher = lost decrements (over-sent past the granted window).
        Assert.True(chA.OutboundWindow is <= 256u,
            $"Outbound window books drifted: {chA.OutboundWindow} (legitimate range 0–256).");

        // Release the pumper.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(1, [0xBB])));
        h.CompleteInbound();
        await WithTimeoutAsync(readB, TimeSpan.FromSeconds(15), "pumper (B) never released", ct);
        Assert.Equal(1, await readB);
    }

    // ── 3. Two concurrent readers on one channel (inbound books + adjusts) ──

    /// <summary>
    /// Two concurrent readers drain 64 KiB (32 waves × 4 × 512 B) through a
    /// small 8 KiB inbound window, so <c>EnsureInboundWindowAsync</c> fires
    /// constantly and the readers' <c>_readAvail -=</c> /
    /// <c>_inboundWindow -=</c> race each other, the pumper's
    /// <c>_readAvail +=</c>, and their own <c>_inboundWindow += adjust</c>
    /// applications. The feeder is credit-gated (next wave only when the
    /// window covers it and the previous wave is fully drained) so the mock
    /// server never over-sends — any truncation/drop means broken books.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Termination: after the last wave drains, the server feeds
    /// <c>CHANNEL_EOF</c>; both readers drain their remainder and return 0.
    /// </para>
    /// <para>
    /// Accounting check: an adjust-counter task tallies every
    /// <c>WINDOW_ADJUST</c> the client sent. The books balance exactly when
    /// <c>InboundWindow == InitialWindow + Σadjust − TotalBytes</c>; the test
    /// polls until that holds (the counter task drains the final adjusts
    /// asynchronously). Pre-fix lost updates (between the readers, or reader
    /// vs pumper) make the equality unreachable and the test fails on the
    /// timeout.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Stress_TwoConcurrentReaders_AdjustAccountingStaysConsistent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel chA = h.CreateChannel(localId: 0, remoteId: 100, inboundWindow: 8192);
        SshChannel chB = h.CreateChannel(localId: 1, remoteId: 200);

        const int WaveCount = 32;
        const int PacketsPerWave = 4;
        const int PacketSize = 512;
        const int WaveBytes = PacketsPerWave * PacketSize;
        const int TotalBytes = WaveCount * WaveBytes;
        const uint InitialWindow = 8192;

        long totalRead = 0;

        // B's blocked read = the pumper.
        byte[] bufB = new byte[8];
        Task<int> readB = Task.Run(() => chB.ReadAsync(bufB, ct), ct);
        await Task.Delay(100, ct);

        // Two concurrent readers on the SAME channel; small buffers force
        // frequent EnsureInboundWindowAsync adjusts.
        var sinks = new MemoryStream[2];
        sinks[0] = new MemoryStream();
        sinks[1] = new MemoryStream();
        Task[] readers =
        [
            Task.Run(async () => await DrainUntilEofAsync(chA, sinks[0], 256, AddTotal, ct), ct),
            Task.Run(async () => await DrainUntilEofAsync(chA, sinks[1], 256, AddTotal, ct), ct),
        ];

        long AddTotal(int n) => Interlocked.Add(ref totalRead, n);

        // Adjust counter: tallies every WINDOW_ADJUST on the wire until cancelled.
        long adjustBytes = 0;
        using var counterCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var counterTask = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    RawPacket pkt = await h.ServerReader.ReadPacketAsync(counterCts.Token);
                    if (pkt.Type == PacketType.ChannelWindowAdjust)
                    {
                        _ = Interlocked.Add(ref adjustBytes,
                            BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(5, 4)));
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal termination.
            }
        }, ct);

        // Credit-gated wave feeder.
        try
        {
            for (int w = 0; w < WaveCount; w++)
            {
                await WaitUntilAsync(
                    () => Volatile.Read(ref totalRead) == (long)w * WaveBytes
                        && chA.InboundWindow >= WaveBytes,
                    TimeSpan.FromSeconds(15),
                    $"wave {w} never became feedable (drained={Volatile.Read(ref totalRead)}, window={chA.InboundWindow})",
                    ct);

                byte[][] wavePackets = new byte[PacketsPerWave][];
                for (int p = 0; p < PacketsPerWave; p++)
                {
                    byte[] body = new byte[PacketSize];
                    Array.Fill(body, (byte)(w & 0xFF));
                    wavePackets[p] = ChannelTestHarness.BuildCleartextPacket(
                        PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(0, body));
                }

                int waveLength = wavePackets.Sum(p => p.Length);
                byte[] wire = new byte[waveLength];
                int off = 0;
                foreach (byte[] pkt in wavePackets)
                {
                    Buffer.BlockCopy(pkt, 0, wire, off, pkt.Length);
                    off += pkt.Length;
                }

                await h.ServerWriter.WriteAsync(wire, ct);
            }

            // All bytes must arrive.
            await WaitUntilAsync(
                () => Volatile.Read(ref totalRead) == TotalBytes,
                TimeSpan.FromSeconds(15),
                $"not all bytes drained ({Volatile.Read(ref totalRead)}/{TotalBytes})",
                ct);

            // EOF terminates both readers.
            await h.ServerWriter.WriteAsync(ChannelTestHarness.BuildCleartextPacket(
                PacketType.ChannelEof, ChannelTestHarness.BuildEofPayload(0)), ct);
            await WithTimeoutAsync(
                Task.WhenAll(readers), TimeSpan.FromSeconds(15),
                "readers did not terminate after EOF", ct);

            // Books must balance once the counter task has tallied every
            // adjust (no new ones can appear after the readers finished).
            await WaitUntilAsync(
                () => (long)chA.InboundWindow == (long)InitialWindow + Interlocked.Read(ref adjustBytes) - TotalBytes,
                TimeSpan.FromSeconds(15),
                $"books never balanced: window={chA.InboundWindow}, Σadjust={Interlocked.Read(ref adjustBytes)}",
                ct);
            Assert.Equal(0u, chA.ReadAvail);
            Assert.Equal(TotalBytes, (int)(sinks[0].Length + sinks[1].Length));

            // Integrity: every wave's 2048 pattern bytes present across the two sinks.
            byte[] all = new byte[TotalBytes];
            sinks[0].ToArray().CopyTo(all, 0);
            sinks[1].ToArray().CopyTo(all, (int)sinks[0].Length);
            int[] histogram = new int[256];
            foreach (byte b in all)
            {
                histogram[b]++;
            }

            for (int w = 0; w < WaveCount; w++)
            {
                Assert.Equal(WaveBytes, histogram[w & 0xFF]);
            }
        }
        finally
        {
            await counterCts.CancelAsync();
            await counterTask;
        }

        // Release the pumper.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelData, ChannelTestHarness.BuildChannelDataPayload(1, [0xBB])));
        h.CompleteInbound();
        await WithTimeoutAsync(readB, TimeSpan.FromSeconds(15), "pumper (B) never released", ct);
        Assert.Equal(1, await readB);
    }

    // ── 4. Deterministic: send failure must not eat the reserved window ────

    /// <summary>
    /// The outbound pipe is completed up front so the first
    /// <see cref="SshChannel.WriteAsync"/> send throws. The outbound window
    /// must be left exactly at its initial value. Pre-fix this holds trivially
    /// (the decrement followed the send); post-fix the chunk is reserved
    /// BEFORE the send, so this test guards the reserve/rollback pairing
    /// introduced by the channel window synchronization fix.
    /// </summary>
    [Fact]
    public async Task WriteAsync_SendFailure_LeavesOutboundWindowIntact()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        SshChannel ch = h.CreateChannel(localId: 0, remoteId: 100, outboundWindow: 1000);

        h.CompleteOutbound();

        byte[] data = new byte[10];
        await Assert.ThrowsAnyAsync<Exception>(() => ch.WriteAsync(data, ct));

        Assert.Equal(1000u, ch.OutboundWindow);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Drains stdout into <paramref name="sink"/> in
    /// <paramref name="bufferSize"/> reads until the channel reports EOF
    /// (returns 0), reporting each byte count via <paramref name="onBytes"/>.
    /// </summary>
    private static async Task DrainUntilEofAsync(
        SshChannel channel, MemoryStream sink, int bufferSize, Func<int, long> onBytes, CancellationToken ct)
    {
        byte[] buf = new byte[bufferSize];
        while (true)
        {
            int n = await channel.ReadAsync(buf, ct);
            if (n == 0)
            {
                return;
            }

            await sink.WriteAsync(buf.AsMemory(0, n), ct);
            _ = onBytes(n);
        }
    }

    /// <summary>
    /// Awaits <paramref name="task"/> but no longer than <paramref name="timeout"/>;
    /// a stall fails the test with <paramref name="message"/> instead of hanging
    /// the run (the pre-fix failure mode of every channel window race is a permanent hang).
    /// </summary>
    private static async Task WithTimeoutAsync(
        Task task, TimeSpan timeout, string message, CancellationToken ct)
    {
        Task finished = await Task.WhenAny(task, Task.Delay(timeout, ct));
        if (finished != task)
        {
            Assert.Fail($"Timeout: {message}");
        }

        await task;
    }

    /// <summary>
    /// Polls <paramref name="condition"/> every 10 ms until it holds or
    /// <paramref name="timeout"/> elapses (then fails with
    /// <paramref name="message"/>).
    /// </summary>
    private static async Task WaitUntilAsync(
        Func<bool> condition, TimeSpan timeout, string message, CancellationToken ct)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail($"Timeout: {message}");
            }

            await Task.Delay(10, ct);
        }
    }
}
