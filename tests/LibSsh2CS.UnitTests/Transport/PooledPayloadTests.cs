using System.Buffers;
using System.IO.Pipelines;

using LibSsh2CS.Transport;
using LibSsh2CS.UnitTests.Channel;

namespace LibSsh2CS.UnitTests.Transport;

public class PooledPayloadTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public static IEnumerable<object[]> Frames()
    {
        foreach (string mode in new[] { "clear", "ctr", "etm", "gcm", "chacha" })
        {
            foreach (int type in new[] { PacketType.ChannelData, PacketType.ChannelExtendedData, PacketType.Ignore })
            {
                yield return [mode, type, false];
                if (mode != "clear")
                {
                    yield return [mode, type, true];
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Frames))]
    public async Task Extraction_BoundsBytesAndOwnership(string mode, int type, bool compressed)
    {
        var pool = new TrackingPayloadPool();
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader, pool);
        await using var writer = new PacketWriter(pipe.Writer);
        if (mode != "clear")
        {
            string cipherName = mode switch
            {
                "gcm" => "aes256-gcm@openssh.com",
                "chacha" => "chacha20-poly1305@openssh.com",
                _ => "aes256-ctr",
            };
            ICipher decrypt = CipherMethods.Create(cipherName)!;
            ICipher encrypt = CipherMethods.Create(cipherName)!;
            decrypt.Init(new byte[decrypt.KeyLen], new byte[decrypt.IvLen], false);
            encrypt.Init(new byte[encrypt.KeyLen], new byte[encrypt.IvLen], true);
            IMac readMac = MacMethods.Noop;
            IMac writeMac = MacMethods.Noop;
            if (!CipherMethods.IsAead(decrypt))
            {
                string macName = mode == "etm" ? "hmac-sha2-256-etm@openssh.com" : "hmac-sha2-256";
                readMac = MacMethods.Create(macName)!;
                writeMac = MacMethods.Create(macName)!;
                readMac.Init(new byte[readMac.MacLen]);
                writeMac.Init(new byte[writeMac.MacLen]);
            }
            ICompression readCompression = CompressionMethods.Create(compressed ? "zlib" : "none")!;
            ICompression writeCompression = CompressionMethods.Create(compressed ? "zlib" : "none")!;
            readCompression.Init(false);
            writeCompression.Init(true);
            reader.SetInboundKeys(decrypt, readMac, readCompression, false, true);
            await writer.SetOutboundKeysAsync(encrypt, writeMac, writeCompression, false, true, Token);
        }

        byte[] expected = Enumerable.Repeat((byte)0x5a, 4096).ToArray();
        expected[0] = (byte)type;
        await writer.WritePacketAsync(type, expected, Token);
        RawPacket packet = await reader.ReadPacketAsync(Token);
        Assert.True(packet.HasPacket);
        Assert.Equal(expected, packet.Payload.ToArray());
        bool pooled = type != PacketType.Ignore;
        Assert.Equal(pooled ? 1 : 0, pool.Outstanding);
        RawPacket copy = packet;
        packet.Dispose();
        copy.Dispose();
        Assert.Equal(pooled ? 1 : 0, pool.Returns);
        Assert.Equal(0, pool.Outstanding);
        // The pool immediately reuses returned storage; the next packet must remain exact.
        expected[10] = 42;
        await writer.WritePacketAsync(type, expected, Token);
        using RawPacket next = await reader.ReadPacketAsync(Token);
        Assert.Equal(expected, next.Payload.ToArray());
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task PartialReads_RetainLeaseThroughEofAndClose(bool stderr, bool merge)
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        if (merge)
        {
            await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, Token);
        }
        byte[] expected = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();
        byte[] payload = stderr
            ? ChannelTestHarness.BuildChannelExtendedDataPayload(channel.LocalId, 1, expected)
            : ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, expected);
        await h.FeedInboundAsync(Frame(payload), Frame(ChannelTestHarness.BuildEofPayload(channel.LocalId)),
            Frame(ChannelTestHarness.BuildClosePayload(channel.LocalId)));
        await h.Router.PumpOneBatchForTestAsync(Token);
        Assert.Equal(1, pool.Outstanding);
        byte[] output = new byte[40];
        int first = stderr && !merge
            ? await channel.ReadStderrAsync(output.AsMemory(0, 7), Token)
            : await channel.ReadAsync(output.AsMemory(0, 7), Token);
        Assert.Equal(7, first);
        Assert.Equal(0, pool.Returns);
        int rest = stderr && !merge
            ? await channel.ReadStderrAsync(output.AsMemory(7), Token)
            : await channel.ReadAsync(output.AsMemory(7), Token);
        Assert.Equal(33, rest);
        Assert.Equal(expected, output);
        Assert.Equal(0, pool.Outstanding);
        await channel.DisposeAsync();
        await channel.DisposeAsync();
        Assert.Equal(1, pool.Returns);
    }

    [Theory]
    [InlineData(0, 20, 20)] // unknown channel
    [InlineData(1, 0, 20)] // full window
    [InlineData(1, 10, 4)] // packet and window truncation
    public async Task DropsAndTruncation_ClearWholePayload(int registered, uint window, uint packetLimit)
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel(register: registered != 0, inboundWindow: window, inboundMaxPacket: packetLimit);
        await h.FeedInboundAsync(Frame(ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, new byte[20])));
        await h.Router.PumpOneBatchForTestAsync(Token);
        if (registered != 0 && window > 0)
        {
            Assert.Equal(1, pool.Outstanding);
            byte[] output = new byte[20];
            Assert.Equal(4, await channel.ReadAsync(output, Token));
        }
        Assert.Equal(0, pool.Outstanding);
        Assert.Equal(1, pool.Returns);
    }

    [Fact]
    public async Task IgnoreFlush_ReleasesUnreadSegmentsAndFuturePackets()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        byte[] payload = ChannelTestHarness.BuildChannelExtendedDataPayload(channel.LocalId, 1, new byte[20]);
        await h.FeedInboundAsync(Frame(payload), Frame(payload));
        await h.Router.PumpOneBatchForTestAsync(Token);
        byte[] snapshot = channel.PeekStderr()[0];
        Assert.Equal(3, await channel.ReadStderrAsync(new byte[3], Token));
        Assert.Equal(2, pool.Outstanding);
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, Token);
        Assert.Equal(0, pool.Outstanding);
        await h.FeedInboundAsync(Frame(payload));
        await h.Router.PumpOneBatchForTestAsync(Token);
        Assert.Equal(3, pool.Returns);
        Assert.Equal(new byte[20], snapshot);
    }

    [Fact]
    public async Task Stash_CancellationAndRekeyPreserveOwnershipUntilCleanup()
    {
        var pool = new TrackingPayloadPool();
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader, pool);
        using var queue = new PacketQueue(reader) { InitialKex = false, ReadTimeout = TimeSpan.Zero };
        await pipe.Writer.WriteAsync(Frame(ChannelTestHarness.BuildChannelDataPayload(0, new byte[20])), Token);
        using var canceled = CancellationTokenSource.CreateLinkedTokenSource(Token);
        Task<RawPacket> pending = queue.WaitForTypeAsync(PacketType.KexInit, canceled.Token).AsTask();
        Assert.Equal(1, pool.Outstanding);
        await canceled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.Equal(1, pool.Outstanding);
        queue.RekeyTriggerAsync = async ct =>
        {
            using RawPacket kex = await queue.WaitForTypeAsync(PacketType.KexInit, ct);
            Assert.Equal(1, pool.Outstanding);
        };
        await pipe.Writer.WriteAsync(Frame([(byte)PacketType.KexInit]), Token);
        Assert.False((await queue.TryTakeAvailableAsync(Token)).HasPacket);
        queue.Dispose();
        queue.Dispose();
        Assert.Equal(0, pool.Outstanding);
        Assert.False(queue.TryTakeStashed(PacketType.ChannelData, out _));
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task StrictKexFailureAndMalformedRouting_ReturnRentals()
    {
        var pool = new TrackingPayloadPool();
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader, pool);
        using var queue = new PacketQueue(reader) { StrictKex = true };
        await pipe.Writer.WriteAsync(Frame([(byte)PacketType.ChannelData]), Token);
        await Assert.ThrowsAsync<SshException>(async () => await queue.WaitForTypeAsync(PacketType.NewKeys, Token));
        Assert.Equal(0, pool.Outstanding);
        using var h = new ChannelTestHarness(pool);
        await h.FeedInboundAsync(Frame([(byte)PacketType.ChannelExtendedData]));
        await h.Router.PumpOneBatchForTestAsync(Token);
        Assert.Equal(0, pool.Outstanding);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task RouterTeardown_DrainsUnreadAndRejectsLateDelivery()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        byte[] payload = ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, new byte[20]);
        await h.FeedInboundAsync(Frame(payload));
        await h.Router.PumpOneBatchForTestAsync(Token);
        Assert.Equal(1, pool.Outstanding);
        h.Router.Dispose();
        h.Router.Dispose();
        Assert.Equal(0, pool.Outstanding);
        Assert.False(channel.DeliverDataPayload(payload, false));
        Assert.Throws<ObjectDisposedException>(() => h.Router.Register(channel));
    }

    [Fact]
    public async Task FailedHandshake_DrainsStashedDataAndLeavesTransportOpen()
    {
        var pool = new TrackingPayloadPool();
        var inbound = new Pipe();
        var outbound = new Pipe();
        await inbound.Writer.WriteAsync("SSH-2.0-pooling-test\r\n"u8.ToArray(), Token);
        await inbound.Writer.WriteAsync(Frame(ChannelTestHarness.BuildChannelDataPayload(0, new byte[20])), Token);
        await inbound.Writer.WriteAsync(Frame([(byte)PacketType.Disconnect]), Token);
        await using var session = new SshSession(TimeProvider.System, pool);
        await Assert.ThrowsAsync<SshException>(() => session.HandshakeAsync(
            new TestDuplex(inbound.Reader, outbound.Writer), (_, _, _) => Task.FromResult(true), Token));
        Assert.Equal(1, pool.Returns);
        Assert.Equal(0, pool.Outstanding);
        await session.DisposeAsync();
        await outbound.Writer.WriteAsync(new byte[1], Token);
        await inbound.Writer.WriteAsync(new byte[1], Token);
        await inbound.Writer.CompleteAsync();
        await inbound.Reader.CompleteAsync();
        await outbound.Writer.CompleteAsync();
        await outbound.Reader.CompleteAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReadLock_PreventsReturnDuringCopy(bool ignore)
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        byte[] data = Enumerable.Repeat((byte)42, 20).ToArray();
        await h.FeedInboundAsync(Frame(ChannelTestHarness.BuildChannelExtendedDataPayload(channel.LocalId, 1, data)));
        await h.Router.PumpOneBatchForTestAsync(Token);
        using var memory = new GatedMemory();
        Task<int> read = Task.Run(async () => await channel.ReadStderrAsync(memory.Output, Token), Token);
        await memory.Entered.Task.WaitAsync(Token);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cleanup = Task.Run(async () =>
        {
            started.SetResult();
            if (ignore)
            {
                await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, Token);
            }
            else
            {
                h.Router.Dispose();
            }
        }, Token);
        await started.Task.WaitAsync(Token);
        try
        {
            Assert.Equal(1, pool.Outstanding);
            Assert.False(cleanup.IsCompleted);
        }
        finally
        {
            memory.Continue.Set();
        }
        Assert.Equal(7, await read);
        await cleanup;
        Assert.Equal(Enumerable.Repeat((byte)42, 7), memory.Bytes);
        Assert.Equal(0, pool.Outstanding);
    }

    [Fact]
    public async Task ExceptionalChannelDisposal_ReleasesUnreadData()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        await h.FeedInboundAsync(Frame(ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, new byte[20])));
        await h.Router.PumpOneBatchForTestAsync(Token);
        await h.ClientWriter.DisposeAsync();
        await Assert.ThrowsAnyAsync<Exception>(() => channel.DisposeAsync().AsTask());
        await channel.DisposeAsync();
        Assert.Equal(0, pool.Outstanding);
    }

    [Fact]
    public async Task CanceledStderrRead_PreservesBufferedStdout()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        byte[] data = Enumerable.Repeat((byte)42, 20).ToArray();
        await h.FeedInboundAsync(Frame(ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, data)));
        await h.Router.PumpOneBatchForTestAsync(Token);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Token);
        Task<int> read = channel.ReadStderrAsync(new byte[20], cancellation.Token).AsTask();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read);
        Assert.Equal(1, pool.Outstanding);
        byte[] output = new byte[20];
        Assert.Equal(20, await channel.ReadAsync(output, Token));
        Assert.Equal(data, output);
        Assert.Equal(0, pool.Outstanding);
    }

    [Fact]
    public async Task RefundFailure_ReturnsIgnoredPacket()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, Token);
        await h.ClientWriter.DisposeAsync();
        await h.FeedInboundAsync(Frame(ChannelTestHarness.BuildChannelExtendedDataPayload(channel.LocalId, 1, new byte[20])));
        await Assert.ThrowsAnyAsync<Exception>(() => h.Router.PumpOnceAsync(Token));
        Assert.Equal(1, pool.Returns);
        Assert.Equal(0, pool.Outstanding);
    }

    [Fact]
    public async Task SessionTeardown_ReleasesChannelBuffers()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        await h.FeedInboundAsync(Frame(ChannelTestHarness.BuildChannelDataPayload(channel.LocalId, new byte[20])));
        await h.Router.PumpOneBatchForTestAsync(Token);
        await using var session = new SshSession();
        session.SetChannelRouterForTest(h.Router);
        await session.DisposeAsync();
        await session.DisposeAsync();
        Assert.Equal(0, pool.Outstanding);
    }

    [Fact]
    public async Task DeliveryAndIgnore_SerializeWithPartialRead()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        SshChannel channel = h.CreateChannel();
        byte[] data = Enumerable.Repeat((byte)42, 20).ToArray();
        byte[] frame = Frame(ChannelTestHarness.BuildChannelExtendedDataPayload(channel.LocalId, 1, data));
        await h.FeedInboundAsync(frame);
        await h.Router.PumpOneBatchForTestAsync(Token);
        using var memory = new GatedMemory();
        Task<int> read = Task.Run(async () => await channel.ReadStderrAsync(memory.Output, Token), Token);
        await memory.Entered.Task.WaitAsync(Token);
        await h.FeedInboundAsync(frame);
        var delivery = Task.Run(() => h.Router.PumpOnceAsync(Token), Token);
        await pool.SecondRent.Task.WaitAsync(Token);
        var ignore = Task.Run(() => channel.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, Token), Token);
        try
        {
            Assert.Equal(2, pool.Outstanding);
            Assert.Equal(0, pool.Returns);
        }
        finally
        {
            memory.Continue.Set();
        }
        Assert.Equal(7, await read);
        await Task.WhenAll(delivery, ignore);
        Assert.Equal(Enumerable.Repeat((byte)42, 7), memory.Bytes);
        Assert.Equal(0, pool.Outstanding);
    }

    [Fact]
    public async Task FailedOpen_UnregistersAndReleasesEarlyData()
    {
        var pool = new TrackingPayloadPool();
        using var h = new ChannelTestHarness(pool);
        byte[] data = ChannelTestHarness.BuildChannelDataPayload(0, new byte[20]);
        // Malformed confirmation fails parsing after the early data was buffered.
        await h.FeedInboundAsync(Frame(data), Frame([(byte)PacketType.ChannelOpenConfirmation, 0, 0, 0, 0]));
        await Assert.ThrowsAsync<SshException>(() => SshChannel.OpenAsync(h.ClientWriter, h.Router, Token));
        Assert.Equal(1, pool.Returns);
        Assert.Equal(0, pool.Outstanding);
        Assert.False(h.Router.TryGet(0, out _));
    }

    private sealed class TestDuplex(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input => input;
        public PipeWriter Output => output;
    }

    private sealed class GatedMemory : MemoryManager<byte>
    {
        public byte[] Bytes { get; } = new byte[7];
        public Memory<byte> Output => CreateMemory(7);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ManualResetEventSlim Continue { get; } = new();
        public override Span<byte> GetSpan()
        {
            Entered.TrySetResult();
            Continue.Wait(Token);
            return Bytes;
        }
        public override MemoryHandle Pin(int elementIndex = 0) => throw new NotSupportedException();
        public override void Unpin() { }
        protected override void Dispose(bool disposing) => Continue.Dispose();
    }

    private static byte[] Frame(byte[] payload) => ChannelTestHarness.BuildCleartextPacket(payload[0], payload);
}

/// <summary>Oversized rentals, immediate reuse, and strict clearing/return accounting.</summary>
internal sealed class TrackingPayloadPool : ArrayPool<byte>
{
    private readonly Dictionary<byte[], int> _live = [];
    private readonly Stack<byte[]> _returned = [];
    private int _rents;
    public TaskCompletionSource SecondRent { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int Outstanding
    {
        get
        {
            lock (_live)
            {
                return _live.Count;
            }
        }
    }
    public int Returns { get; private set; }

    public override byte[] Rent(int minimumLength)
    {
        lock (_live)
        {
            byte[] buffer = _returned.Count > 0 && _returned.Peek().Length >= minimumLength
                ? _returned.Pop() : new byte[minimumLength + 31];
            Array.Fill(buffer, (byte)0xa5);
            _live.Add(buffer, minimumLength);
            if (++_rents == 2)
            {
                SecondRent.TrySetResult();
            }
            return buffer;
        }
    }

    public override void Return(byte[] array, bool clearArray = false)
    {
        lock (_live)
        {
            Assert.True(_live.Remove(array, out int used), "Duplicate or foreign return");
            Assert.True(array.AsSpan(0, used).IndexOfAnyExcept((byte)0) < 0, "Used payload was not cleared");
            Assert.True(array.AsSpan(used).IndexOfAnyExcept((byte)0xa5) < 0, "Rental capacity was modified");
            Returns++;
            _returned.Push(array);
        }
    }
}
