using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Transport;

public class LazyReadDeadlineTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task BufferedRead_DoesNotCreateTimer(bool singleType, bool inline)
    {
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader);
        await using var writer = new PacketWriter(pipe.Writer);
        var time = new CountingTimeProvider();
        using PacketQueue queue = CreateQueue(reader, time);
        if (inline)
        {
            await writer.WritePacketAsync(PacketType.Ignore, new byte[] { (byte)PacketType.Ignore }, TestContext.Current.CancellationToken);
        }
        await writer.WritePacketAsync(PacketType.ChannelSuccess, new byte[] { (byte)PacketType.ChannelSuccess }, TestContext.Current.CancellationToken);
        ValueTask<RawPacket> wait = Wait(queue, singleType, TestContext.Current.CancellationToken);
        Assert.True(wait.IsCompletedSuccessfully);
        using RawPacket packet = await wait;
        Assert.Equal(PacketType.ChannelSuccess, packet.Type);
        Assert.Equal(0, time.TimerCount);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task InlineWork_ConsumesDeadline_AndCallerCancellationWins(bool singleType, bool cancelCaller)
    {
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader);
        await using var writer = new PacketWriter(pipe.Writer);
        var time = new CountingTimeProvider();
        using PacketQueue queue = CreateQueue(reader, time);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        queue.IgnoreCallback = _ =>
        {
            time.Advance(TimeSpan.FromSeconds(6));
            if (cancelCaller)
            {
                cts.Cancel();
            }
        };
        await writer.WritePacketAsync(PacketType.Ignore, new byte[] { (byte)PacketType.Ignore }, TestContext.Current.CancellationToken);
        await writer.WritePacketAsync(PacketType.ChannelSuccess, new byte[] { (byte)PacketType.ChannelSuccess }, TestContext.Current.CancellationToken);
        if (cancelCaller)
        {
            OperationCanceledException error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Wait(queue, singleType, cts.Token).AsTask());
            Assert.Equal(cts.Token, error.CancellationToken);
        }
        else
        {
            SshException error = await Assert.ThrowsAsync<SshException>(() => Wait(queue, singleType, cts.Token).AsTask());
            Assert.Equal(SshErrorCode.Timeout, error.ErrorCode);
        }
        Assert.Equal(0, time.TimerCount);
        Assert.Equal(0, queue.ExpectedType);
        using RawPacket next = await Wait(queue, singleType, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelSuccess, next.Type);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Suspension_UsesRemainingDeadline_AndInlinePacketsDoNotRestartIt(bool singleType)
    {
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader);
        await using var writer = new PacketWriter(pipe.Writer);
        var time = new CountingTimeProvider();
        using PacketQueue queue = CreateQueue(reader, time);
        var secondIgnore = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int ignores = 0;
        queue.IgnoreCallback = _ =>
        {
            time.Advance(TimeSpan.FromSeconds(++ignores == 1 ? 3 : 1));
            if (ignores == 2)
            {
                secondIgnore.SetResult();
            }
        };
        await writer.WritePacketAsync(PacketType.Ignore, new byte[] { (byte)PacketType.Ignore }, TestContext.Current.CancellationToken);
        Task<RawPacket> wait = Wait(queue, singleType, TestContext.Current.CancellationToken).AsTask();
        Assert.False(wait.IsCompleted);
        Assert.Equal(1, time.TimerCount);
        Assert.Equal(TimeSpan.FromSeconds(2), time.LastDueTime);
        await writer.WritePacketAsync(PacketType.Ignore, new byte[] { (byte)PacketType.Ignore }, TestContext.Current.CancellationToken);
        await secondIgnore.Task.WaitAsync(TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromSeconds(1));
        SshException error = await Assert.ThrowsAsync<SshException>(() => wait);
        Assert.Equal(SshErrorCode.Timeout, error.ErrorCode);
        Assert.Equal(1, time.TimerCount);
        await writer.WritePacketAsync(PacketType.ChannelSuccess, new byte[] { (byte)PacketType.ChannelSuccess }, TestContext.Current.CancellationToken);
        using RawPacket next = await Wait(queue, singleType, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelSuccess, next.Type);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task FragmentedEncryptedRead_PreservesCipherState(bool singleType, bool timeoutEnabled)
    {
        var wirePipe = new Pipe();
        var pipe = new Pipe();
        await using var writer = new PacketWriter(wirePipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        ICipher encrypt = CipherMethods.Create("aes128-ctr")!;
        ICipher decrypt = CipherMethods.Create("aes128-ctr")!;
        encrypt.Init(new byte[16], new byte[16], encrypt: true);
        decrypt.Init(new byte[16], new byte[16], encrypt: false);
        await writer.SetOutboundKeysAsync(encrypt, MacMethods.Noop, CompressionMethods.Create("none")!, false, false, TestContext.Current.CancellationToken);
        reader.SetInboundKeys(decrypt, MacMethods.Noop, CompressionMethods.Create("none")!, false, false);
        byte[] payload = new byte[100];
        payload[0] = (byte)PacketType.ChannelSuccess;
        await writer.WritePacketAsync(PacketType.ChannelSuccess, payload, TestContext.Current.CancellationToken);
        ReadResult wire = await wirePipe.Reader.ReadAsync(TestContext.Current.CancellationToken);
        byte[] bytes = new byte[wire.Buffer.Length];
        System.Buffers.BuffersExtensions.CopyTo(wire.Buffer, bytes);
        wirePipe.Reader.AdvanceTo(wire.Buffer.End);
        await wirePipe.Reader.CompleteAsync();
        var time = new CountingTimeProvider();
        using PacketQueue queue = CreateQueue(reader, time);
        if (!timeoutEnabled)
        {
            queue.ReadTimeout = TimeSpan.Zero;
        }
        await pipe.Writer.WriteAsync(bytes.AsMemory(0, 16), TestContext.Current.CancellationToken);
        ValueTask<RawPacket> wait = Wait(queue, singleType, TestContext.Current.CancellationToken);
        Assert.False(wait.IsCompleted);
        await pipe.Writer.WriteAsync(bytes.AsMemory(16), TestContext.Current.CancellationToken);
        using RawPacket packet = await wait;
        Assert.Equal(payload, packet.Payload.ToArray());
        Assert.Equal(timeoutEnabled ? 1 : 0, time.TimerCount);
        await pipe.Writer.CompleteAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletedEmptyPipe_IsDisconnectWithoutTimer(bool singleType)
    {
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader);
        var time = new CountingTimeProvider();
        using PacketQueue queue = CreateQueue(reader, time);
        await pipe.Writer.CompleteAsync();
        SshException error = await Assert.ThrowsAsync<SshException>(() => Wait(queue, singleType, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal(SshErrorCode.SocketDisconnect, error.ErrorCode);
        Assert.Equal(0, time.TimerCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancelPendingRead_StillCancelsBufferedFastPath(bool singleType)
    {
        var pipe = new Pipe();
        await using var reader = new PacketReader(pipe.Reader);
        await using var writer = new PacketWriter(pipe.Writer);
        var time = new CountingTimeProvider();
        using PacketQueue queue = CreateQueue(reader, time);
        await writer.WritePacketAsync(PacketType.ChannelSuccess, new byte[] { (byte)PacketType.ChannelSuccess }, TestContext.Current.CancellationToken);
        pipe.Reader.CancelPendingRead();
        SshException error = await Assert.ThrowsAsync<SshException>(() => Wait(queue, singleType, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal(SshErrorCode.Timeout, error.ErrorCode);
        using RawPacket next = await Wait(queue, singleType, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelSuccess, next.Type);
    }

    private static PacketQueue CreateQueue(PacketReader reader, TimeProvider time) => new(reader)
    {
        TimeProvider = time,
        ReadTimeout = TimeSpan.FromSeconds(5),
    };

    private static ValueTask<RawPacket> Wait(PacketQueue queue, bool singleType, CancellationToken token) => singleType
        ? queue.WaitForTypeAsync(PacketType.ChannelSuccess, token)
        : queue.WaitForTypesAsync([PacketType.ChannelSuccess, PacketType.ChannelFailure], token);

    private sealed class CountingTimeProvider : TimeProvider
    {
        private readonly FakeTimeProvider _time = new();
        public int TimerCount { get; private set; }
        public TimeSpan LastDueTime { get; private set; }
        public override long TimestampFrequency => _time.TimestampFrequency;
        public override long GetTimestamp() => _time.GetTimestamp();
        public override DateTimeOffset GetUtcNow() => _time.GetUtcNow();
        public void Advance(TimeSpan elapsed) => _time.Advance(elapsed);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            TimerCount++;
            LastDueTime = dueTime;
            return _time.CreateTimer(callback, state, dueTime, period);
        }
    }
}
