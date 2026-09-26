using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

public class PacketResultAwaitTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reader_ReturnsIndependentPackets_WhenBufferedOrSuspended(bool buffered)
    {
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        CancellationToken ct = TestContext.Current.CancellationToken;
        byte[] first = [(byte)PacketType.ChannelData, 1, 2, 3];
        byte[] second = [(byte)PacketType.ChannelData, 4, 5, 6];
        if (buffered)
        {
            await writer.WritePacketAsync(PacketType.ChannelData, first, ct);
        }
        ValueTask<RawPacket> read = reader.ReadPacketAsync(ct);
        Assert.Equal(buffered, read.IsCompletedSuccessfully);
        if (!buffered)
        {
            await writer.WritePacketAsync(PacketType.ChannelData, first, ct);
        }
        RawPacket packet1 = await read;
        await writer.WritePacketAsync(PacketType.ChannelData, second, ct);
        RawPacket packet2 = await reader.ReadPacketAsync(ct);
        Assert.Equal(first, packet1.Payload);
        Assert.Equal(second, packet2.Payload);
        Assert.NotSame(packet1.Payload, packet2.Payload);
        Assert.Equal(0u, packet1.Seqno);
        Assert.Equal(1u, packet2.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Theory]
    [InlineData(false, "buffered")]
    [InlineData(true, "buffered")]
    [InlineData(false, "stashed")]
    [InlineData(true, "stashed")]
    [InlineData(false, "suspended")]
    [InlineData(true, "suspended")]
    public async Task TypedWait_ReturnsPacketAcrossCompletionPaths(bool multipleTypes, string path)
    {
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        var queue = new PacketQueue(reader) { ReadTimeout = TimeSpan.Zero };
        CancellationToken ct = TestContext.Current.CancellationToken;
        byte[] body = [(byte)PacketType.ChannelSuccess, 1, 2, 3, 4];
        if (path != "suspended")
        {
            await writer.WritePacketAsync(PacketType.ChannelSuccess, body, ct);
        }
        if (path == "stashed")
        {
            await writer.WritePacketAsync(PacketType.ChannelFailure, new byte[] { (byte)PacketType.ChannelFailure }, ct);
            _ = await queue.WaitForTypeAsync(PacketType.ChannelFailure, ct);
        }
        ValueTask<RawPacket> wait = multipleTypes
            ? queue.WaitForTypesAsync([PacketType.ChannelSuccess, PacketType.ChannelFailure], ct)
            : queue.WaitForTypeAsync(PacketType.ChannelSuccess, ct);
        Assert.Equal(path != "suspended", wait.IsCompletedSuccessfully);
        if (path == "suspended")
        {
            await writer.WritePacketAsync(PacketType.ChannelSuccess, body, ct);
        }
        RawPacket result = await wait;
        Assert.Equal(PacketType.ChannelSuccess, result.Type);
        Assert.Equal(body, result.Payload);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }
}
