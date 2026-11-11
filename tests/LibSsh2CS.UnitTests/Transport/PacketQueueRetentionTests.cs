using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Regression tests for the bounded unexpected-packet stash: per-type and total
/// caps, suppression of repeated EXT_INFO, and disposal of dropped payloads.
/// </summary>
public class PacketQueueRetentionTests
{
    private const int MaxStashedPerType = 8;
    private const int MaxStashedTotal = 64;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task WaitForTypeAsync_UnexpectedPacketsOfOneType_StashIsBounded()
    {
        const int unexpectedCount = 100;
        byte[] unexpected = BuildCleartextPacket(PacketType.ChannelData, [94, 0, 0, 0, 0]);
        using PacketQueue queue = BuildQueueWith(
            RepeatThen(unexpected, unexpectedCount, BuildCleartextPacket(PacketType.KexInit, [20])));

        using RawPacket kex = await queue.WaitForTypeAsync(PacketType.KexInit, Token);

        Assert.Equal(MaxStashedPerType, DrainStashed(queue, PacketType.ChannelData));
    }

    [Fact]
    public async Task WaitForTypeAsync_TotalUnexpectedPacketLimit_ThrowsProto()
    {
        const int packetsPerType = MaxStashedTotal / MaxStashedPerType;
        const int typeCount = 9;
        var chunks = new List<byte[]>(packetsPerType * typeCount + 1);
        for (int t = 0; t < typeCount; t++)
        {
            byte type = (byte)(60 + t);
            byte[] packet = BuildCleartextPacket(type, [type, 0, 0, 0, 0]);
            for (int i = 0; i < packetsPerType; i++)
            {
                chunks.Add(packet);
            }
        }

        chunks.Add(BuildCleartextPacket(PacketType.KexInit, [20]));
        using PacketQueue queue = BuildQueueWith(Concat(chunks));

        SshException ex = await Assert.ThrowsAsync<SshException>(
            async () => await queue.WaitForTypeAsync(PacketType.KexInit, Token));

        Assert.Equal(SshErrorCode.Proto, ex.ErrorCode);
        Assert.Contains("stash limit", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WaitForTypeAsync_RepeatedExtInfo_RetainsOnlyOne()
    {
        const int extInfoCount = 20;
        byte[] extInfo = BuildCleartextPacket(PacketType.ExtInfo, [7, 0, 0, 0, 0]);
        using PacketQueue queue = BuildQueueWith(
            RepeatThen(extInfo, extInfoCount, BuildCleartextPacket(PacketType.KexInit, [20])));

        using RawPacket kex = await queue.WaitForTypeAsync(PacketType.KexInit, Token);

        Assert.True(queue.TryTakeStashed(PacketType.ExtInfo, out RawPacket first));
        first.Dispose();
        Assert.False(queue.TryTakeStashed(PacketType.ExtInfo, out _));
    }

    [Fact]
    public async Task WaitForTypeAsync_OverflowPackets_ReturnPayloadLeases()
    {
        const int unexpectedCount = 18;
        var pool = new TrackingPayloadPool();
        byte[] unexpected = BuildCleartextPacket(PacketType.ChannelData, [94, 0, 0, 0, 0]);
        using PacketQueue queue = BuildQueueWith(
            RepeatThen(unexpected, unexpectedCount, BuildCleartextPacket(PacketType.KexInit, [20])), pool);

        RawPacket kex = await queue.WaitForTypeAsync(PacketType.KexInit, Token);
        kex.Dispose();

        Assert.Equal(MaxStashedPerType, pool.Outstanding);
        Assert.Equal(unexpectedCount - MaxStashedPerType, pool.Returns);

        queue.Dispose();

        Assert.Equal(0, pool.Outstanding);
        Assert.Equal(unexpectedCount, pool.Returns);
    }

    [Fact]
    public async Task WaitForTypeAsync_Flood_DoesNotEvictEarlierControlPacket()
    {
        const int floodCount = 100;
        byte[] flood = BuildCleartextPacket(PacketType.ChannelData, [94, 0, 0, 0, 0]);
        byte[] newKeys = BuildCleartextPacket(PacketType.NewKeys, [21]);
        using PacketQueue queue = BuildQueueWith(
            [.. newKeys, .. RepeatThen(flood, floodCount, BuildCleartextPacket(PacketType.KexInit, [20]))]);

        using RawPacket kex = await queue.WaitForTypeAsync(PacketType.KexInit, Token);

        Assert.True(queue.TryTakeStashed(PacketType.NewKeys, out RawPacket stashed));
        Assert.Equal(PacketType.NewKeys, stashed.Type);
        stashed.Dispose();
    }

    private static int DrainStashed(PacketQueue queue, int type)
    {
        int count = 0;
        while (queue.TryTakeStashed(type, out RawPacket packet))
        {
            packet.Dispose();
            count++;
        }

        return count;
    }

    private static byte[] RepeatThen(byte[] packet, int count, byte[] tail)
    {
        byte[] data = new byte[(packet.Length * count) + tail.Length];
        for (int i = 0; i < count; i++)
        {
            Buffer.BlockCopy(packet, 0, data, i * packet.Length, packet.Length);
        }

        Buffer.BlockCopy(tail, 0, data, packet.Length * count, tail.Length);
        return data;
    }

    private static byte[] Concat(List<byte[]> chunks)
    {
        int length = 0;
        foreach (byte[] chunk in chunks)
        {
            length += chunk.Length;
        }

        byte[] data = new byte[length];
        int offset = 0;
        foreach (byte[] chunk in chunks)
        {
            Buffer.BlockCopy(chunk, 0, data, offset, chunk.Length);
            offset += chunk.Length;
        }

        return data;
    }

    private static PacketQueue BuildQueueWith(byte[] data, ArrayPool<byte>? payloadPool = null)
    {
        var pipe = new Pipe();
        pipe.Writer.Write(data);
        pipe.Writer.Complete();
        var reader = new PacketReader(pipe.Reader, payloadPool);
        return new PacketQueue(reader)
        {
            InitialKex = false,
            ReadTimeout = TimeSpan.FromSeconds(10),
        };
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
}
