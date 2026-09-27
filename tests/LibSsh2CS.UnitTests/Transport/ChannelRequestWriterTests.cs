using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

public class ChannelRequestWriterTests
{
    [Fact]
    public async Task QueuedRequestCancellation_DoesNotEncodeOrCorruptOtherRequests()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 1, resumeWriterThreshold: 1));
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        byte[] request = "signal"u8.ToArray();

        // A real blocked flush holds the writer lock while two more sends queue.
        Task first = writer.WriteChannelRequestPacketAsync(41, request, false, 4, 111u,
            static (destination, state) => BinaryPrimitives.WriteUInt32BigEndian(destination, state), ct);
        Assert.False(first.IsCompleted);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bool encodedCancelledRequest = false;
        Task cancelled = writer.WriteChannelRequestPacketAsync(42, request, false, 4, 222u,
            (destination, state) =>
            {
                encodedCancelledRequest = true;
                BinaryPrimitives.WriteUInt32BigEndian(destination, state);
            }, cts.Token);
        Task third = writer.WriteChannelRequestPacketAsync(43, request, false, 4, 333u,
            static (destination, state) => BinaryPrimitives.WriteUInt32BigEndian(destination, state), ct);
        Assert.False(cancelled.IsCompleted);
        Assert.False(third.IsCompleted);
        await cts.CancelAsync();
        OperationCanceledException error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal(cts.Token, error.CancellationToken);
        Assert.False(encodedCancelledRequest);

        using RawPacket packet1 = await reader.ReadPacketAsync(ct);
        AssertRequest(packet1, 41, 111);
        await first.WaitAsync(ct);
        using RawPacket packet3 = await reader.ReadPacketAsync(ct);
        AssertRequest(packet3, 43, 333);
        await third.WaitAsync(ct);
        Assert.Equal(2u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task OversizedRequest_IsRejected_AndNextRequestSucceeds()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        byte[] request = "signal"u8.ToArray();
        bool encoded = false;
        SshException error = await Assert.ThrowsAsync<SshException>(() =>
            writer.WriteChannelRequestPacketAsync(41, request, false, 35000, 0,
                (_, _) => encoded = true, ct));
        Assert.Equal(SshErrorCode.Inval, error.ErrorCode);
        Assert.False(encoded);
        Assert.Equal(0u, writer.Seqno);
        await writer.WriteChannelRequestPacketAsync(41, request, false, 4, 111u,
            static (destination, state) => BinaryPrimitives.WriteUInt32BigEndian(destination, state), ct);
        using RawPacket packet = await reader.ReadPacketAsync(ct);
        AssertRequest(packet, 41, 111);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    private static void AssertRequest(RawPacket packet, uint recipient, uint value)
    {
        Assert.Equal(PacketType.ChannelRequest, packet.Type);
        Assert.Equal(20, packet.Payload.Length);
        ReadOnlySpan<byte> payload = packet.Payload.Span;
        Assert.Equal(recipient, BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(1)));
        Assert.Equal(6u, BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(5)));
        Assert.True(payload.Slice(9, 6).SequenceEqual("signal"u8));
        Assert.Equal(0, payload[15]);
        Assert.Equal(value, BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(16)));
    }
}
