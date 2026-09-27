using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

public class ControlPacketWriterTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ControlPackets_PreservePayloads_WithEncryptionAndCompression(bool compressed)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        ICipher encrypt = CipherMethods.Create("aes256-gcm@openssh.com")!;
        ICipher decrypt = CipherMethods.Create("aes256-gcm@openssh.com")!;
        encrypt.Init(new byte[32], new byte[12], encrypt: true);
        decrypt.Init(new byte[32], new byte[12], encrypt: false);
        ICompression compressor = CompressionMethods.Create(compressed ? "zlib" : "none")!;
        ICompression decompressor = CompressionMethods.Create(compressed ? "zlib" : "none")!;
        compressor.Init(compress: true);
        decompressor.Init(compress: false);
        await writer.SetOutboundKeysAsync(encrypt, MacMethods.Noop, compressor, false, compressed, ct);
        reader.SetInboundKeys(decrypt, MacMethods.Noop, decompressor, false, compressed);

        foreach (int type in new[] { PacketType.ChannelEof, PacketType.ChannelClose, PacketType.ChannelFailure })
        {
            await writer.WriteChannelControlPacketAsync(type, 0xFEDCBA98, ct);
            using RawPacket packet = await reader.ReadPacketAsync(ct);
            Assert.Equal(new byte[] { (byte)type, 0xFE, 0xDC, 0xBA, 0x98 }, packet.Payload.ToArray());
        }
        foreach (int type in new[] { PacketType.RequestFailure, PacketType.NewKeys })
        {
            await writer.WriteControlPacketAsync(type, ct);
            using RawPacket packet = await reader.ReadPacketAsync(ct);
            Assert.Equal(new byte[] { (byte)type }, packet.Payload.ToArray());
        }
        Assert.Equal(5u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task QueuedCancellation_PreservesOtherControlPackets()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 1, resumeWriterThreshold: 1));
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        Task first = writer.WriteChannelControlPacketAsync(PacketType.ChannelEof, 41, ct);
        Assert.False(first.IsCompleted);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task cancelled = writer.WriteChannelControlPacketAsync(PacketType.ChannelClose, 42, cts.Token);
        Task third = writer.WriteChannelControlPacketAsync(PacketType.ChannelFailure, 43, ct);
        Assert.False(cancelled.IsCompleted);
        Assert.False(third.IsCompleted);
        await cts.CancelAsync();
        OperationCanceledException error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal(cts.Token, error.CancellationToken);

        using RawPacket packet1 = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.ChannelEof, packet1.Type);
        Assert.Equal(41u, BinaryPrimitives.ReadUInt32BigEndian(packet1.Payload.Span.Slice(1)));
        await first.WaitAsync(ct);
        using RawPacket packet3 = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.ChannelFailure, packet3.Type);
        Assert.Equal(43u, BinaryPrimitives.ReadUInt32BigEndian(packet3.Payload.Span.Slice(1)));
        await third.WaitAsync(ct);
        Assert.Equal(2u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }
}
