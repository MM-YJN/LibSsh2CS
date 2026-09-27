using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

public class ForwardedResponseWriterTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForwardedResponses_PreservePayloads_WithEncryptionAndCompression(bool compressed)
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

        await writer.WriteChannelOpenConfirmationAsync(0xFEDCBA98, 7, 2097152, 32768, ct);
        using RawPacket confirmation = await reader.ReadPacketAsync(ct);
        Assert.Equal(Convert.FromHexString("5BFEDCBA98000000070020000000008000"), confirmation.Payload.ToArray());

        foreach ((string description, string language) in new[]
        {
            ("", ""), ("Connection refused", "en"), ("接続拒否", "中文"),
            ("bad" + (char)0xD800, "bad" + (char)0xD800), (new string('x', 4096), ""),
        })
        {
            await writer.WriteChannelOpenFailureAsync(42, 1, description, language, ct);
            using RawPacket failure = await reader.ReadPacketAsync(ct);
            byte[] text = System.Text.Encoding.UTF8.GetBytes(description);
            byte[] lang = System.Text.Encoding.ASCII.GetBytes(language);
            byte[] expected = new byte[17 + text.Length + lang.Length];
            expected[0] = 92;
            BinaryPrimitives.WriteUInt32BigEndian(expected.AsSpan(1), 42);
            BinaryPrimitives.WriteInt32BigEndian(expected.AsSpan(5), 1);
            BinaryPrimitives.WriteInt32BigEndian(expected.AsSpan(9), text.Length);
            text.CopyTo(expected, 13);
            BinaryPrimitives.WriteInt32BigEndian(expected.AsSpan(13 + text.Length), lang.Length);
            lang.CopyTo(expected, 17 + text.Length);
            Assert.Equal(expected, failure.Payload.ToArray());
            Assert.Equal(expected, SshChannel.BuildChannelOpenFailurePayload(42, 1, description, language));
        }
        Assert.Equal(6u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task QueuedCancellation_PreservesOtherResponses()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 1, resumeWriterThreshold: 1));
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        Task first = writer.WriteChannelOpenConfirmationAsync(41, 7, 2097152, 32768, ct);
        Assert.False(first.IsCompleted);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task cancelled = writer.WriteChannelOpenFailureAsync(42, 1, "cancelled", cancellationToken: cts.Token);
        Task third = writer.WriteChannelOpenFailureAsync(43, 2, "surviving response", cancellationToken: ct);
        Assert.False(cancelled.IsCompleted);
        Assert.False(third.IsCompleted);
        await cts.CancelAsync();
        OperationCanceledException error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal(cts.Token, error.CancellationToken);

        using RawPacket packet1 = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.ChannelOpenConfirmation, packet1.Type);
        Assert.Equal(41u, BinaryPrimitives.ReadUInt32BigEndian(packet1.Payload.Span.Slice(1)));
        await first.WaitAsync(ct);
        using RawPacket packet3 = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.ChannelOpenFailure, packet3.Type);
        Assert.Equal(43u, BinaryPrimitives.ReadUInt32BigEndian(packet3.Payload.Span.Slice(1)));
        Assert.Equal(SshChannel.BuildChannelOpenFailurePayload(43, 2, "surviving response"), packet3.Payload.ToArray());
        await third.WaitAsync(ct);
        Assert.Equal(2u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }
}
