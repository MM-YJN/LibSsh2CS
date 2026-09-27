using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

public class DirectRequestWriterTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Requests_PreservePayloads_WithEncryptionAndCompression(bool compressed)
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

        foreach (string name in new[] { "session", "direct-tcpip", "direct-streamlocal@openssh.com" })
        {
            byte[] extra = name == "session" ? [] : [1, 2, 3, 4];
            await writer.WriteChannelOpenPacketAsync(name, 42, 1024, 512, extra.Length, extra,
                static (destination, state) => state.CopyTo(destination), ct);
            using RawPacket packet = await reader.ReadPacketAsync(ct);
            Assert.Equal(SshChannel.BuildChannelOpenPayload(name, 42, 1024, 512, extra), packet.Payload.ToArray());
        }
        foreach (bool wantReply in new[] { false, true })
        {
            foreach (string name in new[] { "tcpip-forward", "cancel-tcpip-forward", "keepalive@libssh2.org" })
            {
                byte[] extra = name == "keepalive@libssh2.org" ? [] : [0, 0, 0, 0, 0, 0, 0, 22];
                await writer.WriteGlobalRequestPacketAsync(name, wantReply, extra.Length, extra,
                    static (destination, state) => state.CopyTo(destination), ct);
                using RawPacket packet = await reader.ReadPacketAsync(ct);
                Assert.Equal(GlobalRequest.BuildPayload(name, extra, wantReply), packet.Payload.ToArray());
            }
        }
        Assert.Equal(9u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueuedCancellation_DoesNotSerializeCancelledState(bool cancelOpen)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 1, resumeWriterThreshold: 1));
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);
        Task first = writer.WriteGlobalRequestPacketAsync("first", false, 0, 0, static (_, _) => { }, ct);
        Assert.False(first.IsCompleted);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task cancelled = cancelOpen
            ? writer.WriteChannelOpenPacketAsync("session", 99, 1024, 512, 0, 0,
                static (_, _) => throw new InvalidOperationException("Cancelled state was serialized"), cts.Token)
            : writer.WriteGlobalRequestPacketAsync("cancelled", false, 0, 0,
                static (_, _) => throw new InvalidOperationException("Cancelled state was serialized"), cts.Token);
        Task third = writer.WriteChannelOpenPacketAsync("session", 43, 1024, 512, 0, 0, static (_, _) => { }, ct);
        Assert.False(cancelled.IsCompleted);
        Assert.False(third.IsCompleted);
        await cts.CancelAsync();
        OperationCanceledException error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal(cts.Token, error.CancellationToken);
        using RawPacket packet1 = await reader.ReadPacketAsync(ct);
        Assert.Equal(GlobalRequest.BuildPayload("first", default, false), packet1.Payload.ToArray());
        await first.WaitAsync(ct);
        using RawPacket packet3 = await reader.ReadPacketAsync(ct);
        Assert.Equal(SshChannel.BuildChannelOpenPayload("session", 43, 1024, 512, default), packet3.Payload.ToArray());
        await third.WaitAsync(ct);
        Assert.Equal(2u, writer.Seqno);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }
}
