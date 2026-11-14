using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Regression tests for the NEWKEYS outbound-key transition. Once the writer
/// has emitted <c>SSH_MSG_NEWKEYS</c>, it must not frame any other packet until
/// the new outbound cipher/MAC/compression has been installed. Under strict KEX
/// the sequence number is reset to 0 at NEWKEYS, so an application packet
/// framed in that window would reuse the old key's nonce; the peer has also
/// already switched its inbound keys and would reject the frame.
/// </summary>
public class NewKeysTransitionTests
{
    private const string CipherName = "chacha20-poly1305@openssh.com";

    /// <summary>
    /// A write issued after NEWKEYS must stay queued until the outbound key
    /// install completes, then must be framed under the new cipher at the
    /// post-NEWKEYS sequence number (0 under strict KEX, continuing otherwise).
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WriteAfterNewKeys_WaitsUntilOutboundKeysInstalled(bool strictKex)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);

        await InstallKeysAsync(writer, reader, keyByte: 0x11, strictKex, ct);
        await writer.WriteControlPacketAsync(PacketType.NewKeys, ct);
        using (RawPacket newKeys = await reader.ReadPacketAsync(ct))
        {
            Assert.Equal(PacketType.NewKeys, newKeys.Type);
        }

        byte[] appPayload = [(byte)PacketType.Ignore, 0x5A];
        Task appWrite = writer.WritePacketAsync(PacketType.Ignore, appPayload, ct);

        // On the unfixed code this write is framed immediately with the old
        // cipher (and strict-KEX seqno 0). The fix must hold it until the new
        // outbound keys are installed.
        await Task.Delay(150, ct);
        Assert.False(appWrite.IsCompleted,
            "application packet was framed after NEWKEYS before the new outbound keys were installed");

        await InstallKeysAsync(writer, reader, keyByte: 0x22, strictKex, ct);
        await appWrite;

        using RawPacket app = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.Ignore, app.Type);
        Assert.Equal(appPayload, app.Payload.ToArray());
        // The new key starts at the strict-KEX reset point (0) or continues the
        // old sequence number when strict KEX was not negotiated.
        Assert.Equal(strictKex ? 0u : 1u, app.Seqno);
        Assert.Equal(strictKex ? 1u : 2u, writer.Seqno);
        Assert.Equal(strictKex ? 1u : 2u, reader.Seqno);
    }

    /// <summary>
    /// Several writers queued behind the NEWKEYS barrier must all be held until
    /// the install, then framed under the new key. Their on-wire order is
    /// arbitrary, but the sequence numbers must be the four post-NEWKEYS slots
    /// and every payload must survive.
    /// </summary>
    [Fact]
    public async Task WriteAfterNewKeys_MultipleConcurrentWriters_AllUseNewKey()
    {
        const int WriterCount = 4;
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);

        await InstallKeysAsync(writer, reader, keyByte: 0x11, strictKex: true, ct);
        await writer.WriteControlPacketAsync(PacketType.NewKeys, ct);
        using (RawPacket newKeys = await reader.ReadPacketAsync(ct))
        {
            Assert.Equal(PacketType.NewKeys, newKeys.Type);
        }

        Task[] writes = Enumerable.Range(0, WriterCount).Select(i =>
            writer.WritePacketAsync(
                PacketType.Ignore, new byte[] { (byte)PacketType.Ignore, (byte)i }, ct)).ToArray();

        await Task.Delay(150, ct);
        Assert.All(writes, write => Assert.False(write.IsCompleted,
            "application packet was framed after NEWKEYS before the new outbound keys were installed"));

        await InstallKeysAsync(writer, reader, keyByte: 0x22, strictKex: true, ct);
        await Task.WhenAll(writes);

        var seqnos = new List<uint>(WriterCount);
        var markers = new List<byte>(WriterCount);
        for (int i = 0; i < WriterCount; i++)
        {
            using RawPacket packet = await reader.ReadPacketAsync(ct);
            Assert.Equal(PacketType.Ignore, packet.Type);
            seqnos.Add(packet.Seqno);
            markers.Add(packet.Payload.Span[1]);
        }

        Assert.Equal(new uint[] { 0, 1, 2, 3 }, seqnos.OrderBy(seqno => seqno).ToArray());
        Assert.Equal(new byte[] { 0, 1, 2, 3 }, markers.OrderBy(marker => marker).ToArray());
    }

    /// <summary>
    /// Cancelling a write that is queued behind the NEWKEYS barrier must not
    /// emit a frame, must surface the cancellation, and must leave the
    /// transition installable afterwards.
    /// </summary>
    [Fact]
    public async Task WriteAfterNewKeys_CancelledWaiter_DoesNotEmitOldKeyFrame()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);

        await InstallKeysAsync(writer, reader, keyByte: 0x11, strictKex: true, ct);
        await writer.WriteControlPacketAsync(PacketType.NewKeys, ct);
        using (RawPacket newKeys = await reader.ReadPacketAsync(ct))
        {
            Assert.Equal(PacketType.NewKeys, newKeys.Type);
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task cancelledWrite = writer.WritePacketAsync(
            PacketType.Ignore, new byte[] { (byte)PacketType.Ignore, 0x01 }, cts.Token);

        await Task.Delay(150, ct);
        Assert.False(cancelledWrite.IsCompleted,
            "application packet was framed after NEWKEYS before the new outbound keys were installed");

        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelledWrite);

        await InstallKeysAsync(writer, reader, keyByte: 0x22, strictKex: true, ct);
        byte[] nextPayload = [(byte)PacketType.Ignore, 0x02];
        await writer.WritePacketAsync(PacketType.Ignore, nextPayload, ct);

        using RawPacket next = await reader.ReadPacketAsync(ct);
        Assert.Equal(nextPayload, next.Payload.ToArray());
        Assert.Equal(0u, next.Seqno);
    }

    /// <summary>
    /// A second NEWKEYS while the first transition is still waiting for its key
    /// install is a protocol error. It must throw without aborting the pending
    /// transition, so the original install can still complete.
    /// </summary>
    [Fact]
    public async Task WriteAfterNewKeys_SecondNewKeysWhilePending_ThrowsProto()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        await using var writer = new PacketWriter(pipe.Writer);
        await using var reader = new PacketReader(pipe.Reader);

        await InstallKeysAsync(writer, reader, keyByte: 0x11, strictKex: true, ct);
        await writer.WriteControlPacketAsync(PacketType.NewKeys, ct);
        using (RawPacket newKeys = await reader.ReadPacketAsync(ct))
        {
            Assert.Equal(PacketType.NewKeys, newKeys.Type);
        }

        SshException error = await Assert.ThrowsAsync<SshException>(
            () => writer.WriteControlPacketAsync(PacketType.NewKeys, ct));
        Assert.Equal(SshErrorCode.Proto, error.ErrorCode);

        // The rejection must not poison the original transition.
        await InstallKeysAsync(writer, reader, keyByte: 0x22, strictKex: true, ct);
        byte[] payload = [(byte)PacketType.Ignore, 0x03];
        await writer.WritePacketAsync(PacketType.Ignore, payload, ct);

        using RawPacket packet = await reader.ReadPacketAsync(ct);
        Assert.Equal(payload, packet.Payload.ToArray());
        Assert.Equal(0u, packet.Seqno);
    }

    /// <summary>
    /// Disposing a writer with a NEWKEYS transition still pending must fault
    /// the waiting write instead of leaving it blocked forever.
    /// </summary>
    [Fact]
    public async Task WriteAfterNewKeys_DisposeFaultsQueuedWriters()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);
        bool disposed = false;
        try
        {
            await using var reader = new PacketReader(pipe.Reader);
            await InstallKeysAsync(writer, reader, keyByte: 0x11, strictKex: true, ct);
            await writer.WriteControlPacketAsync(PacketType.NewKeys, ct);
            using (RawPacket newKeys = await reader.ReadPacketAsync(ct))
            {
                Assert.Equal(PacketType.NewKeys, newKeys.Type);
            }

            Task queuedWrite = writer.WritePacketAsync(
                PacketType.Ignore, new byte[] { (byte)PacketType.Ignore, 0x04 }, ct);
            await Task.Delay(150, ct);
            Assert.False(queuedWrite.IsCompleted,
                "application packet was framed after NEWKEYS before the new outbound keys were installed");

            disposed = true;
            await writer.DisposeAsync();

            await Assert.ThrowsAnyAsync<ObjectDisposedException>(() => queuedWrite);
        }
        finally
        {
            if (!disposed)
            {
                await writer.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// Installs a fresh ChaCha20-Poly1305 outbound/inbound key pair. The test
    /// uses the same key material in both directions; the transport contract
    /// under test is the NEWKEYS ordering, not the A/B key split.
    /// </summary>
    private static async Task InstallKeysAsync(
        PacketWriter writer, PacketReader reader, byte keyByte, bool strictKex, CancellationToken ct)
    {
        byte[] key = new byte[64];
        Array.Fill(key, keyByte);

        ICipher encrypt = CipherMethods.Create(CipherName)!;
        ICipher decrypt = CipherMethods.Create(CipherName)!;
        encrypt.Init(key, ReadOnlySpan<byte>.Empty, encrypt: true);
        decrypt.Init(key, ReadOnlySpan<byte>.Empty, encrypt: false);

        await writer.SetOutboundKeysAsync(
            encrypt, MacMethods.Noop, CompressionMethods.Create("none")!,
            strictKex, compressionActive: false, ct);
        reader.SetInboundKeys(
            decrypt, MacMethods.Noop, CompressionMethods.Create("none")!,
            strictKex, compressionActive: false);
    }
}
