using System.Buffers;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for the delayed-compression activation path that
/// <see cref="SshSession.MarkAuthenticated"/> triggers on the
/// <see cref="PacketWriter"/> / <see cref="PacketReader"/> after a successful
/// userauth. Mirrors libssh2's <c>(session->state &amp; AUTHENTICATED) ||
/// comp->use_in_auth</c> per-packet predicate (<c>transport.c:292-295,
/// 1060-1063</c>): for <c>zlib@openssh.com</c> (<c>use_in_auth=false</c>) the
/// compressor is installed inert at NEWKEYS and only goes live after auth.
/// </summary>
public class DelayedCompressionActivationTests
{
    // ── Writer side ───────────────────────────────────────────────────

    [Fact]
    public async Task Writer_ZlibOpenSsh_NotCompressedBeforeActivation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: false);
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);

        // KeyExchange passes compressionActive = Compresses && UseInAuth at
        // NEWKEYS — false for zlib@openssh.com.
        await writer.SetOutboundKeysAsync(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: comp.Compresses && comp.UseInAuth, ct);

        byte[] payload = [PacketType.Ignore, 0xAA];
        await writer.WritePacketAsync(PacketType.Ignore, payload, ct);
        // Drain the pipe so the next write doesn't deadlock.
        ReadResult rr = await pipe.Reader.ReadAsync(ct);
        pipe.Reader.AdvanceTo(rr.Buffer.End);

        Assert.Empty(comp.CompressCalls);
    }

    [Fact]
    public async Task Writer_ZlibOpenSsh_CompressedAfterActivation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: false);
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);

        await writer.SetOutboundKeysAsync(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: comp.Compresses && comp.UseInAuth, ct);

        writer.ActivateDelayedCompression();

        byte[] payload = [PacketType.Ignore, 0xAA];
        await writer.WritePacketAsync(PacketType.Ignore, payload, ct);
        ReadResult rr = await pipe.Reader.ReadAsync(ct);
        pipe.Reader.AdvanceTo(rr.Buffer.End);

        Assert.Single(comp.CompressCalls);
        Assert.Equal(payload, comp.CompressCalls[0]);
    }

    [Fact]
    public async Task Writer_Zlib_CompressedImmediately_FromNewkeys()
    {
        // Regression guard: zlib (use_in_auth=true) is active from NEWKEYS,
        // so compression fires before any ActivateDelayedCompression call.
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: true);
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);

        await writer.SetOutboundKeysAsync(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: comp.Compresses && comp.UseInAuth, ct);

        byte[] payload = [PacketType.Ignore, 0xBB];
        await writer.WritePacketAsync(PacketType.Ignore, payload, ct);
        ReadResult rr = await pipe.Reader.ReadAsync(ct);
        pipe.Reader.AdvanceTo(rr.Buffer.End);

        Assert.Single(comp.CompressCalls);
    }

    [Fact]
    public async Task Writer_ActivateDelayedCompression_IsIdempotent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: false);
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);

        await writer.SetOutboundKeysAsync(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: false, ct);

        writer.ActivateDelayedCompression();
        writer.ActivateDelayedCompression();

        byte[] payload = [PacketType.Ignore, 0xCC];
        await writer.WritePacketAsync(PacketType.Ignore, payload, ct);
        ReadResult rr = await pipe.Reader.ReadAsync(ct);
        pipe.Reader.AdvanceTo(rr.Buffer.End);

        // Still exactly one Compress call — the second activation is a no-op.
        Assert.Single(comp.CompressCalls);
    }

    // ── Reader side ───────────────────────────────────────────────────

    [Fact]
    public async Task Reader_ZlibOpenSsh_NotDecompressedBeforeActivation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: false);
        byte[] wire = BuildCleartextFramedPacket([PacketType.Ignore, 0x01]);

        var pipe = new Pipe();
        await pipe.Writer.WriteAsync(wire, ct);
        await pipe.Writer.CompleteAsync();

        var reader = new PacketReader(pipe.Reader);
        reader.SetInboundKeys(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: comp.Compresses && comp.UseInAuth);

        RawPacket pkt = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.Ignore, pkt.Type);
        Assert.Empty(comp.DecompressCalls);
    }

    [Fact]
    public async Task Reader_ZlibOpenSsh_DecompressedAfterActivation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: false);
        // RecordableCompression.Decompress is passthrough, so the wire bytes
        // are the same as the unframed payload.
        byte[] wire = BuildCleartextFramedPacket([PacketType.Ignore, 0x02]);

        var pipe = new Pipe();
        await pipe.Writer.WriteAsync(wire, ct);
        await pipe.Writer.CompleteAsync();

        var reader = new PacketReader(pipe.Reader);
        reader.SetInboundKeys(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: comp.Compresses && comp.UseInAuth);

        reader.ActivateDelayedCompression();

        RawPacket pkt = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.Ignore, pkt.Type);
        Assert.Single(comp.DecompressCalls);
    }

    [Fact]
    public async Task Reader_Zlib_DecompressedImmediately_FromNewkeys()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var comp = new RecordableCompression(useInAuth: true);
        byte[] wire = BuildCleartextFramedPacket([PacketType.Ignore, 0x03]);

        var pipe = new Pipe();
        await pipe.Writer.WriteAsync(wire, ct);
        await pipe.Writer.CompleteAsync();

        var reader = new PacketReader(pipe.Reader);
        reader.SetInboundKeys(
            new NoopCipher(), new NoopMac(), comp,
            strictKex: false, compressionActive: comp.Compresses && comp.UseInAuth);

        RawPacket pkt = await reader.ReadPacketAsync(ct);
        Assert.Equal(PacketType.Ignore, pkt.Type);
        Assert.Single(comp.DecompressCalls);
    }

    // ── Helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Builds a cleartext SSH packet (length|padlen|payload|padding) ready to
    /// be fed to a <see cref="PacketReader"/> configured with the no-op
    /// cipher/MAC (which pass bytes through unchanged).
    /// </summary>
    private static byte[] BuildCleartextFramedPacket(byte[] payload)
    {
        // blocksize=8 (NoopCipher), crypt_offset=0 (no etm/aead/aad).
        // 4 + 1 + payload.Length before padding. padding = 8 - ((5 + payload.Length) % 8).
        // Bump by 8 if padding < 4.
        int beforePad = 5 + payload.Length;
        int padding = 8 - (beforePad % 8);
        if (padding < 4)
        {
            padding += 8;
        }

        uint packetLength = (uint)(1 + payload.Length + padding);
        byte[] wire = new byte[4 + 4 + 1 + payload.Length + padding];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(wire, packetLength);
        wire[4] = (byte)padding;
        Buffer.BlockCopy(payload, 0, wire, 5, payload.Length);
        // Remaining bytes are padding; left as zero (the NoopMac doesn't care).
        return wire;
    }

    /// <summary>
    /// An <see cref="ICompression"/> that records every
    /// <see cref="Compress"/>/<see cref="Decompress"/> call and passes bytes
    /// through unchanged. <see cref="Compresses"/> is <c>true</c> so the
    /// per-packet gate at <c>PacketWriter/Reader</c> fires when the
    /// <c>_compressionActive</c> flag is set.
    /// </summary>
    private sealed class RecordableCompression : ICompression
    {
        private readonly bool _useInAuth;

        public RecordableCompression(bool useInAuth) => _useInAuth = useInAuth;

        public string Name => "recordable";
        public bool Compresses => true;
        public bool UseInAuth => _useInAuth;

        public List<byte[]> CompressCalls { get; } = [];
        public List<byte[]> DecompressCalls { get; } = [];

        public void Init(bool compress)
        {
        }

        public void Compress(ReadOnlySpan<byte> src, IBufferWriter<byte> destination)
        {
            byte[] snap = src.ToArray();
            CompressCalls.Add(snap);
            destination.Write(snap);
        }

        public void Decompress(ReadOnlySpan<byte> src, IBufferWriter<byte> destination)
        {
            byte[] snap = src.ToArray();
            DecompressCalls.Add(snap);
            destination.Write(snap);
        }

        public void Dispose()
        {
        }
    }

    private sealed class NoopCipher : ICipher
    {
        public string Name => "noop";
        public int BlockSize => 8;
        public int IvLen => 0;
        public int KeyLen => 0;
        public int AuthTagLen => 0;
        public CipherFlags Flags => CipherFlags.None;
        public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt) { }
        public void Crypt(Span<byte> buf) { }
        public void CryptAead(uint seqno, Span<byte> dest, ReadOnlySpan<byte> src, int payloadLen, int aadLen, bool encrypt) { }
        public bool TryGetLength(uint seqno, ReadOnlySpan<byte> ciphertext, out uint length)
        {
            length = 0;
            return false;
        }

        public void Dispose() { }
    }

    private sealed class NoopMac : IMac
    {
        public string Name => "noop";
        public int MacLen => 0;
        public bool IsEtm => false;
        public void Init(ReadOnlySpan<byte> key) { }
        public void Compute(uint seqno, ReadOnlySpan<byte> data, Span<byte> mac) { }
        public bool Verify(uint seqno, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mac) => true;
        public void Dispose() { }
    }
}
