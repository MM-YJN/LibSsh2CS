using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Increment 3.4.1 — rekey counters on <see cref="PacketReader"/> and
/// <see cref="PacketWriter"/>. Each direction tracks bytes + packets under the
/// current key; both reset to 0 in <c>SetInboundKeys</c>/<c>SetOutboundKeys</c>
/// at the NEWKEYS transition. The rekey auto-trigger (3.4.4) consults these
/// counters to enforce RFC 4253 §9 limits.
/// </summary>
/// <remarks>
/// Tests use the pre-NEWKEYS cleartext path (no cipher installation) — the
/// counter bumps are independent of encryption, and cleartext keeps the test
/// self-contained (no fixture corpus required). The encrypted-path reset is
/// exercised by passing a throwaway cipher into <c>SetInboundKeys</c>/
/// <c>SetOutboundKeys</c>; the counters reset without sending any packets.
/// </remarks>
public class RekeyCounterTests
{
    // ── PacketReader.InboundBytes / InboundPackets ───────────────────────

    [Fact]
    public async Task Reader_Counters_StartAtZero()
    {
        var reader = new PacketReader(await BuildPipeWithBytesAsync(Array.Empty<byte>()));
        Assert.Equal(0, reader.InboundBytes);
        Assert.Equal(0, reader.InboundPackets);
    }

    [Fact]
    public async Task Reader_Counters_IncrementPerPacket()
    {
        // Two cleartext IGNORE packets back-to-back in the pipe.
        byte[] p1 = BuildCleartextPacket(PacketType.Ignore, [2, 0xAA]);
        byte[] p2 = BuildCleartextPacket(PacketType.Ignore, [2, 0xBB, 0xCC]);
        var reader = new PacketReader(await BuildPipeWithBytesAsync([.. p1, .. p2]));

        RawPacket r1 = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(p1.Length, reader.InboundBytes);
        Assert.Equal(1, reader.InboundPackets);

        RawPacket r2 = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(p1.Length + p2.Length, reader.InboundBytes);
        Assert.Equal(2, reader.InboundPackets);

        Assert.Equal(PacketType.Ignore, r1.Type);
        Assert.Equal(PacketType.Ignore, r2.Type);
    }

    [Fact]
    public async Task Reader_Counters_ResetToZero_InSetInboundKeys()
    {
        // Read one packet to bump counters, then call SetInboundKeys and assert
        // both reset to 0 (matching RFC 4253 §9: per-key budget, not cumulative).
        byte[] pkt = BuildCleartextPacket(PacketType.Ignore, [2]);
        var reader = new PacketReader(await BuildPipeWithBytesAsync(pkt));
        await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(pkt.Length, reader.InboundBytes);
        Assert.Equal(1, reader.InboundPackets);

        reader.SetInboundKeys(
            cipher: new DummyCipher(),
            mac: new DummyMac(),
            compression: new DummyCompression(),
            strictKex: false,
            compressionActive: false);

        Assert.Equal(0, reader.InboundBytes);
        Assert.Equal(0, reader.InboundPackets);
    }

    [Fact]
    public async Task Reader_Counters_AccountWireBytes_IncludingLengthAndPadding()
    {
        // payload = 1 byte (type), cleartext blocksize = 8. Per PacketWriter's
        // padding formula: packet_length = 1 + 1 + 10 = 12, total = 4 + 12 = 16.
        // Counter must record 16 (the full wire frame), not just payload length.
        byte[] pkt = BuildCleartextPacket(PacketType.Ignore, [2]);
        Assert.Equal(16, pkt.Length);
        var reader = new PacketReader(await BuildPipeWithBytesAsync(pkt));
        await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(16, reader.InboundBytes);
    }

    // ── PacketWriter.OutboundBytes / OutboundPackets ─────────────────────

    [Fact]
    public async Task Writer_Counters_StartAtZero()
    {
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);
        Assert.Equal(0, writer.OutboundBytes);
        Assert.Equal(0, writer.OutboundPackets);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task Writer_Counters_IncrementPerPacket()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);

        await writer.WritePacketAsync(PacketType.Ignore, (byte[])[2, 0xAA], cancellationToken);
        long after1 = writer.OutboundBytes;
        Assert.Equal(1, writer.OutboundPackets);
        Assert.True(after1 > 0);

        await writer.WritePacketAsync(PacketType.Ignore, (byte[])[2, 0xBB, 0xCC], cancellationToken);
        long after2 = writer.OutboundBytes;
        Assert.Equal(2, writer.OutboundPackets);
        Assert.True(after2 > after1);

        // Drain the pipe so FlushAsync doesn't deadlock.
        ReadResult rr = await pipe.Reader.ReadAsync(cancellationToken);
        pipe.Reader.AdvanceTo(rr.Buffer.End);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task Writer_Counters_ResetToZero_InSetOutboundKeys()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);

        await writer.WritePacketAsync(PacketType.Ignore, (byte[])[2], cancellationToken);
        Assert.Equal(1, writer.OutboundPackets);
        Assert.True(writer.OutboundBytes > 0);

        await writer.SetOutboundKeysAsync(
            cipher: new DummyCipher(),
            mac: new DummyMac(),
            compression: new DummyCompression(),
            strictKex: false,
            compressionActive: false,
            cancellationToken: cancellationToken);

        Assert.Equal(0, writer.OutboundBytes);
        Assert.Equal(0, writer.OutboundPackets);

        ReadResult rr = await pipe.Reader.ReadAsync(cancellationToken);
        pipe.Reader.AdvanceTo(rr.Buffer.End);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task Writer_Counters_AccountFullFrameLength()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // 1-byte IGNORE payload: total = 16 bytes (see Reader_Counters_AccountWireBytes
        // for the formula). The writer's counter must record the same.
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);
        await writer.WritePacketAsync(PacketType.Ignore, (byte[])[2], cancellationToken);
        Assert.Equal(16, writer.OutboundBytes);

        ReadResult rr = await pipe.Reader.ReadAsync(cancellationToken);
        pipe.Reader.AdvanceTo(rr.Buffer.End);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    // ── Cross-direction independence ─────────────────────────────────────

    [Fact]
    public async Task ReaderAndWriter_CountersAreIndependent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // Reader and writer on the same pipe read/write independently; their
        // counters must not bleed across directions.
        var pipe = new Pipe();
        var writer = new PacketWriter(pipe.Writer);
        var reader = new PacketReader(pipe.Reader);

        // Writer sends 2 packets; reader consumes 1.
        await writer.WritePacketAsync(PacketType.Ignore, (byte[])[2], cancellationToken);
        await writer.WritePacketAsync(PacketType.Ignore, (byte[])[2], cancellationToken);
        Assert.Equal(2, writer.OutboundPackets);
        Assert.Equal(0, reader.InboundPackets);

        _ = await reader.ReadPacketAsync(cancellationToken);
        Assert.Equal(1, reader.InboundPackets);
        Assert.Equal(2, writer.OutboundPackets);

        // Drain so writer's FlushAsync doesn't deadlock.
        ReadResult rr = await pipe.Reader.ReadAsync(cancellationToken);
        pipe.Reader.AdvanceTo(rr.Buffer.End);
        await pipe.Writer.CompleteAsync();
        await pipe.Reader.CompleteAsync();
    }

    // ── Failed reads don't bump counters ────────────────────────────────

    [Fact]
    public async Task Reader_Counter_DoesNotAdvance_OnBoundsRejectedPacket()
    {
        // A packet_length=0 cleartext packet is a bounds-check failure
        // (transport.c:600-605 → SshErrorCode.Decrypt). The counter must NOT
        // advance: the read rejected this packet.
        byte[] malformed = [0, 0, 0, 0, 0];   // length=0, padlen=0 (5 bytes minimum)
        var reader = new PacketReader(await BuildPipeWithBytesAsync(malformed));

        SshException ex = await Assert.ThrowsAsync<SshException>(
            async () => await reader.ReadPacketAsync(TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
        Assert.Equal(0, reader.InboundBytes);
        Assert.Equal(0, reader.InboundPackets);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static async Task<PipeReader> BuildPipeWithBytesAsync(byte[] data)
    {
        var pipe = new Pipe();
        await pipe.Writer.WriteAsync(data, TestContext.Current.CancellationToken);
        await pipe.Writer.CompleteAsync();
        return pipe.Reader;
    }

    /// <summary>
    /// Builds a cleartext SSH packet (length|padlen|payload|padding) carrying
    /// the given payload, whose first byte must equal <paramref name="type"/>.
    /// Mirror of <c>ChannelTestHarness.BuildCleartextPacket</c>.
    /// </summary>
    private static byte[] BuildCleartextPacket(int type, byte[] payload)
    {
        if (payload.Length == 0 || payload[0] != type)
        {
            byte[] withType = new byte[payload.Length + 1];
            withType[0] = (byte)type;
            Buffer.BlockCopy(payload, 0, withType, 1, payload.Length);
            payload = withType;
        }

        // blocksize=8 cleartext. packet_length = payload + 1 + padding.
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

    // ── Throwaway ICipher / IMac / ICompression for SetInboundKeys/SetOutboundKeys ──
    //
    // These exist solely to exercise the counter-reset path without having to
    // install real crypto. They never see any packets (the tests call
    // SetInboundKeys/SetOutboundKeys then assert the counters are 0 — no
    // subsequent read/write goes through them).

    private sealed class DummyCipher : ICipher
    {
        public string Name => "dummy";
        public int BlockSize => 16;
        public int KeyLen => 0;
        public int IvLen => 0;
        public int AuthTagLen => 0;
        public CipherFlags Flags => CipherFlags.None;
        public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt) { }
        public void Crypt(Span<byte> buf) { }
        public void CryptAead(uint seq, Span<byte> dest, ReadOnlySpan<byte> src, int payloadLen, int aadLen, bool encrypt) { }
        public bool TryGetLength(uint seq, ReadOnlySpan<byte> ciphertext, out uint length)
        {
            length = 0;
            return false;
        }
        public void Dispose() { }
    }

    private sealed class DummyMac : IMac
    {
        public string Name => "dummy";
        public int MacLen => 0;
        public bool IsEtm => false;
        public void Init(ReadOnlySpan<byte> key) { }
        public void Compute(uint seq, ReadOnlySpan<byte> data, Span<byte> mac) { }
        public bool Verify(uint seq, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mac) => true;
        public void Dispose() { }
    }

    private sealed class DummyCompression : ICompression
    {
        public string Name => "dummy";
        public bool Compresses => false;
        public bool UseInAuth => false;
        public void Init(bool compress) { }
        public void Compress(ReadOnlySpan<byte> src, IBufferWriter<byte> destination)
            => destination.Write(src);

        public void Decompress(ReadOnlySpan<byte> src, IBufferWriter<byte> destination)
            => destination.Write(src);
        public void Dispose() { }
    }
}
