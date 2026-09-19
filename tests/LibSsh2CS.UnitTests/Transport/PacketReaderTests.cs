using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Fixture-driven tests for <see cref="PacketReader"/>. For each captured
/// framing mode, the committed fixtures (produced by the libssh2 capture
/// harness — see <c>Capture/capture-packets.py</c>) provide the outbound
/// ciphertext + plaintext + the 6 derived keys. The reader is configured with
/// the local keys (A=IV, C=enc, E=MAC) and seqno=0, then fed the ciphertext;
/// it must produce the exact plaintext, proving the 1:1 framing parity with
/// libssh2.
/// </summary>
/// <remarks>
/// <para>
/// The oracle is the OUTBOUND (client→server) stream: libssh2 encrypted the
/// plaintext with the local keys A/C/E, and we decrypt it back. This validates
/// the reader's full path (length recovery → decrypt → MAC/AEAD verify →
/// decompress → strip padding) against real libssh2-produced ciphertext for
/// all five framing modes.
/// </para>
/// <para>
/// Note: MSBuild rewrites hyphens in fixture <em>folder</em> names to
/// underscores, so the embedded
/// resource name for <c>aes256-ctr_std</c> is <c>aes256_ctr_std</c>. The
/// <see cref="ModeResource"/> helper applies that mapping.
/// </para>
/// </remarks>
public class PacketReaderTests
{
    // The 4 encrypted framing modes (cleartext has no keys and is tested
    // separately via its own plaintext-only fixture).
    public static IEnumerable<object[]> EncryptedModes => new[]
    {
        new object[] { "aes256-ctr_std" },
        new object[] { "aes256-ctr_etm" },
        new object[] { "aes256-gcm" },
        new object[] { "chacha20-poly1305" },
    };

    // ── Round-trip: reader decrypts the oracle ciphertext to the oracle plaintext ──

    [Theory]
    [MemberData(nameof(EncryptedModes))]
    public async Task Read_DecryptsOracleCiphertext_ToOraclePlaintext(string mode)
    {
        PacketFixture fx = LoadFixture(mode);
        var reader = new PacketReader(BuildPipeWith(fx));
        ConfigureReader(reader, fx);

        // The oracle committed one RawPacket per outbound packet (post-NEWKEYS).
        // Read them all and assert each matches the fixture plaintext byte-for-byte.
        for (int i = 0; i < fx.Packets.Count; i++)
        {
            RawPacket got = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
            byte[] expected = fx.Packets[i].Plaintext;
            Assert.True(got.Payload.Length > 0, $"packet {i}: empty payload");
            Assert.Equal(expected, got.Payload);
            // seqno starts at 0 post-NEWKEYS and increments per packet (matches
            // the oracle, which captured from seqno 0).
            Assert.Equal((uint)i, got.Seqno);
        }
    }

    // ── Bounds checks (DoS guard) ──────────────────────────────────────

    [Fact]
    public async Task Read_RejectsPacketLengthZero_Standard()
    {
        // Fabricate a standard-cipher packet with wire packet_length = 0.
        PacketFixture fx = LoadFixture("aes256-ctr_std");
        var reader = new PacketReader(BuildPipeWith(fx));
        ConfigureReader(reader, fx);

        // We can't easily inject a malformed ciphertext without decrypting the
        // real one; instead, test the bounds check at the cleartext layer where
        // we control the bytes. The encrypted-path bounds check is exercised by
        // the same code (TryReadPacket), so a cleartext test validates the logic.
        var plainReader = new PacketReader(BuildPipeWithBytes(ZeroLengthPacketCleartext()));
        SshException? ex = null;
        try
        {
            await plainReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    [Fact]
    public async Task Read_RejectsPacketLengthOver40000_Cleartext()
    {
        // Cleartext packet with packet_length = 40001 (one over the limit).
        byte[] wire = new byte[5];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(wire, 40001u);
        wire[4] = 4; // padding_length

        var plainReader = new PacketReader(BuildPipeWithBytes(wire));
        SshException? ex = null;
        try
        {
            await plainReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public async Task Read_RejectsPaddingTooLarge_Cleartext()
    {
        // packet_length = 10, padding_length = 10 (> packet_length - 1 = 9).
        byte[] wire = new byte[4 + 10];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(wire, 10u);
        wire[4] = 10;
        var plainReader = new PacketReader(BuildPipeWithBytes(wire));
        SshException? ex = null;
        try
        {
            await plainReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    // ── Hostile standard-cipher short packets (transport.c:620-623, 680-696) ──

    // A decrypted packet_length of 1-11 leaves the plaintext body
    // (4 + packet_length) shorter than the 16-byte cipher block. C rejects
    // such packets with DECRYPT (padding byte > packet_length - 1) or
    // OUT_OF_BOUNDARY (first block cannot fit total_num); before the parity
    // fix the port's ReadStandard let a raw ArgumentException escape the
    // 16-byte first-block copy instead of an SshException.

    [Fact]
    public async Task Read_StandardShortPacket_NoMac_ThrowsOutOfBoundary()
    {
        // packet_length 7 → body 4 + 7 = 11 bytes < blocksize 16. C:
        // total_num = 6 < blocksize - 5 = 11 → OUT_OF_BOUNDARY
        // (transport.c:680-696). The 5 trailing dummy bytes make the pipe
        // buffer ≥ blocksize so the frame is processed at all.
        byte[] body = BuildStandardBody([60, 61], paddingLength: 4);  // 4 + 1 + 2 + 4 = 11 bytes
        byte[] frame = [.. CtrEncrypt(body), .. new byte[5]];

        var reader = new PacketReader(BuildPipeWithBytes(frame));
        ConfigureCtrReader(reader, mac: null);
        SshException? ex = await ReadCatching(reader);

        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public async Task Read_StandardShortPacket_PaddingTooLarge_ThrowsDecrypt()
    {
        // Hostile padding byte 10 > packet_length - 1 = 6 → DECRYPT
        // (transport.c:620-623), checked before the first-block guard — same
        // order as C.
        byte[] body = new byte[11];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(body, 7u);
        body[4] = 10;
        byte[] frame = [.. CtrEncrypt(body), .. new byte[5]];

        var reader = new PacketReader(BuildPipeWithBytes(frame));
        ConfigureCtrReader(reader, mac: null);
        SshException? ex = await ReadCatching(reader);

        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.Decrypt, ex.ErrorCode);
    }

    [Fact]
    public async Task Read_StandardShortPacket_WrongMac_ThrowsInvalidMac()
    {
        // With a MAC in play C accepts the sub-block body (11 + 32 ≥
        // blocksize 16 — the total_num guard passes) and fails at MAC
        // verification instead. The port must do the same rather than crash
        // on the clamped first-block copy.
        byte[] body = BuildStandardBody([60, 61], paddingLength: 4);
        byte[] frame = [.. CtrEncrypt(body), .. new byte[32]];   // garbage MAC

        IMac mac = MacMethods.Create("hmac-sha2-256")!;
        mac.Init(s_testMacKey);
        var reader = new PacketReader(BuildPipeWithBytes(frame));
        ConfigureCtrReader(reader, mac);
        SshException? ex = await ReadCatching(reader);

        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.InvalidMac, ex.ErrorCode);
    }

    [Fact]
    public async Task Read_StandardShortPacket_ValidMac_Accepts()
    {
        // Full C parity: a short (structurally non-conforming) CTR packet
        // whose MAC is correct over the 11-byte body is ACCEPTED by both C
        // (total_num = 6 + 32 ≥ blocksize - 5) and the port.
        byte[] body = BuildStandardBody([60, 61], paddingLength: 4);
        byte[] tag = new byte[32];
        using (IMac signer = MacMethods.Create("hmac-sha2-256")!)
        {
            signer.Init(s_testMacKey);
            signer.Compute(0, body, tag);   // seqno 0: the reader's first packet
        }

        byte[] frame = [.. CtrEncrypt(body), .. tag];
        IMac mac = MacMethods.Create("hmac-sha2-256")!;
        mac.Init(s_testMacKey);
        var reader = new PacketReader(BuildPipeWithBytes(frame));
        ConfigureCtrReader(reader, mac);

        RawPacket pkt = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0u, pkt.Seqno);
        Assert.Equal(60, pkt.Type);
        Assert.Equal((byte[])[60, 61], pkt.Payload);
    }

    // ── AES-GCM total_num bound (transport.c:627-628, 665-667) ──────────
    // C's AES-GCM total_num is packet_length - 1 + mac_len with the aesgcm
    // MAC override's mac_len = 16 (mac.c:529-537) → p + 15, so packet_length
    // 39985 (p + 15 = 40000) is legal and only 39986+ is OUT_OF_BOUNDARY. The
    // port once applied the ChaCha full-frame formula (4 + p + 16), rejecting
    // 39981-39985 that C accepts (parity fix).

    [Fact]
    public async Task Read_AesGcmPacketLength39985_Accepts()
    {
        const int PacketLength = 39985;
        const int PaddingLength = 4;
        byte[] body = new byte[4 + PacketLength];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(body, (uint)PacketLength);
        body[4] = PaddingLength;
        body[5] = 60;   // SSH_MSG_IGNORE type byte

        byte[] frame = new byte[body.Length + 16];
        ICipher enc = CipherMethods.Create("aes256-gcm@openssh.com")!;
        enc.Init(s_gcmKey, s_gcmIv, encrypt: true);
        enc.CryptAead(0, frame, body, PacketLength, aadLen: 4, encrypt: true);
        enc.Dispose();

        var reader = new PacketReader(BuildPipeWithBytes(frame));
        ConfigureGcmReader(reader);

        RawPacket pkt = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);

        Assert.Equal(60, pkt.Type);
        Assert.Equal(PacketLength - 1 - PaddingLength, pkt.Payload.Length);
    }

    [Fact]
    public async Task Read_AesGcmPacketLength39986_ThrowsOutOfBoundary()
    {
        // p + 15 = 40001 > 40000 → OUT_OF_BOUNDARY (checked before the buffer
        // size test, so 4 header bytes suffice).
        byte[] head = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(head, 39986u);

        var reader = new PacketReader(BuildPipeWithBytes(head));
        ConfigureGcmReader(reader);
        SshException? ex = await ReadCatching(reader);

        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    // ── Leftover-bytes invariant ───────────────────────────────────────

    [Fact]
    public async Task Read_LeftoverBytesRetainedForNextPacket_Cleartext()
    {
        // Two cleartext packets in a single pipe write. The reader must return
        // both, and any trailing partial is held for the next read.
        byte[] p1 = BuildCleartextPacket(50, new byte[] { 1, 2, 3 });
        byte[] p2 = BuildCleartextPacket(51, new byte[] { 4, 5 });
        byte[] both = [.. p1, .. p2];

        var reader = new PacketReader(BuildPipeWithBytes(both));

        RawPacket r1 = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(50, r1.Type);
        Assert.Equal((byte[])[50, 1, 2, 3], r1.Payload);

        RawPacket r2 = await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(51, r2.Type);
        Assert.Equal((byte[])[51, 4, 5], r2.Payload);
    }

    // ── seqno ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Read_SeqnoIncrementsPerPacket_Cleartext()
    {
        byte[] p1 = BuildCleartextPacket(2, new byte[] { 2 });
        byte[] p2 = BuildCleartextPacket(2, new byte[] { 2 });
        byte[] p3 = BuildCleartextPacket(2, new byte[] { 2 });
        byte[] all = [.. p1, .. p2, .. p3];

        var reader = new PacketReader(BuildPipeWithBytes(all));
        Assert.Equal(0u, reader.Seqno);
        await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1u, reader.Seqno);
        await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2u, reader.Seqno);
        await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(3u, reader.Seqno);
    }

    // ── Helpers ────────────────────────────────────────────────────────

    private static PacketFixture LoadFixture(string mode)
        => PacketFixtureLoader.Load(mode);

    private static PipeReader BuildPipeWith(PacketFixture fx)
    {
        var pipe = new Pipe();
        // Concatenate all the ciphertext packets into the pipe in order.
        int total = fx.Packets.Sum(p => p.Ciphertext.Length);
        byte[] all = new byte[total];
        int off = 0;
        foreach (PacketEntry p in fx.Packets)
        {
            Buffer.BlockCopy(p.Ciphertext, 0, all, off, p.Ciphertext.Length);
            off += p.Ciphertext.Length;
        }

        pipe.Writer.WriteAsync(all, TestContext.Current.CancellationToken).AsTask().Wait();
        pipe.Writer.Complete();
        return pipe.Reader;
    }

    private static PipeReader BuildPipeWithBytes(byte[] data)
    {
        var pipe = new Pipe();
        pipe.Writer.WriteAsync(data, TestContext.Current.CancellationToken).AsTask().Wait();
        pipe.Writer.Complete();
        return pipe.Reader;
    }

    private static void ConfigureReader(PacketReader reader, PacketFixture fx)
    {
        // Oracle uses the local (outbound) keys A=IV, C=enc, E=MAC.
        byte[] iv = fx.Keys.GetValueOrDefault("A") ?? Array.Empty<byte>();
        byte[] enc = fx.Keys.GetValueOrDefault("C") ?? Array.Empty<byte>();
        byte[] mac = fx.Keys.GetValueOrDefault("E") ?? Array.Empty<byte>();

        ICipher cipher = CipherMethods.Create(fx.NegotiatedCipher)!;
        IMac macAdapter = fx.IsAead ? MacMethods.Noop : (MacMethods.Create(fx.NegotiatedMac) ?? MacMethods.Noop);
        ICompression comp = CompressionMethods.Create("none")!;

        // ChaCha20-Poly1305 has IvLen=0; AES-GCM IvLen=12; CBC/CTR IvLen=16.
        cipher.Init(enc, iv, encrypt: false);
        if (!fx.IsAead)
        {
            macAdapter.Init(mac);
        }

        comp.Init(compress: false);
        reader.SetInboundKeys(cipher, macAdapter, comp, strictKex: false, compressionActive: false);
    }

    private static byte[] ZeroLengthPacketCleartext()
    {
        byte[] wire = new byte[5];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(wire, 0u);
        wire[4] = 4;
        return wire;
    }

    // Fixed keys/IVs for the hostile-short-packet and GCM-bound tests. Their
    // contents are irrelevant — each frame is self-consistent between the
    // crafting (encrypt) and reading (decrypt) cipher instances.
    private static readonly byte[] s_testKey = new byte[16];    // aes128-ctr key
    private static readonly byte[] s_testIv = new byte[16];     // CTR initial counter
    private static readonly byte[] s_testMacKey = new byte[32]; // hmac-sha2-256 key
    private static readonly byte[] s_gcmKey = new byte[32];     // aes256-gcm key
    private static readonly byte[] s_gcmIv = new byte[12];      // GCM fixed IV prefix

    /// <summary>
    /// Builds a standard-family plaintext body: BE32(packetLength) ‖
    /// paddingLength ‖ payload ‖ zero padding, where
    /// packetLength = payload.Length + 1 + paddingLength.
    /// </summary>
    private static byte[] BuildStandardBody(byte[] payload, byte paddingLength)
    {
        int packetLength = payload.Length + 1 + paddingLength;
        byte[] body = new byte[4 + packetLength];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(body, (uint)packetLength);
        body[4] = paddingLength;
        Buffer.BlockCopy(payload, 0, body, 5, payload.Length);
        return body;
    }

    /// <summary>Encrypts <paramref name="plaintext"/> with aes128-ctr (encrypt
    /// side; CTR is symmetric, but a fresh instance keeps the keystream
    /// aligned with each reader's fresh decrypt instance).</summary>
    private static byte[] CtrEncrypt(byte[] plaintext)
    {
        ICipher cipher = CipherMethods.Create("aes128-ctr")!;
        cipher.Init(s_testKey, s_testIv, encrypt: true);
        cipher.Crypt(plaintext);
        cipher.Dispose();
        return plaintext;
    }

    /// <summary>Configures the reader with aes128-ctr (decrypt) + the given
    /// MAC (<c>null</c> = no MAC). The reader takes ownership of
    /// <paramref name="mac"/>.</summary>
    private static void ConfigureCtrReader(PacketReader reader, IMac? mac)
    {
        ICipher cipher = CipherMethods.Create("aes128-ctr")!;
        cipher.Init(s_testKey, s_testIv, encrypt: false);
        reader.SetInboundKeys(cipher, mac ?? MacMethods.Noop,
            CompressionMethods.Create("none")!, strictKex: false, compressionActive: false);
    }

    /// <summary>Configures the reader with aes256-gcm (decrypt).</summary>
    private static void ConfigureGcmReader(PacketReader reader)
    {
        ICipher cipher = CipherMethods.Create("aes256-gcm@openssh.com")!;
        cipher.Init(s_gcmKey, s_gcmIv, encrypt: false);
        reader.SetInboundKeys(cipher, MacMethods.Noop,
            CompressionMethods.Create("none")!, strictKex: false, compressionActive: false);
    }

    /// <summary>Reads one packet, returning the SshException instead of
    /// throwing (null when the read succeeded).</summary>
    private static async Task<SshException?> ReadCatching(PacketReader reader)
    {
        try
        {
            await reader.ReadPacketAsync(TestContext.Current.CancellationToken);
            return null;
        }
        catch (SshException e)
        {
            return e;
        }
    }

    /// <summary>Builds a single cleartext SSH packet (length|padlen|payload|padding).</summary>
    private static byte[] BuildCleartextPacket(int type, byte[] payload)
    {
        if (payload.Length == 0 || payload[0] != type)
        {
            // Prepend the type byte if the caller didn't.
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
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(wire, (uint)packetLength);
        wire[4] = (byte)padding;
        Buffer.BlockCopy(payload, 0, wire, 5, payload.Length);
        return wire;
    }
}
