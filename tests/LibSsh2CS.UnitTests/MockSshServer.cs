using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Crypto;
using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// A minimal mock SSH server over an in-memory pipe pair, sufficient to drive
/// <see cref="SshSession.HandshakeAsync"/> to completion (banner → KEXINIT →
/// KEX → NEWKEYS → SERVICE_REQUEST → SERVICE_ACCEPT). Used by increment 3.4
/// tests that need a post-handshake <see cref="SshSession"/> without a live
/// TCP peer.
/// </summary>
/// <remarks>
/// <para>
/// The server speaks curve25519-sha256 + aes256-ctr + hmac-sha2-256 +
/// ssh-ed25519, the same negotiated set the existing
/// <c>RunExchangeFlowTests</c> mock uses. The server's host key is an
/// Ed25519 keypair generated fresh per handshake, and the KEXDH_REPLY
/// carries a REAL Ed25519 signature over the exchange hash — the session
/// verifies the hostkey signature internally on every exchange (parity with
/// libssh2's kex.c:746-751), so the mock must sign for real.
/// </para>
/// <para>
/// After <see cref="RunAsync"/> completes, the pipes stay open for channel ops
/// and rekey tests. <see cref="Dispose"/> completes both pipes.
/// </para>
/// </remarks>
internal sealed class MockSshServer : IDisposable
{
    private readonly Pipe _c2s = new();
    private readonly Pipe _s2c = new();

    /// <summary>The negotiated methods (set after RunAsync completes the KEXINIT parse).</summary>
    public NegotiatedMethods? Negotiated { get; private set; }

    /// <summary>Corrupts the reply signature to test rejection before host trust.</summary>
    public bool CorruptSignature { get; set; }

    /// <summary>
    /// When true, the mock sends a cleartext SSH_MSG_IGNORE packet BEFORE its
    /// KEXINIT — a pre-KEXINIT packet-injection probe: under strict KEX
    /// the KEXINIT must be the server's very first packet, so the injected
    /// IGNORE must be detected via the KEXINIT's nonzero seqno.
    /// </summary>
    public bool SendIgnoreBeforeKexInit { get; set; }

    /// <summary>
    /// When set, sent instead of the default banner (a banner without a
    /// trailing newline — e.g. an 8192-byte line — must terminate the banner
    /// read loop when the buffer fills, like the C's banner_receive).
    /// </summary>
    public string? BannerOverride { get; set; }

    /// <summary>The server's Ed25519 host key (32-byte public seed).</summary>
    public byte[] HostKeySeed { get; } = new byte[32];

    /// <summary>The server's host key blob (K_S, as sent in KEXDH_REPLY).</summary>
    public byte[] HostKeyBlob { get; private set; } = Array.Empty<byte>();

    /// <summary>The shared secret K (BigInteger), set after the KEX completes.</summary>
    public System.Numerics.BigInteger? SharedSecret { get; private set; }

    /// <summary>The exchange hash H, set after the KEX completes.</summary>
    public byte[]? ExchangeHash { get; private set; }

    /// <summary>
    /// Drives the server side to completion: read client banner, send server
    /// banner, exchange KEXINITs, do curve25519 KEX, send NEWKEYS, answer the
    /// SERVICE_REQUEST with SERVICE_ACCEPT. Returns when the session is
    /// authenticated-ready (no further server-side packet handling).
    /// </summary>
    /// <param name="clientBanner">The client banner to expect.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public async Task RunAsync(string clientBanner, CancellationToken cancellationToken)
    {
        // Generate the Ed25519 host keypair (random seed for the mock).
        RandomNumberGenerator.Fill(HostKeySeed);

        var serverWriter = new PacketWriter(_s2c.Writer);
        var serverReader = new PacketReader(_c2s.Reader);
        ServerPacketWriter = serverWriter;
        ServerPacketReader = serverReader;

        // ── Banner exchange (server speaks first) ─────────────────────────
        // Send our banner, then read the client's.
        string serverBanner = BannerOverride ?? "SSH-2.0-mock-sshd";
        byte[] sb = Encoding.ASCII.GetBytes(serverBanner + (BannerOverride is null ? "\r\n" : ""));
        await _s2c.Writer.WriteAsync(sb, cancellationToken).ConfigureAwait(false);
        await _s2c.Writer.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read the client banner (byte-by-byte until \n).
        string gotClientBanner = await ReadLineAsync(_c2s.Reader, cancellationToken).ConfigureAwait(false);
        if (gotClientBanner != clientBanner)
        {
            throw new InvalidOperationException(
                $"client banner mismatch: expected '{clientBanner}', got '{gotClientBanner}'");
        }

        // ── KEXINIT exchange ──────────────────────────────────────────────
        RawPacket clientKexInitPkt = await serverReader.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
        byte[] clientKexInit = clientKexInitPkt.Payload;

        // Optional pre-KEXINIT IGNORE injection (see the property).
        if (SendIgnoreBeforeKexInit)
        {
            byte[] ignorePayload = [(byte)PacketType.Ignore, 0, 0, 0, 1, (byte)'x'];
            await serverWriter.WritePacketAsync(PacketType.Ignore, ignorePayload, cancellationToken)
                .ConfigureAwait(false);
        }

        // Server KEXINIT: a server-style payload. The client's BuildKexInit
        // prepends ext-info-c and kex-strict-c-v00@openssh.com to its kex list;
        // a real server does NOT send ext-info-c (it's client-only) but DOES
        // send kex-strict-s-v00@openssh.com (Terrapin, OpenSSH 9.6+). We build
        // a server-style KEXINIT manually so Negotiate picks a real algorithm
        // (not the pseudo-ext-info-c).
        byte[] serverKexInit = BuildServerKexInit();
        await serverWriter.WritePacketAsync(PacketType.KexInit, serverKexInit, cancellationToken)
            .ConfigureAwait(false);

        KexInit clientInit = KeyExchange.ParseKexInit(clientKexInit);
        KexInit serverInit = KeyExchange.ParseKexInit(serverKexInit);
        Negotiated = KeyExchange.Negotiate(clientInit, serverInit);

        // ── KEX: curve25519 (read KEXDH_INIT, compute shared secret, send REPLY) ──
        RawPacket init = await serverReader.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
        AssertType(PacketType.KexDhInit, init);
        byte[] qC = ExtractString(init.Payload, 1);

        var serverKp = new Curve25519KeyExchange();
        byte[] qS = serverKp.PublicKey;
        byte[] kBytes = serverKp.ComputeSharedSecret(qC);
        SharedSecret = Endian.BigIntegerFromBigEndian(kBytes);

        // Ed25519 host key blob: [string "ssh-ed25519"][string 32-byte-pubkey].
        // The pubkey is derived from the seed exactly as Ed25519.Sign derives
        // it (RFC 8032 §5.1.5: A = [a]B with a = clamp(SHA-512(seed)[0..32])).
        // The signature below is a REAL Ed25519 signature over H: the session
        // now always verifies the hostkey signature internally (parity with
        // libssh2's kex.c:746-751 sig_verify), so
        // a fake signature blob would fail every handshake.
        byte[] h = SHA512.HashData(HostKeySeed);
        byte[] scalar = h.AsSpan(0, 32).ToArray();
        scalar[0] &= 0b1111_1000;
        scalar[31] &= 0b0111_1111;
        scalar[31] |= 0b0100_0000;
        Ge25519ScalarMult.Base(out GeP3 aB, scalar);
        byte[] pub = new byte[32];
        Ge25519Ops.P3ToBytes(pub, in aB);
        CryptographicOperations.ZeroMemory(h);
        CryptographicOperations.ZeroMemory(scalar);
        HostKeyBlob = ConcatStrings([
            Encoding.ASCII.GetBytes("ssh-ed25519"),
            pub,
        ]);

        ExchangeHash = KeyExchange.ComputeExchangeHash(
            Negotiated.Kex,
            Encoding.ASCII.GetBytes(clientBanner),
            Encoding.ASCII.GetBytes(serverBanner),
            clientKexInit,
            serverKexInit,
            HostKeyBlob,
            qC,
            qS,
            SharedSecret.Value);

        // Real Ed25519 signature over the exchange hash (see above).
        byte[] sig = Ed25519.Sign(HostKeySeed, ExchangeHash);
        if (CorruptSignature)
        {
            sig[0] ^= 1;
        }
        byte[] sigBlob = ConcatStrings([
            Encoding.ASCII.GetBytes("ssh-ed25519"),
            sig,
        ]);

        byte[] replyPayload = BuildKexReply(HostKeyBlob, qS, sigBlob);
        await serverWriter.WritePacketAsync(PacketType.KexDhReply, replyPayload, cancellationToken)
            .ConfigureAwait(false);

        // ── NEWKEYS ───────────────────────────────────────────────────────
        AssertType(PacketType.NewKeys,
            await serverReader.ReadPacketAsync(cancellationToken).ConfigureAwait(false));
        await serverWriter.WritePacketAsync(PacketType.NewKeys,
            new byte[] { (byte)PacketType.NewKeys }, cancellationToken).ConfigureAwait(false);

        // Install keys so the post-NEWKEYS packets round-trip encrypted.
        // The mock is the SERVER. The server's writer (server→client) uses the
        // CLIENT's INBOUND keys (B/D/F): isOutbound=false means "this is the
        // client's inbound direction." The server's reader (client→server)
        // uses the CLIENT's OUTBOUND keys (A/C/E): isOutbound=true means
        // "this is the client's outbound direction."
        await InstallKeys(serverWriter, Negotiated, SharedSecret.Value, ExchangeHash, isOutbound: false, cancellationToken);
        await InstallKeys(serverReader, Negotiated, SharedSecret.Value, ExchangeHash, isOutbound: true, cancellationToken);

        // ── SERVICE_REQUEST → SERVICE_ACCEPT ─────────────────────────────
        RawPacket svcReq = await serverReader.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
        AssertType(PacketType.ServiceRequest, svcReq);
        // Echo "ssh-userauth" back in the SERVICE_ACCEPT.
        byte[] svc = Encoding.ASCII.GetBytes("ssh-userauth");
        byte[] svcAccept = new byte[1 + 4 + svc.Length];
        svcAccept[0] = (byte)PacketType.ServiceAccept;
        BinaryPrimitives.WriteUInt32BigEndian(svcAccept.AsSpan(1, 4), (uint)svc.Length);
        Buffer.BlockCopy(svc, 0, svcAccept, 5, svc.Length);
        await serverWriter.WritePacketAsync(PacketType.ServiceAccept, svcAccept, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>The client→server pipe (the client writes here; the mock reads).</summary>
    public PipeWriter ClientWriter => _c2s.Writer;

    /// <summary>The server→client pipe (the mock writes here; the client reads).</summary>
    public PipeReader ClientReader => _s2c.Reader;

    /// <summary>The client's outbound pipe writer (for channel-test reuse after handshake).</summary>
    public PipeWriter ServerWriter => _s2c.Writer;

    /// <summary>The client's inbound pipe reader (server-side, for channel-test reuse).</summary>
    public PipeReader ServerReader => _c2s.Reader;

    /// <summary>
    /// The server's <see cref="PacketWriter"/> (encrypted post-NEWKEYS). Use this
    /// (NOT <see cref="ServerWriter"/>) to send post-handshake packets to the
    /// client — the raw <see cref="ServerWriter"/> is the underlying pipe and
    /// bypasses the cipher/MAC.
    /// </summary>
    public PacketWriter? ServerPacketWriter { get; private set; }

    /// <summary>
    /// The server's <see cref="PacketReader"/> (encrypted post-NEWKEYS). Use this
    /// (NOT <see cref="ServerReader"/>) to read post-handshake packets from the
    /// client.
    /// </summary>
    public PacketReader? ServerPacketReader { get; private set; }

    public void Dispose()
    {
        try
        {
            _c2s.Writer.Complete();
        }
        catch (InvalidOperationException) { }
        try
        {
            _s2c.Writer.Complete();
        }
        catch (InvalidOperationException) { }
        try
        {
            _c2s.Reader.Complete();
        }
        catch (InvalidOperationException) { }
        try
        {
            _s2c.Reader.Complete();
        }
        catch (InvalidOperationException) { }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a server-style KEXINIT payload: includes
    /// <c>kex-strict-s-v00@openssh.com</c> (Terrapin) but NOT
    /// <c>ext-info-c</c> (client-only). Mirrors a real OpenSSH server's KEXINIT.
    /// </summary>
    private static byte[] BuildServerKexInit()
    {
        using var ms = new MemoryStream(2048);
        ms.WriteByte((byte)PacketType.KexInit);

        // 16-byte random cookie.
        byte[] cookie = new byte[16];
        RandomNumberGenerator.Fill(cookie);
        ms.Write(cookie, 0, 16);

        // KEX list: kex-strict-s + the same in-scope algorithms the client offers.
        string[] kexList = ["kex-strict-s-v00@openssh.com", "curve25519-sha256",
            "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
            "diffie-hellman-group14-sha256"];
        WriteNameList(ms, kexList);
        // Hostkey list: ssh-ed25519 ONLY for the non-ecdsa names (the client's
        // default preference order is ecdsa-* first, so any ecdsa entry here
        // would win the client-pref-first negotiation and the mock would need
        // an ECDSA keypair + DER→r/s conversion. Restricting the server list
        // to ssh-ed25519 (then rsa) pins the negotiated type to Ed25519, which
        // the mock signs with the in-port Ed25519.Sign.
        WriteNameList(ms, ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]);
        WriteNameList(ms, ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"]);
        WriteNameList(ms, ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"]);
        WriteNameList(ms, ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]);
        WriteNameList(ms, ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]);
        WriteNameList(ms, ["none", "zlib", "zlib@openssh.com"]);
        WriteNameList(ms, ["none", "zlib", "zlib@openssh.com"]);
        WriteNameList(ms, [""]);
        WriteNameList(ms, [""]);

        // first_kex_packet_follows = false.
        ms.WriteByte(0);

        // reserved uint32 = 0.
        Span<byte> reserved = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(reserved, 0u);
        ms.Write(reserved);

        return ms.ToArray();
    }

    private static void WriteNameList(Stream ms, string[] names)
    {
        string joined = string.Join(",", names);
        byte[] bytes = Encoding.ASCII.GetBytes(joined);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)bytes.Length);
        ms.Write(len);
        ms.Write(bytes);
    }

    private static async Task<string> ReadLineAsync(PipeReader reader, CancellationToken ct)
    {
        var sb = new StringBuilder();
        while (true)
        {
            ReadResult result = await reader.ReadAsync(ct).ConfigureAwait(false);
            if (result.IsCompleted && result.Buffer.IsEmpty)
            {
                throw new EndOfStreamException("EOF reading banner");
            }

            ReadOnlySequence<byte> buffer = result.Buffer;
            SequencePosition? nlPos = buffer.PositionOf((byte)'\n');
            if (nlPos is null)
            {
                // Consume what we have so far; keep accumulating.
                sb.Append(Encoding.ASCII.GetString(buffer));
                reader.AdvanceTo(buffer.End);
                continue;
            }

            ReadOnlySequence<byte> lineBytes = buffer.Slice(0, nlPos.Value);
            string line = Encoding.ASCII.GetString(lineBytes).TrimEnd('\r', '\n');
            reader.AdvanceTo(buffer.GetPosition(1, nlPos.Value));
            return line;
        }
    }

    private static void AssertType(int expected, RawPacket pkt)
    {
        if (pkt.Type != expected)
        {
            throw new InvalidOperationException($"expected packet type {expected}, got {pkt.Type}");
        }
    }

    private static byte[] ExtractString(byte[] data, int off)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(off, 4));
        return data.AsSpan(off + 4, (int)len).ToArray();
    }

    private static byte[] ConcatStrings(byte[][] parts)
    {
        int total = parts.Sum(p => 4 + p.Length);
        byte[] buf = new byte[total];
        int o = 0;
        foreach (byte[] p in parts)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(o, 4), (uint)p.Length);
            Buffer.BlockCopy(p, 0, buf, o + 4, p.Length);
            o += 4 + p.Length;
        }

        return buf;
    }

    private static byte[] BuildKexReply(byte[] hostKey, byte[] qS, byte[] sig)
    {
        int total = 1 + (4 + hostKey.Length) + (4 + qS.Length) + (4 + sig.Length);
        byte[] p = new byte[total];
        p[0] = (byte)PacketType.KexDhReply;
        int o = 1;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(o, 4), (uint)hostKey.Length);
        Buffer.BlockCopy(hostKey, 0, p, o + 4, hostKey.Length);
        o += 4 + hostKey.Length;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(o, 4), (uint)qS.Length);
        Buffer.BlockCopy(qS, 0, p, o + 4, qS.Length);
        o += 4 + qS.Length;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(o, 4), (uint)sig.Length);
        Buffer.BlockCopy(sig, 0, p, o + 4, sig.Length);
        return p;
    }

    private static async Task InstallKeys(object rw, NegotiatedMethods neg,
        System.Numerics.BigInteger k, byte[] h, bool isOutbound,
        CancellationToken cancellationToken)
    {
        string cipherName = isOutbound ? neg.CipherCs : neg.CipherSc;
        string macName = isOutbound ? neg.MacCs : neg.MacSc;
        ICipher cipher = CipherMethods.Create(cipherName)!;
        bool aead = CipherMethods.IsAead(cipher);

        char ivLetter = isOutbound ? 'A' : 'B';
        char keyLetter = isOutbound ? 'C' : 'D';
        char macLetter = isOutbound ? 'E' : 'F';

        byte[] iv = KeyExchange.DeriveKey(neg.Kex, k, h, h, ivLetter, cipher.IvLen);
        byte[] encKey = KeyExchange.DeriveKey(neg.Kex, k, h, h, keyLetter, cipher.KeyLen);
        cipher.Init(encKey, iv, encrypt: isOutbound);

        IMac mac = aead ? MacMethods.Noop : MacMethods.Create(macName)!;
        if (!aead)
        {
            byte[] macKey = KeyExchange.DeriveKey(neg.Kex, k, h, h, macLetter, mac.MacLen);
            mac.Init(macKey);
        }

        ICompression comp = CompressionMethods.Create(neg.CompCs)!;
        comp.Init(compress: false);

        if (rw is PacketWriter w)
        {
            await w.SetOutboundKeysAsync(cipher, mac, comp, strictKex: neg.StrictKex, compressionActive: false,
                cancellationToken);
        }
        else if (rw is PacketReader r)
        {
            r.SetInboundKeys(cipher, mac, comp, strictKex: neg.StrictKex, compressionActive: false);
        }
    }
}
