using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// The inbound SSH packet reader — a 1:1 managed port of libssh2's
/// <c>_libssh2_transport_read</c> + <c>fullpacket</c> (<c>transport.c:425-895</c>),
/// operating over a <see cref="PipeReader"/> instead of the C
/// <c>session-&gt;packet.buf[35000]</c> ring buffer. Owns the inbound sequence
/// number and the per-direction cipher/MAC/compression.
/// </summary>
/// <remarks>
/// <para>
/// One instance handles every packet received in this direction for the life of
/// the negotiated key. After NEWKEYS, <c>KeyExchange</c> calls
/// <see cref="SetInboundKeys"/> to install the new cipher/MAC/compression and
/// reset seqno to 0 (strict-KEX).
/// </para>
/// <para>
/// <b>Five framing modes</b>, dispatched on <c>(encrypted, cipher.Flags, mac.IsEtm)</c>:
/// <list type="bullet">
/// <item><b>Cleartext</b> (pre-NEWKEYS): blocksize=5, no crypto.</item>
/// <item><b>Standard</b> (AES-CBC/CTR + separate HMAC): decrypt first block to
/// learn length, decrypt the remaining blocks, verify MAC over plaintext.</item>
/// <item><b>ETM</b> (hmac-*-etm): length is plaintext; verify MAC over ciphertext;
/// decrypt the body after MAC passes.</item>
/// <item><b>AES-GCM</b>: length is plaintext AAD; AEAD decrypt + tag verify in
/// one <see cref="ICipher.CryptAead"/> call.</item>
/// <item><b>ChaCha20-Poly1305</b>: header key decrypts the length via
/// <see cref="ICipher.TryGetLength"/>; AEAD decrypt + tag verify in one call.</item>
/// </list>
/// </para>
/// <para>
/// <b>Standard cipher length-recovery</b>: the C code decrypts block-by-block
/// as bytes arrive; the first block's decrypt yields the 4-byte length AND
/// advances the cipher's chaining state, so the remaining blocks decrypt
/// correctly. This reader replicates that: the first block is decrypted once
/// (for length), its plaintext is kept, and the remaining blocks are decrypted
/// in a second <see cref="ICipher.Crypt"/> call. The two calls together form one
/// logical packet decrypt — the cipher state advances exactly once per block,
/// matching libssh2's persistent-context model.
/// </para>
/// <para>
/// <b>Bounds checks</b> (DoS guard, before any buffer allocation — verbatim from
/// <c>transport.c:600-665</c>): <c>packet_length &lt; 1</c> →
/// <c>LibSsh2Exception(Decrypt)</c>; <c>packet_length &gt; 40000</c> →
/// <c>LibSsh2Exception(OutOfBoundary)</c>; <c>total_num &gt; 40000 || == 0</c>
/// → <c>LibSsh2Exception(OutOfBoundary)</c>;
/// <c>padding_length &gt; packet_length - 1</c> →
/// <c>LibSsh2Exception(Decrypt)</c>.
/// </para>
/// <para>
/// <b>Integrity rejection</b>: MAC mismatch (standard/ETM) →
/// <c>LibSsh2Exception(InvalidMac)</c>; AEAD tag mismatch →
/// <c>LibSsh2Exception(Decrypt)</c> (thrown by <see cref="ICipher.CryptAead"/>).
/// </para>
/// <para>
/// <b>Leftover bytes</b>: a single <c>PipeReader.ReadAsync</c> may return data
/// for 2+ packets. After consuming one packet, the reader calls
/// <c>AdvanceTo(endOfPacket, examinedToEnd)</c> so leftover bytes stay buffered
/// for the next read (the pipe replaces libssh2's ring-buffer compaction —
/// <c>transport.c:464-513</c>).
/// </para>
/// </remarks>
internal sealed class PacketReader : IAsyncDisposable
{
    private const int MaxPayload = 40000;      // LIBSSH2_PACKET_MAXPAYLOAD (libssh2.h:277)

    private readonly PipeReader _reader;
    private ICipher? _cipher;
    private IMac? _mac;
    private ICompression? _compression;
    private bool _encrypted;
    private bool _strictKex;
    // volatile: written by SshSession.MarkAuthenticated (the userauth flow) and
    // read by ReadPacketAsync (the consumer flow). Mirrors libssh2's per-packet
    // evaluation of session->state & AUTHENTICATED (transport.c:292-295).
    private volatile bool _compressionActive;
    private uint _seqno;

    // ── Rekey counters ─────────────────────────────────
    // Bytes/packets received under the current inbound key. Reset to 0 in
    // SetInboundKeys at the NEWKEYS transition (matching libssh2's
    // transport-layer counters in _libssh2_transport_read). Used by the
    // ChannelRouter's rekey auto-trigger to enforce RFC 4253 §9 limits.
    private long _inboundBytes;
    private long _inboundPackets;

    public PacketReader(PipeReader reader)
    {
        _reader = reader;
    }

    /// <summary>The current inbound sequence number (0-based, increments per packet).</summary>
    public uint Seqno => _seqno;

    /// <summary>
    /// Bytes received under the current inbound key since the last NEWKEYS.
    /// Reset to 0 by <see cref="SetInboundKeys"/>. Consulted by the rekey
    /// auto-trigger.
    /// </summary>
    public long InboundBytes => _inboundBytes;

    /// <summary>
    /// Packets received under the current inbound key since the last NEWKEYS.
    /// Reset to 0 by <see cref="SetInboundKeys"/>. Consulted by the rekey
    /// auto-trigger.
    /// </summary>
    public long InboundPackets => _inboundPackets;

    /// <summary>
    /// Installs the inbound cipher/MAC/compression for the post-NEWKEYS era and
    /// resets <see cref="Seqno"/> to 0 (strict-KEX: the first post-NEWKEYS packet
    /// uses seqno 0 — matching <c>transport.c:342-345</c>). Also resets the rekey
    /// counters to 0 (a new key starts a fresh byte/packet budget per RFC 4253 §9).
    /// </summary>
    public void SetInboundKeys(ICipher cipher, IMac mac, ICompression compression,
        bool strictKex, bool compressionActive)
    {
        _cipher?.Dispose();
        _mac?.Dispose();
        _compression?.Dispose();

        _cipher = cipher;
        _mac = mac;
        _compression = compression;
        _encrypted = true;
        _strictKex = strictKex;
        // Preserve an already-activated delayed compression across rekey —
        // same reasoning as PacketWriter.SetOutboundKeysAsync (the C's
        // AUTHENTICATED bit persists across NEWKEYS).
        _compressionActive = _compressionActive || compressionActive;
        // Seqno resets to 0 only under strict-KEX (Terrapin, transport.c:342-345).
        // For a non-strict rekey the seqno continues across NEWKEYS; a fresh
        // reader/writer is already at 0, so this only matters mid-session.
        if (strictKex)
        {
            _seqno = 0;
        }

        // Rekey counters: a new key resets the byte/packet budget (RFC 4253 §9
        // limits are per-key, not cumulative across the session).
        _inboundBytes = 0;
        _inboundPackets = 0;

        // Clear any stashed partial first-block decrypt from the
        // previous key era. The decrypt was done under the old cipher; reusing
        // it under the new cipher would corrupt the stream.
        _pendingFirstBlock = null;
    }

    /// <summary>
    /// Flips <see cref="_compressionActive"/> to <c>true</c>. Called by
    /// <see cref="SshSession.MarkAuthenticated"/> after a successful userauth.
    /// For <c>zlib</c> (<c>use_in_auth=true</c>) this is a no-op; for
    /// <c>zlib@openssh.com</c> (<c>use_in_auth=false</c>) this is the
    /// delayed-activation transition. Mirrors libssh2's per-packet predicate
    /// <c>(session->state &amp; LIBSSH2_STATE_AUTHENTICATED) ||
    /// session->local.comp->use_in_auth</c> (<c>transport.c:292-295</c>).
    /// </summary>
    /// <remarks>
    /// Idempotent. The flag is marked <c>volatile</c>; the next
    /// <see cref="ReadPacketAsync"/> observes the new value without explicit
    /// synchronization.
    /// </remarks>
    public void ActivateDelayedCompression() => _compressionActive = true;

    /// <summary>
    /// Reads one SSH packet: decrypts, MAC-verifies, decompresses, and returns
    /// the payload (beginning with the <c>SSH_MSG_*</c> type byte). Awaits the
    /// <see cref="PipeReader"/> until a full packet is available.
    /// </summary>
    public async Task<RawPacket> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            ReadResult result = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (result.IsCanceled)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if (result.IsCompleted && result.Buffer.IsEmpty)
            {
                throw new SshException(SshErrorCode.SocketDisconnect,
                    "Pipe completed before a full packet arrived");
            }

            ReadOnlySequence<byte> buffer = result.Buffer;
            if (TryReadPacket(buffer, out RawPacket packet, out SequencePosition consumedTo))
            {
                _reader.AdvanceTo(consumedTo);
                return packet;
            }

            // Not enough data yet — examine the whole buffer (signal the pipe to
            // buffer more) and loop.
            _reader.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    /// <summary>
    /// Tries to read one SSH packet synchronously (non-blocking). Returns
    /// <see langword="true"/> and the packet if a full one is immediately
    /// available in the pipe's buffer; returns <see langword="false"/> if no
    /// full packet is buffered (without blocking). Used by the cooperative
    /// pumper to drain immediately-available packets after
    /// the first blocking read — so the active pumper routes ALL queued data
    /// before yielding the pump-lock, preventing non-pumping waiters from
    /// starving when multiple packets arrived in one batch.
    /// </summary>
    /// <remarks>
    /// Uses <see cref="PipeReader.TryRead"/>; does NOT
    /// block on the pipe. A <c>false</c> return does NOT mean EOF — it just
    /// means no full packet is currently buffered. The caller should fall back
    /// to <see cref="ReadPacketAsync"/> for the next blocking read.
    /// </remarks>
    /// <param name="packet">The packet, if one was read.</param>
    /// <param name="isCompleted">Set to <see langword="true"/> if the pipe is
    /// completed (EOF); the caller should treat this as a disconnect.</param>
    public bool TryReadPacket(out RawPacket packet, out bool isCompleted)
    {
        packet = default;
        isCompleted = false;

        if (!_reader.TryRead(out ReadResult result))
        {
            return false;
        }

        if (result.IsCompleted && result.Buffer.IsEmpty)
        {
            // PipeReader.TryRead enters the "reading in progress"
            // state when it returns true (data OR completed). We MUST call
            // AdvanceTo to clear it, or the next ReadAsync/TryRead throws
            // "Reading is already in progress". The pre-fix code returned here
            // without advancing, which stranded the pipe when DrainAvailablePacketsAsync
            // was called on a completed pipe (e.g., the second channel's open
            // after the test harness completed the inbound pipe).
            _reader.AdvanceTo(result.Buffer.End);
            isCompleted = true;
            return false;
        }

        ReadOnlySequence<byte> buffer = result.Buffer;
        if (TryReadPacket(buffer, out RawPacket pkt, out SequencePosition consumedTo))
        {
            _reader.AdvanceTo(consumedTo);
            packet = pkt;
            return true;
        }

        // Partial packet buffered — don't consume; the next blocking read will
        // fill it out.
        _reader.AdvanceTo(buffer.Start, buffer.End);
        return false;
    }

    private bool TryReadPacket(ReadOnlySequence<byte> buffer, out RawPacket packet,
        out SequencePosition consumedTo)
    {
        packet = default;
        consumedTo = buffer.Start;

        if (!_encrypted)
        {
            return TryReadCleartext(buffer, out packet, out consumedTo);
        }

        ICipher cipher = _cipher!;
        bool isAead = CipherMethods.IsAead(cipher);
        bool etm = _mac is not null && _mac.IsEtm;

        // ── Length recovery ────────────────────────────────────────────
        // Each family recovers the 4-byte packet_length differently.
        uint wireLength;
        int headerBytes;
        byte[]? firstBlockPlain = null; // standard path keeps the decrypted first block.

        if (etm)
        {
            // ETM: 4-byte length is plaintext. transport.c:541-544, 608-613.
            if (buffer.Length < 4)
            {
                return false;
            }

            Span<byte> lenBuf = stackalloc byte[4];
            buffer.Slice(0, 4).CopyTo(lenBuf);
            wireLength = BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
            headerBytes = 4;
        }
        else if (cipher.TryGetLength(_seqno,
            buffer.Slice(0, (int)Math.Min(4, buffer.Length)).ToArray(), out wireLength))
        {
            // ChaCha20-Poly1305 (header-key decrypt) or AES-GCM (length is plaintext AAD).
            headerBytes = 4;
        }
        else
        {
            // Standard (AES-CBC/CTR): length is encrypted in the first block.
            // transport.c:572-598. Decrypt the first block ONCE to learn the
            // length; keep the plaintext (the MAC later covers it). The cipher
            // state advances by one block — the remaining blocks decrypt in a
            // second Crypt call below.
            int blocksize = cipher.BlockSize;
            if (buffer.Length < blocksize)
            {
                return false;
            }

            // Reuse a previously-decrypted first block if present.
            // The previous code unconditionally called cipher.Crypt() here,
            // which advanced the cipher state (CBC IV / CTR counter) by one
            // block. If a partial packet was buffered, the next call would
            // decrypt the SAME first block again — double-advancing the state
            // and corrupting the stream (MAC failure). The non-blocking
            // TryReadPacket made this much more likely: a partial packet
            // arriving would be decrypted twice (once by TryReadPacket via
            // DrainAvailablePacketsAsync, once by the next blocking
            // ReadPacketAsync). The fix stashes the decrypted first block in
            // _pendingFirstBlock and reuses it on the next call so cipher.Crypt
            // is called exactly once per packet.
            if (_pendingFirstBlock is not null && _pendingFirstBlock.Length == blocksize)
            {
                firstBlockPlain = _pendingFirstBlock;
                wireLength = BinaryPrimitives.ReadUInt32BigEndian(firstBlockPlain);
            }
            else
            {
                // First decrypt of this first block. If we end up returning
                // false below (not enough data for the full packet), we'll
                // stash firstBlockPlain in _pendingFirstBlock so the next
                // call skips the decrypt.
                firstBlockPlain = buffer.Slice(0, blocksize).ToArray();
                cipher.Crypt(firstBlockPlain);
                wireLength = BinaryPrimitives.ReadUInt32BigEndian(firstBlockPlain);
            }

            headerBytes = blocksize;
        }

        // ── Bounds check 1: packet_length (transport.c:600-605) ────────
        if (wireLength < 1)
        {
            throw new SshException(SshErrorCode.Decrypt,
                $"packet_length {wireLength} < 1");
        }

        if (wireLength > MaxPayload)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"packet_length {wireLength} > {MaxPayload}");
        }

        // ── Compute total wire bytes (transport.c:608-650) ──────────────
        // For standard (CBC/CTR): the encrypted body is 4 + packet_length
        // bytes (the 4-byte length is inside the first encrypted block), then
        // mac_len MAC bytes. ETM: 4 (plaintext length) + packet_length
        // (ciphertext body) + mac_len. AEAD: 4 + packet_length + auth_len.
        int macLen = !isAead && _mac is not null ? _mac.MacLen : 0;
        int authLen = isAead ? cipher.AuthTagLen : 0;
        int totalWire = etm
            ? 4 + (int)wireLength + macLen
            : isAead
                ? 4 + (int)wireLength + authLen
                : 4 + (int)wireLength + macLen;

        // ── Bounds check 2: total_num (transport.c:665-667) ─────────────
        // C's total_num is the number of bytes following the 5-byte length +
        // padding-length header for standard frames (packet_length - 1 +
        // mac_len, transport.c:627-628) and the full frame for ETM
        // (transport.c:612-613). AES-GCM takes the standard branch too — it
        // does NOT set REQUIRES_FULL_PACKET in libssh2 — where its integrated
        // tag enters total_num as the aesgcm MAC override's mac_len = 16
        // (mac.c:529-537), modeled by authLen below. Only
        // ChaCha20-Poly1305 (REQUIRES_FULL_PACKET) adds the full frame
        // (transport.c:649-650). The bound is LIBSSH2_PACKET_MAXPAYLOAD
        // (40000), NOT the outbound MAX_SSH_PACKET_LEN (35000) buffer
        // constant that was previously (wrongly) applied here — a peer's
        // packet in (35000, 40000] is legal for libssh2 and was being
        // disconnected by the port.
        int totalNum;
        if (etm)
        {
            totalNum = 4 + (int)wireLength + macLen;      // transport.c:612-613
        }
        else if (cipher.Flags.HasFlag(CipherFlags.RequiresFullPacket))
        {
            totalNum = 4 + (int)wireLength + authLen;     // chacha: transport.c:649-650
        }
        else if (isAead)
        {
            totalNum = (int)wireLength - 1 + authLen;     // aes-gcm: transport.c:627-628
        }
        else
        {
            totalNum = (int)wireLength - 1 + macLen;      // standard: transport.c:627-628
        }

        if (totalNum is 0 or > MaxPayload)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"total_num {totalNum} out of bounds");
        }

        if (buffer.Length < totalWire)
        {
            // Not enough data yet for the full packet. Stash the decrypted
            // first block (standard-cipher path only — AEAD/ETM don't decrypt
            // the first block for length recovery, so firstBlockPlain is null
            // for them). On the next call, we reuse it instead of re-decrypting
            // — which would double-advance the cipher state (CBC IV / CTR
            // counter) and corrupt the stream.
            _pendingFirstBlock = firstBlockPlain;
            return false;
        }

        // Full packet available — commit.
        byte[] wire = buffer.Slice(0, totalWire).ToArray();
        consumedTo = buffer.GetPosition(totalWire);

        // Clear any stashed partial (we have the full packet now).
        _pendingFirstBlock = null;

        // ── Per-family decrypt + verify + extract ─────────────────────
        byte[] plaintext;
        int paddingLength;
        if (etm)
        {
            plaintext = ReadEtm(wire, (int)wireLength, macLen, out paddingLength);
        }
        else if (isAead)
        {
            plaintext = ReadAead(wire, (int)wireLength, authLen, out paddingLength);
        }
        else
        {
            plaintext = ReadStandard(wire, (int)wireLength, macLen,
                firstBlockPlain!, out paddingLength);
        }

        // ── Bounds check 3: padding_length (transport.c:620-623, 819-821) ──
        if (paddingLength > (int)wireLength - 1)
        {
            throw new SshException(SshErrorCode.Decrypt,
                $"padding_length {paddingLength} > packet_length-1 {wireLength - 1}");
        }

        // ── Strip padding (transport.c:289) ────────────────────────────
        int payloadLen = (int)wireLength - 1 - paddingLength;
        byte[] payload = new byte[payloadLen];
        Buffer.BlockCopy(plaintext, 0, payload, 0, payloadLen);

        // ── Decompress (transport.c:292-318) ───────────────────────────
        // Per-packet predicate (transport.c:292-295): active iff encrypted
        // AND (authenticated OR use_in_auth). The flag is set at NEWKEYS from
        // (Compresses && UseInAuth) by SetInboundKeys, then flipped to true
        // after auth by ActivateDelayedCompression (called from
        // SshSession.MarkAuthenticated for zlib@openssh.com).
        if (_compressionActive && _compression is not null && _compression.Compresses)
        {
            payload = _compression.Decompress(payload);
        }

        int type = payload.Length > 0 ? payload[0] : -1;
        uint seqno = _seqno;

        // ── seqno increment + strict-KEX NEWKEYS reset (transport.c:286, 342-345) ──
        _seqno++;
        if (_strictKex && type == PacketType.NewKeys)
        {
            _seqno = 0;
        }

        // ── Rekey counters ───────────────────────────────
        // Bump wire-byte + packet counts for the inbound direction. Reset to 0
        // in SetInboundKeys at the NEWKEYS transition. totalWire covers the
        // full encrypted frame (length + ciphertext + MAC/tag), which is what
        // RFC 4253 §9's sequence-space limit concerns.
        _inboundBytes += totalWire;
        _inboundPackets++;

        packet = new RawPacket(type, payload, seqno);
        return true;
    }

    /// <summary>
    /// Stashed first-block plaintext from a previous partial read of a standard
    /// cipher packet. Reused on the next call so the first block is decrypted
    /// exactly once (matching libssh2's <c>p->init[]</c> persistence across
    /// EAGAIN returns). <c>null</c> when no partial is pending.
    /// </summary>
    private byte[]? _pendingFirstBlock;

    private bool TryReadCleartext(ReadOnlySequence<byte> buffer, out RawPacket packet,
        out SequencePosition consumedTo)
    {
        packet = default;
        consumedTo = buffer.Start;

        if (buffer.Length < 5)
        {
            return false;
        }

        Span<byte> hdr = stackalloc byte[5];
        buffer.Slice(0, 5).CopyTo(hdr);
        uint wireLength = BinaryPrimitives.ReadUInt32BigEndian(hdr);
        byte paddingLength = hdr[4];

        if (wireLength < 1)
        {
            throw new SshException(SshErrorCode.Decrypt,
                $"cleartext packet_length {wireLength} < 1");
        }

        if (wireLength > MaxPayload)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"cleartext packet_length {wireLength} > {MaxPayload}");
        }

        // Cleartext standard frame: total_num = packet_length - 1
        // (transport.c:627-628 with mac_len 0), bounded by
        // LIBSSH2_PACKET_MAXPAYLOAD (40000); total_num == 0 (a zero-payload
        // packet_length == 1) is rejected like the C (transport.c:665-667).
        int totalWire = 4 + (int)wireLength;
        int totalNum = (int)wireLength - 1;
        if (totalNum is 0 or > MaxPayload)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"cleartext total_num {totalNum} out of bounds");
        }

        if (buffer.Length < totalWire)
        {
            return false;
        }

        if (paddingLength > (int)wireLength - 1)
        {
            throw new SshException(SshErrorCode.Decrypt,
                $"cleartext padding_length {paddingLength} > packet_length-1 {wireLength - 1}");
        }

        int payloadLen = (int)wireLength - 1 - paddingLength;
        byte[] payload = new byte[payloadLen];
        buffer.Slice(5, payloadLen).CopyTo(payload);

        int type = payload.Length > 0 ? payload[0] : -1;
        uint seqno = _seqno;
        _seqno++;
        if (_strictKex && type == PacketType.NewKeys)
        {
            _seqno = 0;
        }

        // Rekey counters — same accounting as the encrypted path above.
        _inboundBytes += totalWire;
        _inboundPackets++;

        packet = new RawPacket(type, payload, seqno);
        consumedTo = buffer.GetPosition(totalWire);
        return true;
    }

    /// <summary>
    /// Standard (AES-CBC/CTR + separate HMAC): the first block was already
    /// decrypted for length recovery (its plaintext in <paramref name="firstBlockPlain"/>);
    /// decrypt the remaining blocks, verify MAC over the full plaintext body,
    /// strip padding. transport.c:197-229 (MAC), 741-832 (decrypt).
    /// </summary>
    private byte[] ReadStandard(byte[] wire, int wireLength, int macLen,
        byte[] firstBlockPlain, out int paddingLength)
    {
        ICipher cipher = _cipher!;
        int blocksize = cipher.BlockSize;
        int bodyLen = 4 + wireLength; // full decrypted plaintext (length+padlen+payload+padding)

        // Padding sanity check FIRST (transport.c:620-623): the padding byte
        // lives at firstBlockPlain[4] and C rejects it before the first-block
        // guard below — a hostile packet_length 1-11 must surface DECRYPT
        // here, not a raw copy exception.
        if (firstBlockPlain[4] > wireLength - 1)
        {
            throw new SshException(SshErrorCode.Decrypt,
                $"padding_length {firstBlockPlain[4]} > packet_length-1 {wireLength - 1}");
        }

        // First-block guard (transport.c:680-696): C refuses a standard packet
        // whose total_num (packet_length - 1 + mac_len) cannot hold the
        // blocksize - 5 bytes it copies out of the first decrypted block —
        // i.e. bodyLen + macLen < blocksize. A hostile decrypted packet_length
        // 1-11 (blocksize 16) gets this far past the earlier bounds checks;
        // without the guard the 16-byte first-block copy below would throw a
        // raw ArgumentException into the transport instead of the C's
        // OUT_OF_BOUNDARY (parity fix).
        if (bodyLen + macLen < blocksize)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"packet body {bodyLen} + mac {macLen} bytes < blocksize {blocksize}");
        }

        // Build the full plaintext body: first block (already decrypted) +
        // remaining blocks (decrypt now). The cipher state advanced by one
        // block during length recovery; the remaining decrypt continues from
        // there, matching libssh2's incremental decrypt. The copy is clamped
        // to bodyLen: with a MAC in play C accepts sub-block bodies
        // (bodyLen < blocksize <= bodyLen + macLen) — the body then lies
        // entirely inside the first block and nothing is left to decrypt.
        byte[] body = new byte[bodyLen];
        Buffer.BlockCopy(firstBlockPlain, 0, body, 0, Math.Min(blocksize, bodyLen));

        if (bodyLen > blocksize)
        {
            int remaining = bodyLen - blocksize;
            byte[] rest = new byte[remaining];
            Buffer.BlockCopy(wire, blocksize, rest, 0, remaining);
            cipher.Crypt(rest);
            Buffer.BlockCopy(rest, 0, body, blocksize, remaining);
        }

        // MAC over BE32(seqno) ‖ body (full plaintext: length+padlen+payload+padding).
        // transport.c:197-229.
        if (macLen > 0)
        {
            Span<byte> macExpected = stackalloc byte[macLen];
            _mac!.Compute(_seqno, body, macExpected);
            ReadOnlySpan<byte> macWire = wire.AsSpan(bodyLen, macLen);
            if (!CryptographicOperations.FixedTimeEquals(macExpected, macWire))
            {
                throw new SshException(SshErrorCode.InvalidMac,
                    "Standard MAC mismatch");
            }
        }

        paddingLength = body[4];
        // Return the payload starting after the 4-byte length + 1-byte padlen
        // (body[5..]) so TryReadPacket's payload extraction is uniform with the
        // other families (which also return plaintext starting at the type byte).
        byte[] shifted = new byte[bodyLen - 5];
        Buffer.BlockCopy(body, 5, shifted, 0, bodyLen - 5);
        return shifted;
    }

    /// <summary>
    /// ETM (hmac-*-etm): length is plaintext; verify MAC over the ciphertext
    /// (incl. the plaintext length field); decrypt the body (skipping the 4-byte
    /// length); strip padding. transport.c:206-279.
    /// </summary>
    private byte[] ReadEtm(byte[] wire, int wireLength, int macLen,
        out int paddingLength)
    {
        ICipher cipher = _cipher!;

        // MAC over BE32(seqno) ‖ wire[0..4+wireLength-1] (plaintext length +
        // ciphertext body). transport.c:206-213.
        if (macLen > 0)
        {
            Span<byte> macExpected = stackalloc byte[macLen];
            _mac!.Compute(_seqno, wire.AsSpan(0, 4 + wireLength), macExpected);
            ReadOnlySpan<byte> macWire = wire.AsSpan(4 + wireLength, macLen);
            if (!CryptographicOperations.FixedTimeEquals(macExpected, macWire))
            {
                throw new SshException(SshErrorCode.InvalidMac,
                    "ETM MAC mismatch");
            }
        }

        // Decrypt the body (skip the 4 plaintext length bytes). transport.c:235-279.
        byte[] body = new byte[wireLength];
        Buffer.BlockCopy(wire, 4, body, 0, wireLength);
        cipher.Crypt(body.AsSpan(0, wireLength));

        // The first decrypted byte is padding_length (transport.c:260).
        paddingLength = body[0];
        // The payload starts at body[1] (after padding_length byte). Shift left
        // by 1 (transport.c:281-283) so the returned body starts at the type byte.
        byte[] shifted = new byte[wireLength - 1];
        Buffer.BlockCopy(body, 1, shifted, 0, wireLength - 1);
        return shifted;
    }

    /// <summary>
    /// AEAD (AES-GCM, ChaCha20-Poly1305): single CryptAead call verifies the
    /// tag and decrypts. The 4-byte length is AAD (GCM) or header-key-encrypted
    /// (ChaCha). transport.c:791-821 + fullpacket ChaCha path.
    /// </summary>
    private byte[] ReadAead(byte[] wire, int wireLength, int authLen,
        out int paddingLength)
    {
        ICipher cipher = _cipher!;
        int aadLen = 4;
        int payloadLen = wireLength; // = 1 (padlen) + payload + padding
        byte[] dest = new byte[aadLen + payloadLen];
        // On decrypt, CryptAead reads src = [aadLen+payloadLen ciphertext] +
        // [authLen tag] (the tag is at wire[aadLen+payloadLen..+authLen-1]).
        // src must span the full aadLen + payloadLen + authLen bytes.
        cipher.CryptAead(_seqno, dest, wire.AsSpan(0, aadLen + payloadLen + authLen),
            payloadLen, aadLen, encrypt: false);

        // The first byte of the decrypted body is padding_length (transport.c:281).
        paddingLength = dest[aadLen];
        // Payload starts after the padding_length byte.
        byte[] body = new byte[payloadLen - 1];
        Buffer.BlockCopy(dest, aadLen + 1, body, 0, payloadLen - 1);
        return body;
    }

    public ValueTask DisposeAsync()
    {
        _cipher?.Dispose();
        _mac?.Dispose();
        _compression?.Dispose();
        return default;
    }
}
