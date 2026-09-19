using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// The outbound SSH packet framer — a 1:1 managed port of libssh2's
/// <c>_libssh2_transport_send</c> (<c>transport.c:988-1306</c>), operating over
/// a <see cref="PipeWriter"/> instead of the C <c>session-&gt;packet.outbuf[]</c>.
/// Owns the outbound sequence number and the per-direction cipher/MAC/compression.
/// </summary>
/// <remarks>
/// <para>
/// One instance handles every packet sent in this direction for the life of the
/// negotiated key — mirroring libssh2's single persistent
/// <c>session-&gt;local.{crypt,mac,comp}_abstract</c>. After NEWKEYS,
/// <c>KeyExchange</c> calls <see cref="SetOutboundKeysAsync"/> to install the new
/// cipher/MAC/compression; the seqno is reset to 0 there if strict-KEX is active
/// (matching <c>transport.c:1271-1273</c>, which resets AFTER the increment on
/// the NEWKEYS packet itself).
/// </para>
/// <para>
/// <b>Thread safety.</b> <see cref="WritePacketAsync"/> and
/// <see cref="SetOutboundKeysAsync"/> are serialized by an internal
/// <see cref="SemaphoreSlim"/>. This is required by the multi-channel
/// cooperative-pumper model: two channels may call
/// <see cref="SshChannel.WriteAsync"/> concurrently, and the resulting
/// <see cref="WritePacketAsync"/> calls must not interleave their reads of
/// <c>_seqno</c>/<c>_cipher</c>/<c>_mac</c> or their writes to the underlying
/// <see cref="PipeWriter"/>. The lock is held across the full
/// frame+encrypt+flush+seqno-increment sequence so the on-wire ordering matches
/// the call ordering (parity with libssh2's single-threaded transport).
/// </para>
/// <para>
/// <b>Per-family MAC-vs-encrypt order</b> (parity-critical, from the
/// <c>transport.c</c> audit):
/// <list type="bullet">
/// <item><b>Standard</b> (AES-CBC/CTR + separate HMAC): MAC over plaintext →
/// append MAC → encrypt the plaintext portion only (MAC stays clear).</item>
/// <item><b>ETM</b> (hmac-*-etm): encrypt first (skipping the plaintext 4-byte
/// length field) → MAC over ciphertext (incl. the plaintext length field).</item>
/// <item><b>AEAD</b> (AES-GCM, ChaCha20-Poly1305): the cipher produces the tag
/// itself; the 4-byte length is AAD (GCM) or header-key-encrypted (ChaCha).</item>
/// </list>
/// </para>
/// <para>
/// <b>Padding formula</b> (verbatim from <c>transport.c:1130-1149</c>):
/// <code>
/// packet_length = payload_len + 1 + 4   // +1 padlen byte, +4 length field
/// crypt_offset  = (etm || auth_len || (encrypted &amp;&amp; PktLenAad)) ? 4 : 0
/// padding_length = blocksize - ((packet_length - crypt_offset) % blocksize)
/// if (padding_length &lt; 4) padding_length += blocksize
/// </code>
/// </para>
/// </remarks>
internal sealed class PacketWriter : IAsyncDisposable
{
    private readonly PipeWriter _writer;
    private ICipher? _cipher;
    private IMac? _mac;
    private ICompression? _compression;
    // volatile: written by SshSession.MarkAuthenticated (a different async flow
    // than WritePacketAsync) and read here at the start of each packet write.
    // Matches libssh2's per-packet evaluation of session->state & AUTHENTICATED
    // (transport.c:1060-1063) without needing the write lock on the auth path.
    private bool _encrypted;
    private volatile bool _compressionActive;
    private uint _seqno;
    private bool _strictKex;

    // ── Rekey counters ─────────────────────────────────
    // Bytes/packets sent under the current outbound key. Reset to 0 in
    // SetOutboundKeys at the NEWKEYS transition (matching libssh2's
    // transport-layer counters in _libssh2_transport_send). Used by the
    // ChannelRouter's rekey auto-trigger to enforce RFC 4253 §9 limits.
    private long _outboundBytes;
    private long _outboundPackets;

    // ── Outbound payload bounds (parity transport.c:1065-1102) ───────────
    // The C rejects an uncompressed payload of MAX_SSH_PACKET_LEN-0x100
    // (34744) bytes or more with LIBSSH2_ERROR_INVAL, and budgets compressed
    // output at MAX_SSH_PACKET_LEN-5-256 (34739) — an overflow is a
    // LIBSSH2_ERROR_ZLIB "compression failure". The channel layer chunks at
    // 32700, so these fire only for direct WritePacketAsync callers (KEX,
    // global requests, …).
    private const int MaxUncompressedPayload = 35000 - 0x100;
    private const int MaxCompressedPayload = 35000 - 5 - 256;

    // ── Thread-safety lock ─────────────────────────────
    // Serializes WritePacketAsync + SetOutboundKeys so concurrent channel
    // writes (multi-channel cooperative pumper) cannot
    // interleave their reads of _seqno/_cipher/_mac or their writes to the
    // underlying PipeWriter. Held across the full frame+encrypt+flush+seqno
    // sequence so on-wire ordering matches call ordering.
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    /// <summary>
    /// Constructs a writer over the given <see cref="PipeWriter"/>. The writer
    /// starts in the pre-NEWKEYS cleartext state; call
    /// <see cref="SetOutboundKeysAsync"/> after NEWKEYS to switch to encrypted mode.
    /// </summary>
    public PacketWriter(PipeWriter writer)
    {
        _writer = writer;
    }

    /// <summary>The current outbound sequence number (0-based, increments per packet).</summary>
    public uint Seqno => _seqno;

    /// <summary>
    /// Bytes sent under the current outbound key since the last NEWKEYS. Reset
    /// to 0 by <see cref="SetOutboundKeysAsync"/>. Consulted by the rekey auto-trigger.
    /// </summary>
    public long OutboundBytes => _outboundBytes;

    /// <summary>
    /// Packets sent under the current outbound key since the last NEWKEYS.
    /// Reset to 0 by <see cref="SetOutboundKeysAsync"/>. Consulted by the rekey
    /// auto-trigger.
    /// </summary>
    public long OutboundPackets => _outboundPackets;

    /// <summary>
    /// Installs the outbound cipher/MAC/compression for the post-NEWKEYS era.
    /// Sets <c>strictKex</c> and resets <see cref="Seqno"/> to 0 when strict-KEX
    /// is active (the reset lands BEFORE the first post-NEWKEYS packet, so the
    /// NEWKEYS packet itself carries the last seqno of the old era — matching
    /// <c>transport.c:1271-1273</c> which resets after incrementing on NEWKEYS).
    /// Also resets the rekey counters to 0 (a new key starts a fresh
    /// byte/packet budget per RFC 4253 §9).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Locked under <see cref="_writeLock"/>.</b> The original
    /// design left this method unlocked on the (incorrect) assumption
    /// that the rekey flow was already serialized with channel writes via the
    /// router's pump-lock. That assumption was wrong: channel
    /// <see cref="WritePacketAsync"/> calls only take <see cref="_writeLock"/>,
    /// never the pump-lock, so a concurrent channel write could race with this
    /// key swap — torn cipher read, NRE on a disposed cipher, or MAC failure
    /// that corrupts the session. The fix takes <see cref="_writeLock"/> across
    /// the swap so no write can be mid-encrypt while the cipher is replaced.
    /// </para>
    /// <para>
    /// Now async because <see cref="SemaphoreSlim.WaitAsync(CancellationToken)"/>
    /// is the correct way to take the lock from an async caller (the rekey flow
    /// runs from <c>RunExchangeAsync</c>, which is async).
    /// </para>
    /// </remarks>
    public async Task SetOutboundKeysAsync(ICipher cipher, IMac mac, ICompression compression,
        bool strictKex, bool compressionActive, CancellationToken cancellationToken = default)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _cipher?.Dispose();
            _mac?.Dispose();
            _compression?.Dispose();

            _cipher = cipher;
            _mac = mac;
            _compression = compression;
            _encrypted = true;
            _strictKex = strictKex;
            // Preserve an already-activated delayed compression across rekey:
            // libssh2's per-packet predicate is
            // (AUTHENTICATED || use_in_auth) (transport.c:292-295, 1060-1063) —
            // the AUTHENTICATED bit persists across NEWKEYS, so a post-auth
            // rekey must NOT deactivate zlib@openssh.com. The naive overwrite
            // turned compression off at every rekey while the peer kept
            // compressing, breaking the session.
            // A renegotiated "none" is safe: the use sites also guard on
            // _compression.Compresses.
            _compressionActive = _compressionActive || compressionActive;
            // Seqno resets to 0 only under strict-KEX (Terrapin, transport.c:1271-1273).
            // For a non-strict rekey the seqno continues across NEWKEYS; a fresh
            // reader/writer is already at 0, so this only matters mid-session.
            if (strictKex)
            {
                _seqno = 0;
            }

            // Rekey counters: a new key resets the byte/packet budget (RFC 4253 §9
            // limits are per-key, not cumulative across the session).
            _outboundBytes = 0;
            _outboundPackets = 0;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Flips <see cref="_compressionActive"/> to <c>true</c>. Called by
    /// <see cref="SshSession.MarkAuthenticated"/> after a successful userauth.
    /// For <c>zlib</c> (<c>use_in_auth=true</c>) this is a no-op (the flag was
    /// already <c>true</c> from <see cref="SetOutboundKeysAsync"/>); for
    /// <c>zlib@openssh.com</c> (<c>use_in_auth=false</c>) this is the
    /// delayed-activation transition that mirrors libssh2's
    /// <c>(session->state &amp; LIBSSH2_STATE_AUTHENTICATED) ||
    /// session->local.comp->use_in_auth</c> per-packet predicate
    /// (<c>transport.c:1060-1063</c>).
    /// </summary>
    /// <remarks>
    /// Idempotent. The flag is marked <c>volatile</c>, so the next
    /// <see cref="WritePacketAsync"/> observes the new value without taking
    /// <see cref="_writeLock"/> here.
    /// </remarks>
    public void ActivateDelayedCompression() => _compressionActive = true;

    /// <summary>
    /// Sends one SSH packet: <paramref name="payload"/> begins with the
    /// <c>SSH_MSG_*</c> type byte. Framing, padding, MAC, and encryption are
    /// applied per the negotiated algorithms. The packet is flushed to the
    /// <see cref="PipeWriter"/> before returning.
    /// </summary>
    /// <remarks>
    /// <b>Thread safety.</b> The full frame+encrypt+flush+seqno
    /// sequence runs under <see cref="_writeLock"/>. Concurrent callers serialize
    /// transparently; on-wire packet ordering matches call ordering (parity with
    /// libssh2's single-threaded transport).
    /// </remarks>
    public async Task WritePacketAsync(int type, ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        if (payload.Length == 0 || payload.Span[0] != type)
        {
            throw new ArgumentException(
                $"payload[0] must equal the type byte {type}", nameof(payload));
        }

        // Serialize with SetOutboundKeys and any other concurrent WritePacketAsync
        // caller. The lock is held across the entire frame+encrypt+flush+seqno
        // sequence so two concurrent channel writes (multi-channel cooperative
        // pumper) produce strictly-ordered on-wire output.
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // ── 1. Compress (if active) ────────────────────────────────────
            // transport.c:1060-1097. Compression applies only after NEWKEYS
            // AND (authenticated OR use_in_auth). The flag is set at NEWKEYS
            // from (Compresses && UseInAuth) by SetOutboundKeysAsync, then
            // flipped to true after auth by ActivateDelayedCompression (called
            // from SshSession.MarkAuthenticated for zlib@openssh.com).
            byte[] body = payload.ToArray();
            if (_encrypted && _compressionActive && _compression is not null
                && _compression.Compresses)
            {
                body = _compression.Compress(body);

                // Parity transport.c:1065-1078: the compressed output is
                // budgeted at MAX_SSH_PACKET_LEN-5-256 (34739) — an
                // incompressible payload that overflows the budget is a
                // LIBSSH2_ERROR_ZLIB "compression failure", NOT an oversized
                // packet.
                if (body.Length > MaxCompressedPayload)
                {
                    throw new SshException(SshErrorCode.Zlib, "compression failure");
                }
            }
            else if (body.Length >= MaxUncompressedPayload)
            {
                // Parity transport.c:1099-1102: an uncompressed payload of
                // MAX_SSH_PACKET_LEN-0x100 (34744) bytes or more is rejected
                // with LIBSSH2_ERROR_INVAL "too large packet". Previously the
                // port framed and sent any size.
                throw new SshException(SshErrorCode.Inval, "too large packet");
            }

            // ── 2. Determine framing parameters ────────────────────────────
            // transport.c:1027-1047, 1130-1149.
            int blocksize = _encrypted && _cipher is not null ? _cipher.BlockSize : 8;
            bool isAead = _encrypted && _cipher is not null && CipherMethods.IsAead(_cipher);
            bool etm = _encrypted && _mac is not null && _mac.IsEtm;
            int authLen = _encrypted && _cipher is not null ? _cipher.AuthTagLen : 0;

            // packet_length = payload + 1 (padlen byte) + 4 (length field).
            // The stored packet_length value excludes the 4-byte length field
            // itself: payload + 1 + padding (transport.c:1161).
            // crypt_offset: for ETM/AEAD/PktLenAad the 4-byte length is not
            // encrypted, so it is excluded from the block-alignment computation.
            int cryptOffset = (etm || authLen > 0 ||
                (_encrypted && _cipher is not null &&
                    (_cipher.Flags & CipherFlags.PktLenAad) != 0))
                ? 4 : 0;

            // padding_length: pad to blocksize, minimum 4 bytes.
            int packetLengthWithHeader = body.Length + 1 + 4;
            int paddingLength = blocksize - ((packetLengthWithHeader - cryptOffset) % blocksize);
            if (paddingLength < 4)
            {
                paddingLength += blocksize;
            }

            // The SSH wire packet_length field value (excludes its own 4 bytes).
            int wirePacketLength = body.Length + 1 + paddingLength;

            // ── 3. Lay out the unencrypted packet ─────────────────────────
            // [0..3]   BE32 packet_length
            // [4]      padding_length
            // [5..]    payload (body)
            // [5+body..]  random padding
            // [..]     MAC (standard/etm) or AEAD tag (appended by CryptAead)
            int macLen = (!isAead && _mac is not null) ? _mac.MacLen : 0;
            int totalLen = 4 + wirePacketLength + macLen;
            // AEAD appends its tag in the same buffer (CryptAead writes it).
            if (isAead)
            {
                totalLen += authLen;
            }

            byte[] outbuf = new byte[totalLen];
            BinaryPrimitives.WriteInt32BigEndian(outbuf.AsSpan(0, 4), wirePacketLength);
            outbuf[4] = (byte)paddingLength;
            Buffer.BlockCopy(body, 0, outbuf, 5, body.Length);

            // Random padding (transport.c:1166). _libssh2_random fills the padding
            // area; BCL RandomNumberGenerator.Fill is the AOT-friendly equivalent.
            RandomNumberGenerator.Fill(outbuf.AsSpan(5 + body.Length, paddingLength));

            // ── 4. MAC + encrypt per family ────────────────────────────────
            if (!_encrypted)
            {
                // Pre-NEWKEYS cleartext: no MAC, no encryption.
            }
            else if (isAead)
            {
                // AEAD (AES-GCM, ChaCha20-Poly1305): single CryptAead call covers
                // the 4-byte length (AAD / header-key) + payload + tag. The MAC is
                // integrated; no separate MAC append. transport.c:1189-1197 +
                // 1240-1251.
                //
                // aadLen = 4 (the packet_length field). payloadLen = everything
                // after the length field: 1 (padlen) + body + padding.
                int aadLen = 4;
                int payloadLen = wirePacketLength; // = 1 + body.Length + paddingLength
                // CryptAead reads src[0..aadLen+payloadLen-1] + tag (decrypt) or
                // writes dest[0..aadLen+payloadLen-1] + tag (encrypt).
                Span<byte> dest = outbuf.AsSpan(0, aadLen + payloadLen + authLen);
                // For encryption, src == the plaintext we just laid out (in outbuf
                // itself). CryptAead encrypts in-place-safe fashion: it reads the
                // plaintext from src and writes ciphertext+tag to dest. We point
                // src and dest at the same buffer region; the AEAD adapters
                // support this (they copy the AAD then encrypt the payload).
                _cipher!.CryptAead(_seqno, dest, outbuf.AsSpan(0, aadLen + payloadLen),
                    payloadLen, aadLen, encrypt: true);
            }
            else if (etm)
            {
                // ETM: encrypt first (skipping the plaintext 4-byte length),
                // then MAC over the ciphertext (incl. the plaintext length).
                // transport.c:1205-1237 (encrypt from crypt_offset=4) + 1254-1266.
                Span<byte> toEncrypt = outbuf.AsSpan(4, wirePacketLength);
                _cipher!.Crypt(toEncrypt);

                Span<byte> macOut = outbuf.AsSpan(4 + wirePacketLength, macLen);
                // MAC over BE32(seqno) ‖ outbuf[0..4+wirePacketLength-1]
                // (the plaintext length field + the ciphertext body).
                _mac!.Compute(_seqno, outbuf.AsSpan(0, 4 + wirePacketLength), macOut);
            }
            else
            {
                // Standard (AES-CBC/CTR + separate HMAC): MAC over plaintext,
                // then encrypt the plaintext portion only. transport.c:1180-1187
                // + 1205-1237 (encrypt from crypt_offset=0).
                Span<byte> macOut = outbuf.AsSpan(4 + wirePacketLength, macLen);
                // MAC over BE32(seqno) ‖ outbuf[0..4+wirePacketLength-1] (plaintext).
                _mac!.Compute(_seqno, outbuf.AsSpan(0, 4 + wirePacketLength), macOut);

                // Encrypt the whole packet including the 4-byte length field
                // (standard: length is encrypted; crypt_offset=0).
                _cipher!.Crypt(outbuf.AsSpan(0, 4 + wirePacketLength));
            }

            // ── 5. Write + flush ──────────────────────────────────────────
            await _writer.WriteAsync(outbuf, cancellationToken).ConfigureAwait(false);
            await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);

            // ── 6. seqno increment + strict-KEX NEWKEYS reset ──────────────
            // transport.c:1269-1273. Increment first, then reset to 0 if this
            // was a NEWKEYS under strict-KEX (so the NEXT packet uses seqno 0).
            _seqno++;
            if (_strictKex && type == PacketType.NewKeys)
            {
                _seqno = 0;
            }

            // ── 7. Rekey counters ───────────────────────
            // Bump wire-byte + packet counts for the outbound direction. Reset
            // in SetOutboundKeys at the NEWKEYS transition. totalLen covers the
            // full encrypted frame (length + ciphertext + MAC/tag).
            _outboundBytes += totalLen;
            _outboundPackets++;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        _cipher?.Dispose();
        _mac?.Dispose();
        _compression?.Dispose();
        _writeLock.Dispose();
        return default;
    }
}
