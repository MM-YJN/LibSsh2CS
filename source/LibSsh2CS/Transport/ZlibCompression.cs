using System.Buffers;
using System.IO.Compression;

namespace LibSsh2CS.Transport;

/// <summary>
/// zlib (RFC 1950) compression for both <c>zlib</c> and <c>zlib@openssh.com</c>.
/// The two differ only in <see cref="UseInAuth"/>; the engine
/// is identical and built on the .NET 11 <see cref="ZLibEncoder"/>/<see cref="ZLibDecoder"/>.
/// </summary>
/// <remarks>
/// <para>
/// A persistent codec is held per direction (one <see cref="ZLibEncoder"/> for
/// outbound, one <see cref="ZLibDecoder"/> for inbound), so the deflate
/// dictionary carries across packets — the same contract as libssh2's persistent
/// <c>z_stream</c> initialized once in <c>comp_method_zlib_init</c>
/// (<c>comp.c:142</c>) and reused per packet with <c>Z_PARTIAL_FLUSH</c>.
/// </para>
/// <para>
/// SSH compression never finalizes the deflate stream: each packet is one
/// <see cref="ZLibEncoder.Compress"/> call with <c>isFinalBlock = false</c>
/// followed by <see cref="ZLibEncoder.Flush"/> to emit a block boundary (the
/// <c>Z_SYNC_FLUSH</c> equivalent). Decompression is the inverse — feed one
/// packet's bytes to <see cref="ZLibDecoder.Decompress"/>; it returns
/// <see cref="OperationStatus.NeedMoreData"/> at the packet boundary while
/// keeping the dictionary in the decoder.
/// </para>
/// <para>
/// <b>Parity note:</b> the BCL codec uses the same bundled zlib engine as the
/// prior <see cref="ZLibStream"/>-based path, so flush-marker bytes are
/// unchanged. Live-server byte-for-byte flush-marker interop is exercised by
/// the <c>Handshake_Compression_ZlibOpenSsh_NegotiatesAndExecRoundTrips</c>
/// integration test (gated on the <see cref="SshSession.MarkAuthenticated"/>
/// delayed-activation fix for <c>zlib@openssh.com</c>).
/// </para>
/// </remarks>
internal sealed class ZlibCompression : ICompression
{
    /// <summary>
    /// <c>LIBSSH2_PACKET_MAXDECOMP</c> (<c>libssh2.h:273</c>) — the C's
    /// decompression growth budget. A tiny compressed packet must not be able
    /// to expand to gigabytes.
    /// </summary>
    private const int PayloadLimit = 40000;

    private readonly bool _useInAuth;

    // One persistent codec per instance. An instance handles a single direction
    // (compress OR decompress), set in Init — see KeyExchange.cs:822,854.
    private ZLibEncoder? _encoder;
    private ZLibDecoder? _decoder;

    public ZlibCompression(string name, bool useInAuth)
    {
        Name = name;
        _useInAuth = useInAuth;
    }

    public string Name { get; }
    public bool Compresses => true;
    public bool UseInAuth => _useInAuth;

    public void Init(bool compress)
    {
        if (compress)
        {
            _encoder = new ZLibEncoder();
        }
        else
        {
            _decoder = new ZLibDecoder();
        }
    }

    public byte[] Compress(ReadOnlySpan<byte> src)
    {
        if (_encoder is null)
        {
            throw new InvalidOperationException($"{Name}: Init(compress: true) not called");
        }

        // SSH packets are bounded; a src.Length + 64-byte floor covers typical
        // expansion + the flush marker. ArrayBufferWriter<byte> grows via
        // ArrayPool<byte>.Shared on demand.
        var output = new ArrayBufferWriter<byte>(Math.Max(src.Length + 64, 256));

        // Phase 1: feed all input without finalizing. The stream stays open
        // across packets; only Flush (phase 2) marks a block boundary.
        ReadOnlySpan<byte> remaining = src;
        while (true)
        {
            Span<byte> dst = output.GetSpan(Math.Max(remaining.Length, 64));
            OperationStatus status = _encoder.Compress(
                remaining, dst, out int consumed, out int written, isFinalBlock: false);

            output.Advance(written);
            remaining = remaining[consumed..];

            switch (status)
            {
                case OperationStatus.InvalidData:
                    throw new SshException(
                        SshErrorCode.Zlib, $"{Name}: zlib compress rejected input");
                case OperationStatus.DestinationTooSmall:
                    // Destination filled mid-input. Force growth so the next
                    // GetSpan makes progress (avoid a stall when nothing was
                    // written this iteration).
                    if (written == 0)
                    {
                        output.GetSpan(output.Capacity * 2);
                    }

                    continue;
            }

            // Done (defensive — only reachable with isFinalBlock=true) or
            // NeedMoreData. The batch is complete when input is consumed.
            if (remaining.IsEmpty)
            {
                break;
            }
        }

        // Phase 2: flush to emit a block boundary. The peer's decompressor
        // needs this marker to yield the packet's bytes.
        while (true)
        {
            Span<byte> dst = output.GetSpan(64);
            OperationStatus status = _encoder.Flush(dst, out int written);

            output.Advance(written);

            switch (status)
            {
                case OperationStatus.Done:
                    return output.WrittenSpan.ToArray();
                case OperationStatus.DestinationTooSmall:
                    if (written == 0)
                    {
                        output.GetSpan(output.Capacity * 2);
                    }

                    continue;
                default:
                    throw new SshException(
                        SshErrorCode.Zlib, $"{Name}: zlib flush failed");
            }
        }
    }

    public byte[] Decompress(ReadOnlySpan<byte> src)
    {
        if (_decoder is null)
        {
            throw new InvalidOperationException($"{Name}: Init(compress: false) not called");
        }

        var output = new ArrayBufferWriter<byte>(Math.Max(src.Length * 4, 1024));

        ReadOnlySpan<byte> remaining = src;
        while (true)
        {
            Span<byte> dst = output.GetSpan(Math.Max(remaining.Length, 256));
            OperationStatus status = _decoder.Decompress(remaining, dst, out int consumed, out int written);

            output.Advance(written);
            remaining = remaining[consumed..];

            // Decompression growth cap (parity comp.c:235-250, 289-293): the C
            // starts the output budget at min(max(src_len*4, 25),
            // LIBSSH2_PACKET_MAXDECOMP=40000), doubles it on each full buffer,
            // and fails with LIBSSH2_ERROR_ZLIB "Excessive growth in
            // decompression phase" once a fill completes with the budget above
            // the limit — an effective bound of ~2×40000 bytes per packet
            // (the exact boundary varies with the doubling sequence; this
            // check errors at the same ~2×40000 ceiling). Without it, a
            // hostile peer's small compressed packet could expand to
            // gigabytes of managed allocations.
            if (output.WrittenCount >= 2 * PayloadLimit)
            {
                throw new SshException(
                    SshErrorCode.Zlib,
                    $"{Name}: excessive growth in decompression phase");
            }

            switch (status)
            {
                case OperationStatus.NeedMoreData:
                    // Decoder has consumed this packet's bytes and is waiting
                    // for the next packet. Dictionary persists in the decoder.
                    return output.WrittenSpan.ToArray();
                case OperationStatus.Done:
                    // Mid-session Done means the peer finalized its deflate
                    // stream — a protocol desync.
                    throw new SshException(
                        SshErrorCode.Zlib,
                        $"{Name}: peer finalized zlib stream mid-session");
                case OperationStatus.DestinationTooSmall:
                    if (written == 0)
                    {
                        output.GetSpan(output.Capacity * 2);
                    }

                    continue;
                default: // OperationStatus.InvalidData
                    throw new SshException(
                        SshErrorCode.Zlib, $"{Name}: corrupt zlib stream");
            }
        }
    }

    public void Dispose()
    {
        _encoder?.Dispose();
        _encoder = null;
        _decoder?.Dispose();
        _decoder = null;
    }
}
