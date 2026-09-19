using System.Buffers;
using System.Numerics;
using System.Text;

namespace LibSsh2CS.Util;

/// <summary>
/// A stack-only sequence-aware SSH wire reader over
/// <see cref="ReadOnlySequence{T}"/> of <see cref="byte"/>, built on the BCL
/// <see cref="SequenceReader{T}"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the pipe-based counterpart of the <c>byte[]</c>-backed
/// <c>PacketWireReader</c> at the bottom of <c>PemParser.cs</c>. The packet layer
/// (<see cref="Transport.PacketReader"/>) reads from a <c>PipeReader</c>, whose
/// data spans one or more memory segments; <see cref="SequenceReader{T}"/>
/// handles segment boundaries transparently.
/// </para>
/// <para>
/// Declared <see langword="ref struct"/> so it can hold a
/// <see cref="SequenceReader{T}"/> (itself a ref struct) by value. It is
/// constructed on the stack for each packet parse — the packet layer passes in
/// the packet's <see cref="ReadOnlySequence{T}"/>, reads fields off, and lets
/// the reader go out of scope before the next <c>await</c>.
/// </para>
/// <para>
/// Methods throw on underflow except where a
/// <c>Try*</c> variant is needed for non-destructive framing peeks.
/// </para>
/// <para>
/// Provides <see cref="ReadString"/> (the SSH <c>string</c> type, RFC
/// 4251 §5) and <see cref="ReadNameList"/> (the SSH <c>name-list</c> type, RFC
/// 4251 §3.6.1) — both used by the KEXINIT parser. Also provides
/// <see cref="ReadMpint"/> + <see cref="ReadMpintAsBigInteger"/> for the DH
/// server-public <c>f</c> and the shared secret <c>K</c>.
/// </para>
/// </remarks>
internal ref struct PacketWireReader
{
    private SequenceReader<byte> _reader;

    /// <summary>Constructs a reader over the given sequence.</summary>
    public PacketWireReader(ReadOnlySequence<byte> sequence)
    {
        _reader = new SequenceReader<byte>(sequence);
    }

    /// <summary>The current cursor position (bytes consumed since construction).</summary>
    public readonly long Position => _reader.Consumed;

    /// <summary>The number of bytes remaining from the cursor to the end.</summary>
    public readonly long Remaining => _reader.Remaining;

    /// <summary>
    /// Reads one byte and advances the cursor. Throws if no byte is available.
    /// </summary>
    public byte ReadByte()
    {
        if (!_reader.TryRead(out byte value))
        {
            throw new SshException(SshErrorCode.OutOfBoundary, "ReadByte: end of sequence");
        }

        return value;
    }

    /// <summary>
    /// Reads a big-endian <see cref="uint"/> (4 bytes) and advances the cursor.
    /// Throws if fewer than 4 bytes remain.
    /// </summary>
    public uint ReadUInt32BigEndian()
    {
        if (!_reader.TryReadBigEndian(out int signed))
        {
            throw new SshException(SshErrorCode.OutOfBoundary, "ReadUInt32: end of sequence");
        }

        return (uint)signed;
    }

    /// <summary>
    /// Tries to read a big-endian <see cref="uint"/> (4 bytes) without
    /// advancing the cursor on failure. Returns <c>false</c> if fewer than 4
    /// bytes remain (used by the packet layer to peek the packet length before
    /// the full packet has arrived).
    /// </summary>
    public bool TryReadUInt32BigEndian(out uint value)
    {
        if (_reader.TryReadBigEndian(out int signed))
        {
            value = (uint)signed;
            return true;
        }

        value = 0;
        return false;
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes and advances the cursor.
    /// Returns a contiguous <see cref="byte"/> array (the pipe-based reader
    /// copies across segments when a packet straddles a segment boundary —
    /// acceptable for SSH packet rates).
    /// Throws if fewer than <paramref name="count"/> bytes remain.
    /// </summary>
    public byte[] ReadBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        if (!_reader.TryReadExact(count, out ReadOnlySequence<byte> slice))
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"ReadBytes: need {count}, have {_reader.Remaining}");
        }

        return slice.ToArray();
    }

    /// <summary>
    /// Reads an SSH <c>string</c> — a big-endian <see cref="uint"/> length prefix
    /// followed by that many UTF-8 bytes — and advances the cursor. Port of
    /// libssh2's <c>_libssh2_store_string</c> / <c>session-&gt;kex_args[]</c>
    /// reads. Throws on underflow (length prefix shorter than 4 bytes, or the
    /// declared length exceeds the remaining bytes — matching the C
    /// <c>_libssh2_error(LIBSSH2_ERROR_OUT_OF_BOUNDARY)</c> path).
    /// </summary>
    /// <remarks>
    /// RFC 4251 §5: SSH strings are UTF-8-encoded. The test project sets
    /// <c>InvariantGlobalization=true</c> so <see cref="Encoding.UTF8"/> is the
    /// right decoder; SSH wire strings are always UTF-8 (never a culture-aware
    /// encoding). An empty string (length 0) is valid and decodes to
    /// <see cref="string.Empty"/>.
    /// </remarks>
    public string ReadString()
    {
        uint length = ReadUInt32BigEndian();
        if (length == 0)
        {
            return string.Empty;
        }

        // Cap at int.MaxValue to keep the ToArray/GetString call paths safe —
        // SSH strings in KEXINIT are at most a few hundred bytes, but a
        // malicious 4GB length would OOM without this.
        if (length > int.MaxValue)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"ReadString: length {length} > int.MaxValue");
        }

        byte[] bytes = ReadBytes((int)length);
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Reads an SSH <c>name-list</c> — a UTF-8 string of comma-separated
    /// algorithm names (RFC 4251 §3.6.1) — and splits it into its constituent
    /// names. Advances the cursor past the name-list. An empty name-list
    /// decodes to a zero-length array (never <c>null</c> and never a single
    /// empty element). Used by the KEXINIT parser to read the 10 algorithm
    /// name-lists and by the <c>ext-info</c> / <c>kex-strict-c</c> detection
    /// helpers that scan the kex name-list.
    /// </summary>
    /// <remarks>
    /// RFC 4251 §3.6.1: a name-list is a comma-separated list of names with no
    /// trailing comma. <c>"a,b,c"</c> → <c>["a","b","c"]</c>; <c>""</c> →
    /// <c>[]</c>. Whitespace is significant inside a name (so we do not trim);
    /// names are matched exactly against the SSH algorithm registry.
    /// </remarks>
    public string[] ReadNameList()
    {
        string s = ReadString();
        if (s.Length == 0)
        {
            return [];
        }

        return s.Split(',');
    }

    /// <summary>
    /// Reads an SSH <c>string</c> as raw bytes (no UTF-8 decode) — for binary
    /// blobs like the server host key (<c>K_S</c>) and the KEX-REPLY signature,
    /// which are not text. Port of libssh2's <c>_libssh2_get_string</c> /
    /// <c>_libssh2_copy_string</c> for the byte-passthrough case. Throws on
    /// underflow.
    /// </summary>
    public byte[] ReadBlob()
    {
        uint length = ReadUInt32BigEndian();
        if (length > int.MaxValue)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"ReadBlob: length {length} > int.MaxValue");
        }

        return ReadBytes((int)length);
    }

    /// <summary>
    /// Reads an SSH <c>mpint</c> body — a big-endian uint32 length prefix
    /// followed by that many bytes — and advances the cursor. Returns the raw
    /// body bytes (which may include a leading 0x00 sign guard when the high
    /// bit is set, per RFC 4251 §5). Port of libssh2's
    /// <c>_libssh2_get_string</c> as used on the DH <c>f</c> / <c>K</c> fields.
    /// Throws on underflow (length prefix &lt; 4 bytes, or the declared length
    /// exceeds the remaining bytes).
    /// </summary>
    public byte[] ReadMpint()
    {
        uint length = ReadUInt32BigEndian();
        if (length > int.MaxValue)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"ReadMpint: length {length} > int.MaxValue");
        }

        return ReadBytes((int)length);
    }

    /// <summary>
    /// Reads an SSH <c>mpint</c> and parses it into a <see cref="BigInteger"/>
    /// (treating the body as a non-negative big-endian integer — the leading
    /// 0x00 sign guard, if present, is insignificant). Used by the KEX layer to
    /// read the server DH public <c>f</c> and the shared secret <c>K</c>.
    /// Replaces libssh2's <c>_libssh2_bn_from_bin</c>.
    /// </summary>
    public BigInteger ReadMpintAsBigInteger()
        => Endian.BigIntegerFromBigEndian(ReadMpint());

    /// <summary>
    /// Tries to read exactly <paramref name="count"/> bytes as a
    /// <see cref="ReadOnlySequence{T}"/> slice without copying. Returns
    /// <c>false</c> if fewer than <paramref name="count"/> bytes remain (the
    /// cursor is not advanced on failure).
    /// </summary>
    public bool TryReadExact(int count, out ReadOnlySequence<byte> slice)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        return _reader.TryReadExact(count, out slice);
    }

    /// <summary>
    /// Advances the cursor by <paramref name="count"/> bytes, discarding them.
    /// Used by the packet layer to skip already-processed MAC / tag tails.
    /// </summary>
    public void Advance(long count)
    {
        if (count < 0 || count > _reader.Remaining)
        {
            throw new SshException(SshErrorCode.OutOfBoundary, "Advance past end of sequence");
        }

        _reader.Advance(count);
    }

    /// <summary>
    /// Returns the unconsumed tail as a <see cref="ReadOnlySequence{T}"/>
    /// without advancing. Used to hand leftover bytes (belonging to the next
    /// packet) back to the <c>PipeReader</c> via <c>AdvanceTo</c>.
    /// </summary>
    public readonly ReadOnlySequence<byte> UnconsumedSequence => _reader.UnreadSequence;
}
