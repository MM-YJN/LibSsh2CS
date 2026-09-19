using System.Buffers;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.Util;

/// <summary>
/// Tests for the sequence-aware <see cref="PacketWireReader"/>: byte / uint32 /
/// raw-bytes reads over single-segment and multi-segment
/// <see cref="ReadOnlySequence{T}"/>, plus the <c>Try*</c> peek variants the
/// packet layer uses for framing.
/// </summary>
public class PacketWireReaderTests
{
    // ── ReadByte / ReadUInt32 ───────────────────────────────────────────

    [Fact]
    public void ReadByte_AdvancesCursor()
    {
        byte[] data = [0x14, 0x00, 0x00, 0x01, 0x41];
        var seq = new ReadOnlySequence<byte>(data);
        var r = new PacketWireReader(seq);

        Assert.Equal(0x14, r.ReadByte());
        Assert.Equal(1, r.Position);
        Assert.Equal(4, r.Remaining);

        Assert.Equal(0x00, r.ReadByte());
        Assert.Equal(0x00, r.ReadByte());
        Assert.Equal(0x01, r.ReadByte());
        Assert.Equal(0x41, r.ReadByte());
        Assert.Equal(0, r.Remaining);
    }

    [Fact]
    public void ReadByte_ThrowsWhenExhausted()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0x01]));
        r.ReadByte();

        SshException? ex = null;
        try
        {
            r.ReadByte();
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadUInt32BigEndian_DecodesNetworkOrder()
    {
        // 0x00000100 = 256 in big-endian.
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0x00, 0x00, 0x01, 0x00]));
        Assert.Equal(256u, r.ReadUInt32BigEndian());
        Assert.Equal(4, r.Position);
    }

    [Fact]
    public void ReadUInt32BigEndian_MaxValue()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0xFF, 0xFF, 0xFF, 0xFF]));
        Assert.Equal(uint.MaxValue, r.ReadUInt32BigEndian());
    }

    [Fact]
    public void ReadUInt32BigEndian_ThrowsWhenExhausted()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0x00, 0x00, 0x01]));

        SshException? ex = null;
        try
        {
            r.ReadUInt32BigEndian();
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    // ── TryReadUInt32BigEndian (non-destructive peek) ──────────────────

    [Fact]
    public void TryReadUInt32BigEndian_SucceedsAndAdvances()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0x00, 0x00, 0x00, 0x2A]));
        Assert.True(r.TryReadUInt32BigEndian(out uint value));
        Assert.Equal(42u, value);
        Assert.Equal(4, r.Position);
    }

    [Fact]
    public void TryReadUInt32BigEndian_FailsWithoutAdvancing()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0x00, 0x01]));
        Assert.False(r.TryReadUInt32BigEndian(out uint value));
        Assert.Equal(0u, value);
        Assert.Equal(0, r.Position);
        Assert.Equal(2, r.Remaining);
    }

    // ── ReadBytes / TryReadExact ───────────────────────────────────────

    [Fact]
    public void ReadBytes_ReturnsContiguousCopy()
    {
        byte[] data = [1, 2, 3, 4, 5];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));
        byte[] got = r.ReadBytes(3);

        Assert.Equal((byte[])[1, 2, 3], got);
        Assert.Equal(3, r.Position);
        // The returned array is an independent copy — mutate it, source is untouched.
        got[0] = 99;
        byte[] rest = r.ReadBytes(2);
        Assert.Equal((byte[])[4, 5], rest);
    }

    [Fact]
    public void ReadBytes_ThrowsWhenShort()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[1, 2]));

        SshException? ex = null;
        try
        {
            r.ReadBytes(4);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadBytes_RejectsNegativeCount()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[1]));

        ArgumentOutOfRangeException? ex = null;
        try
        {
            r.ReadBytes(-1);
        }
        catch (ArgumentOutOfRangeException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
    }

    [Fact]
    public void TryReadExact_SucceedsWithoutCopy()
    {
        byte[] data = [0xAA, 0xBB, 0xCC, 0xDD];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));
        Assert.True(r.TryReadExact(2, out ReadOnlySequence<byte> slice));

        // The slice is a view into the source (no copy) — single-segment here.
        Assert.True(slice.IsSingleSegment);
        Assert.Equal((byte[])[0xAA, 0xBB], slice.ToArray());
        Assert.Equal(2, r.Position);
    }

    [Fact]
    public void TryReadExact_FailsWithoutAdvancing()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0xAA]));
        Assert.False(r.TryReadExact(3, out ReadOnlySequence<byte> slice));
        Assert.Equal(0, r.Position);
        Assert.True(slice.IsEmpty);
    }

    // ── Multi-segment sequences ────────────────────────────────────────

    [Fact]
    public void ReadUInt32BigEndian_AcrossSegmentBoundary()
    {
        // A 4-byte uint32 that straddles two segments: [0x00,0x00] | [0x01,0x00]
        var first = new ArraySegment<byte>([0x00, 0x00]);
        var second = new ArraySegment<byte>([0x01, 0x00]);
        ReadOnlySequence<byte> seq = BuildSequence(first, second);

        var r = new PacketWireReader(seq);
        Assert.Equal(256u, r.ReadUInt32BigEndian());
        Assert.Equal(4, r.Position);
    }

    [Fact]
    public void ReadBytes_AcrossSegmentBoundary_CopiesToContiguousArray()
    {
        var first = new ArraySegment<byte>([1, 2, 3]);
        var second = new ArraySegment<byte>([4, 5, 6]);
        ReadOnlySequence<byte> seq = BuildSequence(first, second);

        var r = new PacketWireReader(seq);
        byte[] got = r.ReadBytes(5);
        Assert.Equal((byte[])[1, 2, 3, 4, 5], got);
        Assert.Equal(5, r.Position);
    }

    [Fact]
    public void ReadByte_AcrossSegmentBoundary()
    {
        var first = new ArraySegment<byte>([0x41]);
        var second = new ArraySegment<byte>([0x42]);
        ReadOnlySequence<byte> seq = BuildSequence(first, second);

        var r = new PacketWireReader(seq);
        Assert.Equal(0x41, r.ReadByte());
        Assert.Equal(0x42, r.ReadByte());
        Assert.Equal(0, r.Remaining);
    }

    // ── Advance / UnconsumedSequence ───────────────────────────────────

    [Fact]
    public void Advance_SkipsBytes()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0, 1, 2, 3, 4]));
        r.Advance(2);
        Assert.Equal(2, r.Position);
        Assert.Equal(3, r.Remaining);
        Assert.Equal(2, r.ReadByte());
    }

    [Fact]
    public void Advance_PastEnd_Throws()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[1, 2]));

        SshException? ex = null;
        try
        {
            r.Advance(3);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void UnconsumedSequence_ReturnsTailWithoutAdvancing()
    {
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0, 1, 2, 3, 4]));
        r.ReadBytes(2);
        ReadOnlySequence<byte> tail = r.UnconsumedSequence;

        Assert.Equal((byte[])[2, 3, 4], tail.ToArray());
        // Reading the tail did not advance the reader's own cursor.
        Assert.Equal(2, r.Position);
    }

    // ── ReadString (SSH string: BE32 length + UTF-8 bytes) ─────────────

    [Fact]
    public void ReadString_DecodesUtf8()
    {
        // "curve25519-sha256" — 17 bytes, prefixed by BE32(17).
        byte[] body = "curve25519-sha256"u8.ToArray();
        byte[] data = new byte[4 + body.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(data, (uint)body.Length);
        Buffer.BlockCopy(body, 0, data, 4, body.Length);

        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));
        string s = r.ReadString();

        Assert.Equal("curve25519-sha256", s);
        Assert.Equal(4 + body.Length, r.Position);
    }

    [Fact]
    public void ReadString_EmptyString()
    {
        // Length 0 → empty string, no body bytes consumed.
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0, 0, 0, 0]));
        Assert.Equal(string.Empty, r.ReadString());
        Assert.Equal(4, r.Position);
    }

    [Fact]
    public void ReadString_ThrowsWhenBodyTruncated()
    {
        // Length says 10 but only 3 body bytes available.
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0, 0, 0, 10, 0x41, 0x42, 0x43]));

        SshException? ex = null;
        try
        {
            r.ReadString();
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadString_ThrowsWhenLengthPrefixTruncated()
    {
        // Only 3 bytes — can't read the 4-byte length prefix.
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0, 0, 0]));

        SshException? ex = null;
        try
        {
            r.ReadString();
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadString_AcrossSegmentBoundary()
    {
        // BE32 length straddles two segments: [0x00,0x00] | [0x00,0x03, 'a','b','c']
        var first = new ArraySegment<byte>([0x00, 0x00]);
        var second = new ArraySegment<byte>([0x00, 0x03, .. "abc"u8.ToArray()]);
        ReadOnlySequence<byte> seq = BuildSequence(first, second);

        var r = new PacketWireReader(seq);
        Assert.Equal("abc", r.ReadString());
        Assert.Equal(4 + 3, r.Position);
    }

    // ── ReadNameList (SSH name-list: string of comma-separated names) ──

    [Fact]
    public void ReadNameList_SingleName()
    {
        byte[] data =
        [
            0x00, 0x00, 0x00, 0x03,
            .. "abc"u8.ToArray(),
        ];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));
        string[] names = r.ReadNameList();

        Assert.Equal(new[] { "abc" }, names);
        Assert.Equal(4 + 3, r.Position);
    }

    [Fact]
    public void ReadNameList_MultipleNames()
    {
        // "a,b,curve25519-sha256" — 20 bytes.
        byte[] body = "a,b,curve25519-sha256"u8.ToArray();
        byte[] data = new byte[4 + body.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(data, (uint)body.Length);
        Buffer.BlockCopy(body, 0, data, 4, body.Length);

        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));
        string[] names = r.ReadNameList();

        Assert.Equal(new[] { "a", "b", "curve25519-sha256" }, names);
    }

    [Fact]
    public void ReadNameList_Empty()
    {
        // Empty name-list = zero-length string → zero-length array (not a single
        // empty element).
        var r = new PacketWireReader(new ReadOnlySequence<byte>((byte[])[0, 0, 0, 0]));
        string[] names = r.ReadNameList();

        Assert.Empty(names);
    }

    // ── ReadMpint / ReadMpintAsBigInteger ──────────────────────────────

    [Fact]
    public void ReadMpint_ReturnsBody_IncludingLeadingZeroSignGuard()
    {
        // mpint for 0x80FF: length=3, body=00 80 FF (leading zero guards the high bit)
        byte[] data = [0, 0, 0, 3, 0x00, 0x80, 0xFF];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));

        byte[] body = r.ReadMpint();

        Assert.Equal([0x00, 0x80, 0xFF], body);
        Assert.Equal(0, r.Remaining);
    }

    [Fact]
    public void ReadMpint_EmptyBody_ForZeroValue()
    {
        // mpint for 0: length=0, no body
        byte[] data = [0, 0, 0, 0];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));

        byte[] body = r.ReadMpint();

        Assert.Empty(body);
    }

    [Fact]
    public void ReadMpint_ThrowsWhenTruncated()
    {
        // length prefix says 4 bytes but only 2 remain
        byte[] data = [0, 0, 0, 4, 0xAB, 0xCD];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));

        SshException? ex = null;
        try
        {
            r.ReadMpint();
        }
        catch (SshException e)
        {
            ex = e;
        }

        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
    }

    [Fact]
    public void ReadMpint_HandlesMultiSegmentBody()
    {
        // length prefix in segment 1, body split across segments 2 and 3
        byte[] len = [0, 0, 0, 5];
        byte[] b1 = [0x01, 0x02, 0x03];
        byte[] b2 = [0x04, 0x05];
        ReadOnlySequence<byte> seq = BuildSequence(len, b1, b2);
        var r = new PacketWireReader(seq);

        byte[] body = r.ReadMpint();

        Assert.Equal([0x01, 0x02, 0x03, 0x04, 0x05], body);
    }

    [Fact]
    public void ReadMpintAsBigInteger_DecodesHighBitValue()
    {
        // mpint for 0x80FF (leading-zero present): should decode to 0x80FF = 33023
        byte[] data = [0, 0, 0, 3, 0x00, 0x80, 0xFF];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));

        System.Numerics.BigInteger v = r.ReadMpintAsBigInteger();

        Assert.Equal((System.Numerics.BigInteger)0x80FF, v);
    }

    [Fact]
    public void ReadMpintAsBigInteger_DecodesPlainValue()
    {
        // mpint for 0x0100 = 256 (no leading zero, high bit clear)
        byte[] data = [0, 0, 0, 2, 0x01, 0x00];
        var r = new PacketWireReader(new ReadOnlySequence<byte>(data));

        System.Numerics.BigInteger v = r.ReadMpintAsBigInteger();

        Assert.Equal((System.Numerics.BigInteger)256, v);
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a multi-segment <see cref="ReadOnlySequence{T}"/> from segments
    /// — one <c>Segment</c> per <see cref="ArraySegment{T}"/> so the packet
    /// boundary falls between them (the segment-spanning case the packet
    /// reader must handle).
    /// </summary>
    private static ReadOnlySequence<byte> BuildSequence(
        params ArraySegment<byte>[] segments)
    {
        if (segments.Length == 1)
        {
            byte[]? array = segments[0].Array;
            if (array is null)
            {
                throw new ArgumentException("single segment must have a non-null Array", nameof(segments));
            }
            return new ReadOnlySequence<byte>(array, segments[0].Offset, segments[0].Count);
        }

        // Build a linked list of segments with correct RunningIndex (the
        // ReadOnlySequence multi-segment ctor requires RunningIndex to be the
        // cumulative byte offset of each segment from the start).
        Segment? first = null;
        Segment? current = null;
        long running = 0;
        foreach (ArraySegment<byte> seg in segments)
        {
            var node = new Segment();
            node.SetMemory(seg.Array!, seg.Offset, seg.Count, running);
            running += seg.Count;
            if (first is null)
            {
                first = node;
            }
            else
            {
                current!.SetNext(node);
            }

            current = node;
        }

        return new ReadOnlySequence<byte>(first!, 0, current!, current!.Memory.Length);
    }

    /// <summary>A minimal <see cref="ReadOnlySequenceSegment{T}"/> for the
    /// multi-segment test helper. The <c>Memory</c>/<c>Next</c>/<c>RunningIndex</c>
    /// setters are protected on the base, so this subclass exposes helpers that
    /// assign them from within (the only context where they're accessible).</summary>
    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public void SetMemory(byte[] array, int offset, int length, long runningIndex)
        {
            Memory = array.AsMemory(offset, length);
            RunningIndex = runningIndex;
        }

        public void SetNext(ReadOnlySequenceSegment<byte> next)
        {
            Next = next;
        }
    }
}
