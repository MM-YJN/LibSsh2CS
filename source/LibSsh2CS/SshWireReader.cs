using System.Buffers.Binary;
using System.Text;

namespace LibSsh2CS;

/// <summary>
/// Minimal SSH wire-format reader. Reads length-prefixed strings, uint32, and
/// raw bytes from a cursor over a byte array. Mirrors libssh2's
/// <c>_libssh2_get_string</c> / <c>_libssh2_get_u32</c> family.
/// </summary>
internal ref struct SshWireReader
{
    private ReadOnlySpan<byte> _data;

    public SshWireReader(ReadOnlySpan<byte> data)
    {
        _data = data;
    }

    /// <summary>Reads a big-endian uint32 and advances the cursor by 4.</summary>
    public uint ReadUInt32()
    {
        if (_data.Length < 4)
        {
            throw new SshException(SshErrorCode.OutOfBoundary, "uint32 read past end of buffer");
        }

        uint value = BinaryPrimitives.ReadUInt32BigEndian(_data);
        _data = _data.Slice(4);
        return value;
    }

    /// <summary>The number of unconsumed bytes.</summary>
    public readonly int Remaining => _data.Length;

    /// <summary>The unconsumed bytes (used by the Ed25519 padding-tail check).</summary>
    public readonly ReadOnlySpan<byte> RemainingBytes => _data;

    /// <summary>
    /// Reads an SSH byte string (uint32 length prefix + bytes) and advances the
    /// cursor. Returns a copy of the bytes.
    /// </summary>
    public ReadOnlySpan<byte> ReadSshBytes()
    {
        int length = (int)ReadUInt32();
        if (length < 0 || _data.Length < length)
        {
            // A length ≥ 2^31 sign-flips and previously escaped as a raw
            // ArgumentOutOfRangeException from Span.Slice.
            throw new SshException(SshErrorCode.OutOfBoundary, "string read past end of buffer");
        }

        ReadOnlySpan<byte> bytes = _data.Slice(0, length);
        _data = _data.Slice(length);
        return bytes;
    }

    /// <summary>Reads <paramref name="count"/> raw bytes and advances the cursor.</summary>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        if (_data.Length < count)
        {
            throw new SshException(SshErrorCode.OutOfBoundary, "raw read past end of buffer");
        }

        ReadOnlySpan<byte> bytes = _data.Slice(0, count);
        _data = _data.Slice(count);
        return bytes;
    }
}
