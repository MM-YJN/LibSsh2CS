using System.Buffers.Binary;

namespace LibSsh2CS.UnitTests.Util;

/// <summary>
/// Tests for the byte-array-backed <see cref="SshWireReader"/> (used by the
/// PEM parser and key-blob parsing). Covers the length sign-flip guard.
/// </summary>
public class SshWireReaderTests
{
    [Fact]
    public void ReadSshBytes_ReadsLengthPrefixedData()
    {
        byte[] data = new byte[4 + 3];
        BinaryPrimitives.WriteInt32BigEndian(data, 3);
        data[4] = 1;
        data[5] = 2;
        data[6] = 3;

        var r = new SshWireReader(data);

        Assert.Equal(new byte[] { 1, 2, 3 }, r.ReadSshBytes().ToArray());
        Assert.Equal(0, r.Remaining);
    }

    [Fact]
    public void ReadSshBytes_HighBitLength_ThrowsOutOfBoundary()
    {
        // A length ≥ 2^31 sign-flips to negative when cast to int; it must
        // fail with OutOfBoundary, not escape as a raw
        // ArgumentOutOfRangeException from Span.Slice.
        byte[] data = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(data, unchecked((int)0x80000000));

        var r = new SshWireReader(data);

        SshException? caught = null;
        try
        {
            _ = r.ReadSshBytes();
        }
        catch (SshException ex)
        {
            caught = ex;
        }

        Assert.NotNull(caught);
        Assert.Equal(SshErrorCode.OutOfBoundary, caught!.ErrorCode);
    }

    [Fact]
    public void ReadSshBytes_OverlongLength_ThrowsOutOfBoundary()
    {
        byte[] data = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(data, 100);   // 100 bytes declared, 4 present

        var r = new SshWireReader(data);

        SshException? caught = null;
        try
        {
            _ = r.ReadSshBytes();
        }
        catch (SshException ex)
        {
            caught = ex;
        }

        Assert.NotNull(caught);
        Assert.Equal(SshErrorCode.OutOfBoundary, caught!.ErrorCode);
    }
}
