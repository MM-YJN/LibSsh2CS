using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

public class SignatureSerializationTests
{
    [Theory]
    [InlineData("00", "00", "3006020100020100")]
    [InlineData("000001", "007F", "300602010102017F")]
    [InlineData("80", "FF", "300802020080020200FF")]
    [InlineData("000080", "01", "300702020080020101")]
    public void DerIntegers_PreserveMinimalPositiveEncoding(string r, string s, string expected)
    {
        Assert.Equal(Convert.FromHexString(expected),
            HostKeyVerifier.EncodeEcdsaDerSig(Convert.FromHexString(r), Convert.FromHexString(s)));
    }

    [Theory]
    [InlineData(60, false)]
    [InlineData(61, true)]
    [InlineData(66, true)]
    public void DerSequence_UsesCorrectLengthForm(int size, bool longForm)
    {
        byte[] integer = Enumerable.Repeat((byte)0x80, size).ToArray();
        byte[] encoded = HostKeyVerifier.EncodeEcdsaDerSig(integer, integer);
        int sequenceLength = 6 + 2 * size;
        byte[] header = longForm ? [(byte)0x30, 0x81, (byte)sequenceLength] : [(byte)0x30, (byte)sequenceLength];
        Assert.Equal(header, encoded[..header.Length]);
        Assert.Equal(header.Length + sequenceLength, encoded.Length);
        for (int offset = header.Length; offset < encoded.Length; offset += size + 3)
        {
            Assert.Equal(2, encoded[offset]);
            Assert.Equal(size + 1, encoded[offset + 1]);
            Assert.Equal(0, encoded[offset + 2]);
            Assert.Equal(integer, encoded.AsSpan(offset + 3, size).ToArray());
        }
        integer[0] = 0;
        Assert.Equal(0x80, encoded[header.Length + 3]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ssh-ed25519")]
    [InlineData("ecdsa-sha2-nistp521")]
    [InlineData("署名")]
    public void SshBlob_PreservesEncodingAndOwnsOutput(string name)
    {
        VerifyBlob(name);
    }

    [Fact]
    public void SshBlob_PreservesMalformedUtf16Replacement() => VerifyBlob("sig" + (char)0xD800);

    private static void VerifyBlob(string name)
    {
        byte[] raw = [0, 0x80, 0xff];
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] result = SshSign.BuildSshSigBlob(name, raw);
        Assert.Equal(nameBytes.Length, BinaryPrimitives.ReadInt32BigEndian(result));
        Assert.Equal(nameBytes, result.AsSpan(4, nameBytes.Length).ToArray());
        Assert.Equal(3, BinaryPrimitives.ReadInt32BigEndian(result.AsSpan(4 + nameBytes.Length)));
        Assert.Equal(raw, result.AsSpan(8 + nameBytes.Length).ToArray());
        raw[0] = 42;
        Assert.Equal(0, result[8 + nameBytes.Length]);
    }
}
