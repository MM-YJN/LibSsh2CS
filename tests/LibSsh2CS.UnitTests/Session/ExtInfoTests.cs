using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// ExtInfo.Parse tests — verifies the SSH_MSG_EXT_INFO (RFC 8308) parser
/// extracts <c>server-sig-algs</c> correctly, the value that drives RSA-SHA2
/// algorithm selection in UserAuth.
/// </summary>
public class ExtInfoTests
{
    /// <summary>
    /// Parses a minimal EXT_INFO with a single <c>server-sig-algs</c> extension;
    /// asserts the algorithms are split on commas.
    /// </summary>
    [Fact]
    public void Parse_SingleServerSigAlgs_SplitsOnComma()
    {
        byte[] payload = BuildExtInfoPayload(
            ("server-sig-algs", "ssh-rsa,rsa-sha2-256,rsa-sha2-512"));
        var ext = ExtInfo.Parse(payload);

        Assert.Equal(
            new[] { "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512" },
            ext.ServerSignatureAlgorithms);
        Assert.Single(ext.Extensions);
        Assert.Equal("server-sig-algs", ext.Extensions[0].Name);
    }

    /// <summary>
    /// Parses an EXT_INFO with two extensions (server-sig-algs + a future one);
    /// asserts both are surfaced in wire order and server-sig-algs is split.
    /// </summary>
    [Fact]
    public void Parse_TwoExtensions_KeepsBothInWireOrder()
    {
        byte[] payload = BuildExtInfoPayload(
            ("server-sig-algs", "rsa-sha2-256,rsa-sha2-512"),
            ("ping@openssh.com", "0"));
        var ext = ExtInfo.Parse(payload);

        Assert.Equal(2, ext.Extensions.Length);
        Assert.Equal("server-sig-algs", ext.Extensions[0].Name);
        Assert.Equal("ping@openssh.com", ext.Extensions[1].Name);
        Assert.Equal(
            new[] { "rsa-sha2-256", "rsa-sha2-512" },
            ext.ServerSignatureAlgorithms);
    }

    /// <summary>
    /// An EXT_INFO without server-sig-algs yields an empty array (not null).
    /// </summary>
    [Fact]
    public void Parse_NoServerSigAlgs_ReturnsEmptyArray()
    {
        byte[] payload = BuildExtInfoPayload(("no-such-extension", "value"));
        var ext = ExtInfo.Parse(payload);
        Assert.Empty(ext.ServerSignatureAlgorithms);
    }

    /// <summary>
    /// An empty server-sig-algs value (zero-length string) yields an empty
    /// array, not a single empty-string element.
    /// </summary>
    [Fact]
    public void Parse_EmptyServerSigAlgsValue_ReturnsEmptyArray()
    {
        byte[] payload = BuildExtInfoPayload(("server-sig-algs", ""));
        var ext = ExtInfo.Parse(payload);
        Assert.Empty(ext.ServerSignatureAlgorithms);
    }

    /// <summary>
    /// A payload that does not begin with the EXT_INFO type byte (7) is rejected
    /// with Proto.
    /// </summary>
    [Fact]
    public void Parse_WrongTypeByte_ThrowsProto()
    {
        byte[] payload = new byte[] { 0x06, 0x00, 0x00, 0x00, 0x00 }; // SERVICE_ACCEPT, not EXT_INFO
        Assert.Throws<SshException>(() => ExtInfo.Parse(payload));
    }

    /// <summary>
    /// A truncated EXT_INFO (nr-extensions claims more than the payload carries)
    /// is rejected with OutOfBoundary / Proto.
    /// </summary>
    [Fact]
    public void Parse_Truncated_Throws()
    {
        // nr-extensions = 1, but no name/value pair follows.
        byte[] payload = new byte[] { 0x07, 0x00, 0x00, 0x00, 0x01 };
        Assert.Throws<SshException>(() => ExtInfo.Parse(payload));
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds an SSH_MSG_EXT_INFO payload: [7] [uint32 nr] [ [string name]
    /// [string value] ]*. Mirrors the wire format in RFC 8308 §2.2.
    /// </summary>
    private static byte[] BuildExtInfoPayload(params (string Name, string Value)[] extensions)
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)PacketType.ExtInfo);

        byte[] nr = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(nr, (uint)extensions.Length);
        ms.Write(nr, 0, 4);

        foreach ((string name, string value) in extensions)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);
            byte[] nameLen = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(nameLen, (uint)nameBytes.Length);
            ms.Write(nameLen, 0, 4);
            ms.Write(nameBytes, 0, nameBytes.Length);
            byte[] valueLen = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(valueLen, (uint)valueBytes.Length);
            ms.Write(valueLen, 0, 4);
            ms.Write(valueBytes, 0, valueBytes.Length);
        }

        return ms.ToArray();
    }
}
