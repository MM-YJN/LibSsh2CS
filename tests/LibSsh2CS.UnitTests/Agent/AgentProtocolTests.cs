using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Tests for the pure agent-protocol parsers and request builders in
/// <see cref="AgentProtocol"/>. These verify the wire byte-exact structure of
/// agent messages without any socket I/O.
/// </summary>
/// <remarks>
/// The wire format is the OpenSSH agent protocol (PROTOCOL.agent):
/// <code>
///   SSH2_AGENTC_REQUEST_IDENTITIES  = 11  (client → agent, no body)
///   SSH2_AGENT_IDENTITIES_ANSWER    = 12  (agent → client: count + [blob, comment]*)
///   SSH2_AGENTC_SIGN_REQUEST        = 13  (client → agent: blob + data + flags)
///   SSH2_AGENT_SIGN_RESPONSE        = 14  (agent → client: sig blob)
///   SSH_AGENT_FAILURE               = 5
/// </code>
/// </remarks>
public class AgentProtocolTests
{
    // ════════════════════════════════════════════════════════════════════════
    // Constants
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Constants_Match_AgentC_Values()
    {
        // Parity with agent.c:65-108 — values must not change.
        Assert.Equal(11, AgentProtocol.MsgRequestIdentities);
        Assert.Equal(12, AgentProtocol.MsgIdentitiesAnswer);
        Assert.Equal(13, AgentProtocol.MsgSignRequest);
        Assert.Equal(14, AgentProtocol.MsgSignResponse);
        Assert.Equal(5, AgentProtocol.MsgFailure);
        Assert.Equal(6, AgentProtocol.MsgSuccess);
        Assert.Equal(2u, AgentProtocol.FlagRsaSha2_256);
        Assert.Equal(4u, AgentProtocol.FlagRsaSha2_512);
    }

    // ════════════════════════════════════════════════════════════════════════
    // BuildRequestIdentities
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void BuildRequestIdentities_SingleByte_11()
    {
        byte[] payload = AgentProtocol.BuildRequestIdentities();

        Assert.Single(payload);
        Assert.Equal(11, payload[0]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // BuildSignRequest
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sign request structure: [13][string blob][string data][uint32 flags].
    /// Parity with agent.c:463-488.
    /// </summary>
    [Fact]
    public void BuildSignRequest_Wire_Byte_Exact()
    {
        byte[] blob = [0x00, 0x00, 0x00, 0x0B, (byte)'s', (byte)'s', (byte)'h', (byte)'-', (byte)'e', (byte)'d', (byte)'2', (byte)'5', (byte)'5', (byte)'1', (byte)'9', 1, 2, 3];  // 4 + 11 + 3 = 18
        byte[] data = [0xAB, 0xCD, 0xEF];
        uint flags = AgentProtocol.FlagRsaSha2_256 | AgentProtocol.FlagRsaSha2_512;

        byte[] payload = AgentProtocol.BuildSignRequest(blob, data, flags);

        // Expected layout:
        //   [0]    = 13 (MsgSignRequest)
        //   [1-4]  = BE32 18 (blob length)
        //   [5-22] = blob bytes
        //   [23-26] = BE32 3 (data length)
        //   [27-29] = data bytes
        //   [30-33] = BE32 flags (6 = SHA256|SHA512)
        Assert.Equal(34, payload.Length);
        Assert.Equal(13, payload[0]);

        Assert.Equal(18u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
        Assert.Equal(blob, payload.AsSpan(5, 18).ToArray());

        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(23, 4)));
        Assert.Equal(data, payload.AsSpan(27, 3).ToArray());

        Assert.Equal(6u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(30, 4)));
    }

    [Fact]
    public void BuildSignRequest_ZeroFlags()
    {
        byte[] payload = AgentProtocol.BuildSignRequest([0x01], [0x02], 0);

        // Layout: [13][BE32 1][0x01][BE32 1][0x02][BE32 0] = 15 bytes
        Assert.Equal(15, payload.Length);
        Assert.Equal(13, payload[0]);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(11, 4)));
    }

    // ════════════════════════════════════════════════════════════════════════
    // ParseIdentitiesAnswer
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses a well-formed identities-answer payload with two identities.
    /// Parity with agent.c:670-714.
    /// </summary>
    [Fact]
    public void ParseIdentitiesAnswer_TwoIdentities_ReturnsBoth()
    {
        byte[] blob1 = BuildString(Encoding.UTF8.GetBytes("ssh-ed25519"));
        byte[] blob2 = BuildString(Encoding.UTF8.GetBytes("ssh-rsa"));
        byte[] comment1 = BuildString(Encoding.UTF8.GetBytes("alice@host"));
        byte[] comment2 = BuildString(Encoding.UTF8.GetBytes(""));

        byte[] payload = BuildIdentitiesAnswerPayload([
            (blob1, comment1),
            (blob2, comment2),
        ]);

        List<(byte[] Blob, string Comment)> ids = AgentProtocol.ParseIdentitiesAnswer(payload);

        Assert.Equal(2, ids.Count);
        Assert.Equal(Encoding.UTF8.GetBytes("ssh-ed25519"), ids[0].Blob);
        Assert.Equal("alice@host", ids[0].Comment);
        Assert.Equal(Encoding.UTF8.GetBytes("ssh-rsa"), ids[1].Blob);
        Assert.Equal("", ids[1].Comment);
    }

    [Fact]
    public void ParseIdentitiesAnswer_ZeroIdentities_EmptyList()
    {
        byte[] payload = new byte[5];
        payload[0] = 12;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 0);

        List<(byte[] Blob, string Comment)> ids = AgentProtocol.ParseIdentitiesAnswer(payload);

        Assert.Empty(ids);
    }

    [Fact]
    public void ParseIdentitiesAnswer_WrongTypeByte_Throws()
    {
        // Type byte 99 instead of 12.
        byte[] payload = new byte[5];
        payload[0] = 99;

        SshException ex = Assert.Throws<SshException>(() =>
            AgentProtocol.ParseIdentitiesAnswer(payload));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("99", ex.Message);
        Assert.Contains("12", ex.Message);
    }

    [Fact]
    public void ParseIdentitiesAnswer_CountExceeds1024_Throws()
    {
        byte[] payload = new byte[5];
        payload[0] = 12;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 1025);

        SshException ex = Assert.Throws<SshException>(() =>
            AgentProtocol.ParseIdentitiesAnswer(payload));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("1025", ex.Message);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ParseSignResponse
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sign response: [14][string sig_blob]. The returned sig_blob is opaque
    /// to the transport (it's the SSH signature: [string algo][string rawSig]).
    /// Parity with agent.c:511-591.
    /// </summary>
    [Fact]
    public void ParseSignResponse_ReturnsSigBlob_Intact()
    {
        byte[] sigBlob = [0x00, 0x00, 0x00, 0x0B, (byte)'s', (byte)'s', (byte)'h', (byte)'-', (byte)'e', (byte)'d', (byte)'2', (byte)'5', (byte)'5', (byte)'1', (byte)'9', 0xAA, 0xBB];
        byte[] payload = new byte[1 + 4 + sigBlob.Length];
        payload[0] = 14;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), (uint)sigBlob.Length);
        Buffer.BlockCopy(sigBlob, 0, payload, 5, sigBlob.Length);

        byte[] got = AgentProtocol.ParseSignResponse(payload);

        Assert.Equal(sigBlob, got);
    }

    [Fact]
    public void ParseSignResponse_WrongTypeByte_Throws()
    {
        byte[] payload = new byte[5];
        payload[0] = 99;

        SshException ex = Assert.Throws<SshException>(() =>
            AgentProtocol.ParseSignResponse(payload));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
    }

    // ════════════════════════════════════════════════════════════════════════
    // CreateFailureException
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void CreateFailureException_HasAgentProtocolCode_AndMessage()
    {
        Exception ex = AgentProtocol.CreateFailureException("list identities");

        Assert.IsType<SshException>(ex);
        var sshEx = (SshException)ex;
        Assert.Equal(SshErrorCode.AgentProtocol, sshEx.ErrorCode);
        Assert.Contains("list identities", ex.Message);
        Assert.Contains("SSH_AGENT_FAILURE", ex.Message);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Round-trip
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sign-request built by <see cref="AgentProtocol.BuildSignRequest"/> can
    /// be parsed back via a manual reverse operation — confirms byte-exact
    /// structure without an actual agent.
    /// </summary>
    [Fact]
    public void BuildSignRequest_RoundTrips_Byte_Exact()
    {
        byte[] blob = [0x00, 0x00, 0x00, 0x03, 1, 2, 3];
        byte[] data = [0xDE, 0xAD, 0xBE, 0xEF];
        uint flags = AgentProtocol.FlagRsaSha2_256;

        byte[] req = AgentProtocol.BuildSignRequest(blob, data, flags);

        // Re-parse manually to confirm structure.
        Assert.Equal(13, req[0]);
        int offset = 1;
        int blobLen = (int)BinaryPrimitives.ReadUInt32BigEndian(req.AsSpan(offset, 4));
        offset += 4;
        byte[] gotBlob = req.AsSpan(offset, blobLen).ToArray();
        offset += blobLen;
        int dataLen = (int)BinaryPrimitives.ReadUInt32BigEndian(req.AsSpan(offset, 4));
        offset += 4;
        byte[] gotData = req.AsSpan(offset, dataLen).ToArray();
        offset += dataLen;
        uint gotFlags = BinaryPrimitives.ReadUInt32BigEndian(req.AsSpan(offset, 4));

        Assert.Equal(blob, gotBlob);
        Assert.Equal(data, gotData);
        Assert.Equal(flags, gotFlags);
        Assert.Equal(req.Length, offset + 4);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>Builds an SSH string (BE32 length + bytes).</summary>
    private static byte[] BuildString(byte[] content)
    {
        byte[] s = new byte[4 + content.Length];
        BinaryPrimitives.WriteUInt32BigEndian(s.AsSpan(0, 4), (uint)content.Length);
        Buffer.BlockCopy(content, 0, s, 4, content.Length);
        return s;
    }

    /// <summary>
    /// Builds an identities-answer payload: [12][uint32 count][blob, comment]*.
    /// Each blob and comment is itself an SSH string.
    /// </summary>
    private static byte[] BuildIdentitiesAnswerPayload(
        IReadOnlyList<(byte[] Blob, byte[] Comment)> identities)
    {
        int total = 1 + 4;
        foreach ((byte[] b, byte[] c) in identities)
        {
            total += b.Length + c.Length;
        }

        byte[] payload = new byte[total];
        payload[0] = 12;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), (uint)identities.Count);

        int offset = 5;
        foreach ((byte[] b, byte[] c) in identities)
        {
            Buffer.BlockCopy(b, 0, payload, offset, b.Length);
            offset += b.Length;
            Buffer.BlockCopy(c, 0, payload, offset, c.Length);
            offset += c.Length;
        }

        return payload;
    }
}
