using System.Buffers;
using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.Agent;

/// <summary>
/// Wire-protocol constants and parsers for the SSH agent protocol
/// (PROTOCOL.agent — the OpenSSH agent spec, ports 11/12/13/14). All message
/// types are SSH2 (SSH1 message types 1-9 are deliberately not ported — see
/// <c>agent.c:65-100</c>, all in <c>#if 0</c>).
/// </summary>
/// <remarks>
/// <para>
/// The agent protocol is symmetric length-prefixed framing: every request and
/// response is <c>[4-byte BE length][payload]</c> where the first byte of the
/// payload is the message-type byte. This file holds only the message-type
/// constants and pure parsers; the actual byte transport lives in
/// <see cref="IAgentTransport"/> implementations (Unix socket now; Pageant
/// and Windows OpenSSH named-pipe backends deferred).
/// </para>
/// <para>
/// <b>Constant values are <c>internal</c> not <c>public</c></b> — the agent is
/// consumed via <see cref="SshAgent"/>'s typed surface; callers never construct
/// wire messages directly. Values match <c>agent.c:65-108</c> verbatim.
/// </para>
/// </remarks>
internal static class AgentProtocol
{
    // ── SSH2 message types (active; the only ones LibSsh2CS sends/receives) ──

    /// <summary>Client → agent: request the list of loaded identities.</summary>
    public const byte MsgRequestIdentities = 11;

    /// <summary>Agent → client: the list of identities (count + blob/comment pairs).</summary>
    public const byte MsgIdentitiesAnswer = 12;

    /// <summary>Client → agent: request a signature with an identity.</summary>
    public const byte MsgSignRequest = 13;

    /// <summary>Agent → client: the requested signature.</summary>
    public const byte MsgSignResponse = 14;

    // ── Generic status codes ──

    /// <summary>Agent → client: request failed (parity <c>agent.c:89</c>).</summary>
    public const byte MsgFailure = 5;

    /// <summary>Agent → client: request succeeded (parity <c>agent.c:90</c>).</summary>
    public const byte MsgSuccess = 6;

    // ── Sign-request flag bits (parity <c>agent.c:107-108</c>) ──
    //
    // These are passed to <see cref="AgentSignFlags"/> values verbatim; the
    // constants here are the wire-level bit values.

    /// <summary>Sign with RSA-SHA2-256 (RFC 8332). Ignored for non-RSA keys.</summary>
    public const uint FlagRsaSha2_256 = 2;

    /// <summary>Sign with RSA-SHA2-512 (RFC 8332). Ignored for non-RSA keys.</summary>
    public const uint FlagRsaSha2_512 = 4;

    // ════════════════════════════════════════════════════════════════════════
    // Request builders (return payload only — transport adds the 4-byte length prefix)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Builds the <see cref="MsgRequestIdentities"/> payload: a single byte.
    /// Mirrors <c>agent.c:629-636</c>.
    /// </summary>
    public static byte[] BuildRequestIdentities()
        => [MsgRequestIdentities];

    internal static int GetSignRequestPayloadLength(int publicKeyBlobLength, int dataLength)
        => 1 + 4 + publicKeyBlobLength + 4 + dataLength + 4;

    /// <summary>
    /// Builds the <see cref="MsgSignRequest"/> payload:
    /// <c>[byte 13][string public_key_blob][string data_to_sign][uint32 flags]</c>.
    /// Mirrors <c>agent.c:463-488</c>. <paramref name="flags"/> is the bitwise-OR
    /// of <see cref="FlagRsaSha2_256"/> / <see cref="FlagRsaSha2_512"/> (or 0 for
    /// no SHA-2 hint — agent picks default, typically SHA-1).
    /// </summary>
    public static byte[] BuildSignRequest(ReadOnlySpan<byte> publicKeyBlob, ReadOnlySpan<byte> data, uint flags)
    {
        int len = GetSignRequestPayloadLength(publicKeyBlob.Length, data.Length);
        byte[] payload = new byte[len];
        BuildSignRequest(payload, publicKeyBlob, data, flags);
        return payload;
    }

    internal static void BuildSignRequest(Span<byte> destination, ReadOnlySpan<byte> publicKeyBlob, ReadOnlySpan<byte> data, uint flags)
    {
        if (destination.Length < GetSignRequestPayloadLength(publicKeyBlob.Length, data.Length))
        {
            throw new ArgumentException("Destination buffer is too small", nameof(destination));
        }

        int offset = 0;
        destination[offset++] = MsgSignRequest;
        WriteString(destination, ref offset, publicKeyBlob);
        WriteString(destination, ref offset, data);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset, 4), flags);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Response parsers (input is the full payload minus the 4-byte length prefix)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses an <see cref="MsgIdentitiesAnswer"/> payload into a list of
    /// <c>(blob, comment)</c> pairs. Mirrors <c>agent.c:670-714</c>.
    /// </summary>
    /// <param name="payload">The full payload starting with the type byte (12).</param>
    /// <returns>The list of identities in the order the agent returned them.</returns>
    public static List<(byte[] Blob, string Comment)> ParseIdentitiesAnswer(ReadOnlyMemory<byte> payload)
        => ParseIdentitiesAnswer(new ReadOnlySequence<byte>(payload));

    internal static List<(byte[] Blob, string Comment)> ParseIdentitiesAnswer(ReadOnlySequence<byte> payload)
    {
        try
        {
            return ParseIdentitiesAnswerCore(payload);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            // Parity agent.c:647-718: every truncation in the identities
            // response parse is LIBSSH2_ERROR_AGENT_PROTOCOL — previously the
            // reader's OutOfBoundary escaped.
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Agent response truncated: {ex.Message}", ex);
        }
    }

    private static List<(byte[] Blob, string Comment)> ParseIdentitiesAnswerCore(ReadOnlySequence<byte> payload)
    {
        var r = new PacketWireReader(payload);
        byte type = r.ReadByte();
        if (type != MsgIdentitiesAnswer)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Agent returned unexpected message type {type} (expected {MsgIdentitiesAnswer} identities-answer)");
        }

        uint count = r.ReadUInt32BigEndian();
        if (count > 1024)
        {
            // Cap to defend against a malicious or buggy agent.
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Agent returned too many identities ({count} > 1024)");
        }

        var result = new List<(byte[] Blob, string Comment)>((int)count);
        for (int i = 0; i < (int)count; i++)
        {
            byte[] blob = r.ReadBlob();
            byte[] commentBytes = r.ReadBlob();
            string comment = Encoding.UTF8.GetString(commentBytes);
            result.Add((blob, comment));
        }

        return result;
    }

    /// <summary>
    /// Parses an <see cref="MsgSignResponse"/> payload and extracts the SSH
    /// signature blob. Mirrors <c>agent.c:511-591</c>.
    /// </summary>
    /// <param name="payload">The full payload starting with the type byte (14).</param>
    /// <returns>The signature blob (<c>[string algo][string rawSig]</c>).</returns>
    public static byte[] ParseSignResponse(ReadOnlyMemory<byte> payload)
        => ParseSignResponse(new ReadOnlySequence<byte>(payload));

    internal static byte[] ParseSignResponse(ReadOnlySequence<byte> payload)
    {
        try
        {
            return ParseSignResponseCore(payload);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            // Parity agent.c:511-591: truncation in the sign-response parse is
            // LIBSSH2_ERROR_AGENT_PROTOCOL.
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Agent response truncated: {ex.Message}", ex);
        }
    }

    private static byte[] ParseSignResponseCore(ReadOnlySequence<byte> payload)
    {
        var r = new PacketWireReader(payload);
        byte type = r.ReadByte();
        if (type != MsgSignResponse)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Agent returned unexpected message type {type} (expected {MsgSignResponse} sign-response)");
        }

        // The response is: [14][string sig_blob]. The sig_blob itself contains
        // [string algoName][string rawSig]. The agent returns the full SSH
        // signature blob, which is exactly what UserAuth.AppendSignature expects.
        return r.ReadBlob();
    }

    /// <summary>
    /// Throws <see cref="SshException"/> with the appropriate code for a
    /// generic <see cref="MsgFailure"/> response. Mirrors <c>agent.c:565-575</c>
    /// (failure → <c>LIBSSH2_ERROR_AGENT_FAILURE</c>).
    /// </summary>
    public static Exception CreateFailureException(string operation)
        => new SshException(SshErrorCode.AgentProtocol,
            $"SSH agent returned SSH_AGENT_FAILURE for {operation}");

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>Writes an SSH string (BE32 length + raw bytes) and advances the offset.</summary>
    private static void WriteString(Span<byte> buf, ref int offset, ReadOnlySpan<byte> bytes)
    {
        BinaryPrimitives.WriteInt32BigEndian(buf.Slice(offset, 4), bytes.Length);
        offset += 4;
        bytes.CopyTo(buf.Slice(offset));
        offset += bytes.Length;
    }
}
