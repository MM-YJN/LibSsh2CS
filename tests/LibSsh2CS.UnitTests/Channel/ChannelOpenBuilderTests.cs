using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Phase 5.2 payload-builder tests — verifies the generalized
/// <see cref="SshChannel.BuildChannelOpenPayload"/> (channel-type + extra data)
/// and the new <c>BuildChannelOpenConfirmationPayload</c> /
/// <c>BuildChannelOpenFailurePayload</c> helpers produce byte-exact wire
/// payloads. These builders are reused by Phase 5.4 (direct-tcpip /
/// direct-streamlocal factories) and Phase 5.6 (server-initiated channel-open
/// dispatch).
/// </summary>
public class ChannelOpenBuilderTests
{
    // ── BuildChannelOpenPayload ───────────────────────────────────────────

    [Fact]
    public void BuildOpen_SessionType_NoExtra_MatchesOldHardcodedShape()
    {
        // Parity with the pre-5.2 hard-coded "session" builder
        // (channel.c:199-203):
        //   [90][string "session"][u32 localId][u32 window][u32 packet]
        byte[] payload = SshChannel.BuildChannelOpenPayload(
            channelType: "session", localId: 7,
            window: ChannelConstants.WindowDefault,
            packet: ChannelConstants.PacketDefault,
            extra: default);

        Assert.Equal(24, payload.Length);
        Assert.Equal((byte)PacketType.ChannelOpen, payload[0]);
        Assert.Equal("session", ReadStringAt(payload, 1));
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(12, 4)));
        Assert.Equal(ChannelConstants.WindowDefault,
            BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(16, 4)));
        Assert.Equal(ChannelConstants.PacketDefault,
            BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(20, 4)));
    }

    [Fact]
    public void BuildOpen_ArbitraryType_NoExtra_UsesGivenType()
    {
        byte[] payload = SshChannel.BuildChannelOpenPayload(
            channelType: "direct-tcpip", localId: 99,
            window: 1024, packet: 2048, extra: default);

        Assert.Equal("direct-tcpip", ReadStringAt(payload, 1));
        Assert.Equal(99u, ReadU32At(payload, 1 + 4 + "direct-tcpip".Length));
        Assert.Equal(1024u, ReadU32At(payload, 1 + 4 + "direct-tcpip".Length + 4));
        Assert.Equal(2048u, ReadU32At(payload, 1 + 4 + "direct-tcpip".Length + 8));
    }

    [Fact]
    public void BuildOpen_WithExtra_AppendsExtraAfterStandardHeader()
    {
        // Direct-tcpip-like: extra = [string host][u32 port][string shost][u32 sport]
        byte[] host = Encoding.ASCII.GetBytes("example.com");
        byte[] shost = Encoding.ASCII.GetBytes("127.0.0.1");
        byte[] extra = new byte[4 + host.Length + 4 + 4 + shost.Length + 4];
        int o = 0;
        WriteString(extra, ref o, host);
        BinaryPrimitives.WriteUInt32BigEndian(extra.AsSpan(o, 4), 80u);
        o += 4;
        WriteString(extra, ref o, shost);
        BinaryPrimitives.WriteUInt32BigEndian(extra.AsSpan(o, 4), 0u);

        const string ChannelType = "direct-tcpip";
        byte[] payload = SshChannel.BuildChannelOpenPayload(
            channelType: ChannelType, localId: 5,
            window: ChannelConstants.WindowDefault,
            packet: ChannelConstants.PacketDefault,
            extra: extra);

        // Header = 1 (type) + 4 (strlen) + type.Length + 4 + 4 + 4 (localId/window/packet).
        int headerLen = 1 + 4 + ChannelType.Length + 4 + 4 + 4;
        Assert.Equal(headerLen + extra.Length, payload.Length);

        // Extra starts immediately after the header.
        byte[] actualExtra = payload.AsSpan(headerLen, extra.Length).ToArray();
        Assert.Equal(extra, actualExtra);
    }

    [Fact]
    public void BuildOpen_StreamLocalAtOpenssh_DotCom_TypePreservedVerbatim()
    {
        // Channel type names containing @ and . must round-trip byte-for-byte.
        byte[] payload = SshChannel.BuildChannelOpenPayload(
            channelType: "direct-streamlocal@openssh.com", localId: 0,
            window: 0, packet: 0, extra: default);

        Assert.Equal("direct-streamlocal@openssh.com", ReadStringAt(payload, 1));
    }

    // ── BuildChannelOpenConfirmationPayload ───────────────────────────────

    [Fact]
    public void BuildConfirmation_MatchesPacketDotC_210_216_Shape()
    {
        // packet.c:210-216: [91][u32 recip][u32 sender][u32 window][u32 packet] — 17 bytes.
        byte[] payload = SshChannel.BuildChannelOpenConfirmationPayload(
            recipientChannel: 100, senderChannel: 200, window: 0x100000, maxPacket: 0x8000);

        Assert.Equal(17, payload.Length);
        Assert.Equal((byte)PacketType.ChannelOpenConfirmation, payload[0]);
        Assert.Equal(100u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
        Assert.Equal(200u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4)));
        Assert.Equal(0x100000u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(9, 4)));
        Assert.Equal(0x8000u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(13, 4)));
    }

    // ── BuildChannelOpenFailurePayload ────────────────────────────────────

    [Fact]
    public void BuildFailure_AdministrativelyProhibited_EncodesReasonAndDescription()
    {
        // channel.c:253-257: [92][u32 recip][u32 reason][string desc][string lang].
        byte[] payload = SshChannel.BuildChannelOpenFailurePayload(
            recipientChannel: 42,
            reason: ChannelConstants.OpenAdministrativelyProhibited,
            description: "forwarding not requested",
            lang: "");

        Assert.Equal((byte)PacketType.ChannelOpenFailure, payload[0]);
        Assert.Equal(42u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
        Assert.Equal((uint)ChannelConstants.OpenAdministrativelyProhibited,
            BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4)));
        Assert.Equal("forwarding not requested", ReadStringAt(payload, 9));

        // Language tag follows the description.
        int langOffset = 9 + 4 + "forwarding not requested".Length;
        Assert.Equal(string.Empty, ReadStringAt(payload, langOffset));
    }

    [Fact]
    public void BuildFailure_ResourceShortage_WhenQueueFull()
    {
        byte[] payload = SshChannel.BuildChannelOpenFailurePayload(
            recipientChannel: 7,
            reason: ChannelConstants.OpenResourceShortage,
            description: "listener queue full",
            lang: "en");

        Assert.Equal((uint)ChannelConstants.OpenResourceShortage,
            BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4)));
    }

    [Fact]
    public void BuildFailure_UnknownChannelType_ReasonThree()
    {
        byte[] payload = SshChannel.BuildChannelOpenFailurePayload(
            recipientChannel: 0,
            reason: ChannelConstants.OpenUnknownChannelType,
            description: "x11 not supported",
            lang: "");

        Assert.Equal((uint)ChannelConstants.OpenUnknownChannelType,
            BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4)));
    }

    [Fact]
    public void BuildFailure_NullDescription_EncodesAsEmptyString()
    {
        byte[] payload = SshChannel.BuildChannelOpenFailurePayload(
            recipientChannel: 1, reason: 1, description: null!, lang: null!);

        Assert.Equal(string.Empty, ReadStringAt(payload, 9));
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// <summary>Reads an SSH string (BE32 length + bytes) at the given offset.</summary>
    private static string ReadStringAt(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        return Encoding.ASCII.GetString(buf, offset + 4, (int)len);
    }

    /// <summary>Reads a BE32 at the given offset.</summary>
    private static uint ReadU32At(byte[] buf, int offset)
        => BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));

    /// <summary>Writes an SSH string (BE32 length + bytes) and advances the offset.</summary>
    private static void WriteString(byte[] buf, ref int offset, byte[] bytes)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(offset, 4), (uint)bytes.Length);
        offset += 4;
        Buffer.BlockCopy(bytes, 0, buf, offset, bytes.Length);
        offset += bytes.Length;
    }
}
