using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Shared test harness for channel tests: builds a pair of cleartext SSH pipes
/// (client↔server) wrapped in <see cref="PacketReader"/>/<see cref="PacketWriter"/>
/// and a <see cref="ChannelRouter"/> over the client's inbound queue.
/// </summary>
/// <remarks>
/// Tests run in cleartext (pre-NEWKEYS) mode — no cipher /
/// MAC key installation. The channel protocol is cipher-independent, so a
/// cleartext pipe pair is sufficient and matches the pattern in
/// <c>RunExchangeFlowTests</c>. The mock "server" is the test thread driving
/// <see cref="ServerWriter"/> (feed inbound packets to the client) and
/// <see cref="ServerReader"/> (read the client's outbound packets).
/// </remarks>
internal sealed class ChannelTestHarness : IDisposable
{
    /// <summary>Client→server pipe: the client writes, the mock server reads.</summary>
    private readonly Pipe _c2s = new();

    /// <summary>Server→client pipe: the mock server writes, the client reads.</summary>
    private readonly Pipe _s2c = new();

    /// <summary>Constructs the harness with a fresh router over the client pipes.</summary>
    public ChannelTestHarness()
    {
        ClientWriter = new PacketWriter(_c2s.Writer);
        var queue = new PacketQueue(new PacketReader(_s2c.Reader));
        Router = new ChannelRouter(queue, ClientWriter);
        ServerReader = new PacketReader(_c2s.Reader);
    }

    // ── Client side (the system under test) ────────────────────────────────

    /// <summary>The client's outbound writer (used to construct channels).</summary>
    public PacketWriter ClientWriter { get; }

    /// <summary>The channel router under test (sole reader of the client's inbound queue).</summary>
    public ChannelRouter Router { get; }

    // ── Mock-server side ───────────────────────────────────────────────────

    /// <summary>Reads the client's OUTBOUND packets (to assert wire bytes).</summary>
    public PacketReader ServerReader { get; }

    /// <summary>
    /// Writes INBOUND packets to the client (feed the router). Tests write
    /// cleartext packet bytes here, then call <see cref="CompleteInbound"/> so
    /// the client reader sees them (and EOF after).
    /// </summary>
    public PipeWriter ServerWriter => _s2c.Writer;

    /// <summary>Completes the inbound writer so the client reader observes queued packets.</summary>
    public void CompleteInbound() => _s2c.Writer.Complete();

    /// <summary>Completes the outbound writer so the mock-server reader sees EOF
    /// after any packets the client wrote. Used by tests that assert "the client
    /// wrote nothing" (ServerReader then throws completed-empty).</summary>
    public void CompleteOutbound() => _c2s.Writer.Complete();

    /// <summary>
    /// Completes both pipe writers so the harness releases its pipe resources.
    /// Wrapped in try/catch because a test may have already completed a writer
    /// (e.g. via <see cref="CompleteInbound"/>); double-completion throws
    /// <see cref="InvalidOperationException"/> but is harmless here.
    /// </summary>
    public void Dispose()
    {
        try
        {
            _c2s.Writer.Complete();
        }
        catch (InvalidOperationException) { }
        try
        {
            _s2c.Writer.Complete();
        }
        catch (InvalidOperationException) { }
    }

    /// <summary>Writes one or more raw (already-framed) packets to the client's inbound pipe.</summary>
    public async Task FeedInboundAsync(params byte[][] packets)
    {
        foreach (byte[] pkt in packets)
        {
            await _s2c.Writer.WriteAsync(pkt, TestContext.Current.CancellationToken);
        }
    }

    // ── Channel factory ────────────────────────────────────────────────────

    /// <summary>
    /// Constructs a <see cref="SshChannel"/> against this harness and optionally
    /// registers it with the router. <paramref name="localId"/> defaults to the
    /// next allocated id; <paramref name="remoteId"/> to <c>localId + 100</c>
    /// (an arbitrary peer id distinct from the local id).
    /// </summary>
    public SshChannel CreateChannel(
        uint? localId = null,
        uint? remoteId = null,
        bool register = true,
        uint outboundWindow = ChannelConstants.WindowDefault,
        uint outboundMaxPacket = ChannelConstants.PacketDefault,
        uint inboundWindow = ChannelConstants.WindowDefault,
        uint inboundMaxPacket = ChannelConstants.PacketDefault)
    {
        uint lid = localId ?? Router.AllocateLocalId();
        uint rid = remoteId ?? lid + 100;
        var channel = new SshChannel(ClientWriter, Router, lid, rid,
            outboundWindow, outboundMaxPacket, inboundWindow, inboundMaxPacket);
        if (register)
        {
            Router.Register(channel);
        }

        return channel;
    }

    // ── Packet builders ────────────────────────────────────────────────────

    /// <summary>
    /// Frames a cleartext SSH packet (length|padlen|payload|padding) carrying
    /// the given payload, whose first byte must equal <paramref name="type"/>.
    /// Mirror of <c>PacketQueueTests.BuildCleartextPacket</c>.
    /// </summary>
    public static byte[] BuildCleartextPacket(int type, byte[] payload)
    {
        if (payload.Length == 0 || payload[0] != type)
        {
            byte[] withType = new byte[payload.Length + 1];
            withType[0] = (byte)type;
            Buffer.BlockCopy(payload, 0, withType, 1, payload.Length);
            payload = withType;
        }

        // blocksize=8 cleartext. packet_length = payload + 1 + padding.
        int withHeader = payload.Length + 1 + 4;
        int padding = 8 - (withHeader % 8);
        if (padding < 4)
        {
            padding += 8;
        }

        int packetLength = payload.Length + 1 + padding;
        byte[] wire = new byte[4 + packetLength];
        BinaryPrimitives.WriteUInt32BigEndian(wire, (uint)packetLength);
        wire[4] = (byte)padding;
        Buffer.BlockCopy(payload, 0, wire, 5, payload.Length);
        return wire;
    }

    /// <summary>Builds a <c>SSH_MSG_CHANNEL_DATA</c> payload: [94][u32 recip][u32 datalen][data].</summary>
    public static byte[] BuildChannelDataPayload(uint recipientChannel, byte[] data)
    {
        byte[] payload = new byte[1 + 4 + 4 + data.Length];
        payload[0] = (byte)PacketType.ChannelData;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), (uint)data.Length);
        Buffer.BlockCopy(data, 0, payload, 9, data.Length);
        return payload;
    }

    /// <summary>
    /// Builds a <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> payload:
    /// [95][u32 recip][u32 datatype][u32 datalen][data].
    /// </summary>
    public static byte[] BuildChannelExtendedDataPayload(uint recipientChannel, uint dataTypeCode, byte[] data)
    {
        byte[] payload = new byte[1 + 4 + 4 + 4 + data.Length];
        payload[0] = (byte)PacketType.ChannelExtendedData;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), dataTypeCode);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), (uint)data.Length);
        Buffer.BlockCopy(data, 0, payload, 13, data.Length);
        return payload;
    }

    /// <summary>Builds a <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> payload: [93][u32 recip][u32 bytestoadd].</summary>
    public static byte[] BuildWindowAdjustPayload(uint recipientChannel, uint bytesToAdd)
    {
        byte[] payload = new byte[9];
        payload[0] = (byte)PacketType.ChannelWindowAdjust;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), bytesToAdd);
        return payload;
    }

    /// <summary>Builds a <c>SSH_MSG_CHANNEL_EOF</c> payload: [96][u32 recip].</summary>
    public static byte[] BuildEofPayload(uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelEof;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }

    /// <summary>Builds a <c>SSH_MSG_CHANNEL_CLOSE</c> payload: [97][u32 recip].</summary>
    public static byte[] BuildClosePayload(uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelClose;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }

    /// <summary>
    /// Builds a <c>SSH_MSG_CHANNEL_REQUEST</c> "exit-status" payload:
    /// [98][u32 recip][string "exit-status"][bool want_reply][u32 status].
    /// </summary>
    public static byte[] BuildExitStatusPayload(uint recipientChannel, int exitStatus, bool wantReply)
    {
        byte[] reason = System.Text.Encoding.ASCII.GetBytes("exit-status");
        byte[] payload = new byte[1 + 4 + 4 + reason.Length + 1 + 4];
        int o = 0;
        payload[o++] = (byte)PacketType.ChannelRequest;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), recipientChannel);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)reason.Length);
        o += 4;
        Buffer.BlockCopy(reason, 0, payload, o, reason.Length);
        o += reason.Length;
        payload[o++] = (byte)(wantReply ? 1 : 0);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)exitStatus);
        return payload;
    }

    /// <summary>
    /// Builds a <c>SSH_MSG_CHANNEL_REQUEST</c> "exit-signal" payload:
    /// [98][u32 recip][string "exit-signal"][bool want_reply][string signal][bool core]
    /// [string errmsg][string lang].
    /// </summary>
    public static byte[] BuildExitSignalPayload(uint recipientChannel, string signal, bool wantReply)
    {
        byte[] reason = System.Text.Encoding.ASCII.GetBytes("exit-signal");
        byte[] sig = System.Text.Encoding.ASCII.GetBytes(signal);
        byte[] errmsg = System.Text.Encoding.ASCII.GetBytes("");
        byte[] lang = System.Text.Encoding.ASCII.GetBytes("");
        byte[] payload = new byte[1 + 4 + 4 + reason.Length + 1
            + 4 + sig.Length + 1 + 4 + errmsg.Length + 4 + lang.Length];
        int o = 0;
        payload[o++] = (byte)PacketType.ChannelRequest;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), recipientChannel);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)reason.Length);
        o += 4;
        Buffer.BlockCopy(reason, 0, payload, o, reason.Length);
        o += reason.Length;
        payload[o++] = (byte)(wantReply ? 1 : 0);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)sig.Length);
        o += 4;
        Buffer.BlockCopy(sig, 0, payload, o, sig.Length);
        o += sig.Length;
        payload[o++] = 0;   // core dumped = false
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)errmsg.Length);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)lang.Length);
        return payload;
    }

    /// <summary>
    /// Builds a <c>SSH_MSG_CHANNEL_OPEN_CONFIRMATION</c> payload (the reply the
    /// open flow waits for): [91][u32 recip=local][u32 sender=remote][u32 window][u32 packet].
    /// </summary>
    public static byte[] BuildOpenConfirmationPayload(
        uint recipientChannel, uint senderChannel, uint window, uint maxPacket)
    {
        byte[] payload = new byte[17];
        payload[0] = (byte)PacketType.ChannelOpenConfirmation;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), senderChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), window);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(13, 4), maxPacket);
        return payload;
    }
}
