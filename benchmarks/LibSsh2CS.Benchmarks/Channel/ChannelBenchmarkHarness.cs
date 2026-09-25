using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Benchmarks.Transport;
using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Shared setup for the channel benchmarks: a cleartext
/// <see cref="PacketWriter"/> / <see cref="PacketReader"/> pipe pair wrapped in
/// a <see cref="ChannelRouter"/> over the client's inbound queue, plus packet
/// builders for a mock server. Mirrors the unit-test harness
/// (<c>ChannelTestHarness</c>); the channel protocol is cipher-independent, so
/// cleartext (pre-NEWKEYS) framing is sufficient.
/// </summary>
/// <remarks>
/// The pipe pause threshold is parameterized so a producer racing the
/// benchmarked side stays naturally paced by backpressure; allocations made by
/// producer/drain tasks on other threads are excluded from BenchmarkDotNet's
/// per-thread measurement.
/// </remarks>
internal sealed class ChannelBenchmarkHarness : IDisposable
{
    /// <summary>Client→server pipe: the client writes, the mock server reads.</summary>
    private readonly Pipe _c2s;

    /// <summary>Server→client pipe: the mock server writes, the client reads.</summary>
    private readonly Pipe _s2c;

    /// <param name="pipeMegabytes">Per-pipe pause threshold (backpressure bound).</param>
    public ChannelBenchmarkHarness(int pipeMegabytes = 1)
    {
        _c2s = TransportSetup.CreatePipe(pipeMegabytes);
        _s2c = TransportSetup.CreatePipe(pipeMegabytes);
        ClientWriter = new PacketWriter(_c2s.Writer);
        Queue = new PacketQueue(new PacketReader(_s2c.Reader));
        Router = new ChannelRouter(Queue, ClientWriter);
        ServerReader = new PacketReader(_c2s.Reader);
    }

    /// <summary>The client's outbound writer (used to construct channels).</summary>
    public PacketWriter ClientWriter { get; }

    /// <summary>The client's inbound queue (the router's packet source).</summary>
    public PacketQueue Queue { get; }

    /// <summary>The router under test (sole reader of the client's inbound queue).</summary>
    public ChannelRouter Router { get; }

    /// <summary>Reads the client's OUTBOUND packets (the mock-server side).</summary>
    public PacketReader ServerReader { get; }

    /// <summary>Writes INBOUND packets to the client (feeds the router).</summary>
    public PipeWriter ServerWriter => _s2c.Writer;

    /// <summary>
    /// Raw reader over the client's outbound pipe, for benchmarks that just
    /// need the client's writes drained (not parsed). Do not use concurrently
    /// with <see cref="ServerReader"/>.
    /// </summary>
    public PipeReader OutboundReader => _c2s.Reader;

    /// <summary>
    /// Creates and registers a channel with an effectively unbounded inbound
    /// window: benchmarks feed the peer's side directly, so no WINDOW_ADJUST
    /// traffic distorts the measured path.
    /// </summary>
    public SshChannel CreateChannel(uint? localId = null, uint? remoteId = null)
    {
        uint lid = localId ?? Router.AllocateLocalId();
        uint rid = remoteId ?? lid + 100;
        var channel = new SshChannel(
            ClientWriter,
            Router,
            lid,
            rid,
            outboundWindow: uint.MaxValue / 2,
            outboundMaxPacket: ChannelConstants.PacketDefault,
            inboundWindow: uint.MaxValue / 2,
            inboundMaxPacket: ChannelConstants.PacketDefault);
        Router.Register(channel);
        return channel;
    }

    public void Dispose()
    {
        try
        {
            _c2s.Writer.Complete();
        }
        catch (InvalidOperationException)
        {
        }

        try
        {
            _s2c.Writer.Complete();
        }
        catch (InvalidOperationException)
        {
        }

        Router.Dispose();
    }

    // ── Packet builders (mirror ChannelTestHarness) ────────────────────────

    /// <summary>
    /// Frames a cleartext SSH packet (length|padlen|payload|padding) carrying
    /// the given payload, whose first byte must equal <paramref name="type"/>.
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

    /// <summary>Builds a <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> payload: [93][u32 recip][u32 bytestoadd].</summary>
    public static byte[] BuildWindowAdjustPayload(uint recipientChannel, uint bytesToAdd)
    {
        byte[] payload = new byte[9];
        payload[0] = (byte)PacketType.ChannelWindowAdjust;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), bytesToAdd);
        return payload;
    }

    /// <summary>Builds a <c>SSH_MSG_CHANNEL_SUCCESS</c> payload: [99][u32 recip].</summary>
    public static byte[] BuildChannelSuccessPayload(uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelSuccess;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }
}
