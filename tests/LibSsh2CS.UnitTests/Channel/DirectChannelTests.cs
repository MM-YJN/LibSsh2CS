using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

/// <summary>
/// Phase 5.4 <c>direct-tcpip</c> and <c>direct-streamlocal@openssh.com</c>
/// channel-open tests. Verifies the factories:
/// <list type="bullet">
/// <item>Build correct wire payloads (parity with channel.c:399-419 and
/// channel.c:491-497).</item>
/// <item>Propagate CHANNEL_OPEN_CONFIRMATION to a usable SshChannel.</item>
/// <item>Propagate CHANNEL_OPEN_FAILURE as a thrown LibSsh2Exception.</item>
/// <item>Reuse the standard channel lifecycle — no divergence from the
/// session-channel open path.</item>
/// </list>
/// </summary>
public class DirectChannelTests
{
    // ── Payload byte-exactness ────────────────────────────────────────────

    /// <summary>
    /// Parses a CHANNEL_OPEN payload's typed-extra block (after the standard
    /// 1+4+type+4+4+4 header). Returns the extra as a separate byte array.
    /// </summary>
    private static byte[] ExtractExtra(byte[] payload, string channelType)
    {
        int headerLen = 1 + 4 + channelType.Length + 4 + 4 + 4;
        Assert.True(payload.Length >= headerLen);
        return payload.AsSpan(headerLen).ToArray();
    }

    /// <summary>Reads an SSH string (BE32 length + bytes) and advances past it.</summary>
    private static (string value, int newOffset) ReadString(byte[] buf, int offset)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
        string s = Encoding.ASCII.GetString(buf, offset + 4, (int)len);
        return (s, offset + 4 + (int)len);
    }

    /// <summary>Reads a BE32 and advances past it.</summary>
    private static (uint value, int newOffset) ReadU32(byte[] buf, int offset)
    {
        return (BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4)), offset + 4);
    }

    [Fact]
    public async Task OpenDirectTcpIp_SendsDirectTcpipPayload_WithHostAndPortAndOriginator()
    {
        // channel.c:399-419 + 407-410 — wire payload:
        //   [90][string "direct-tcpip"][u32 localId][u32 window][u32 packet]
        //   [string host][u32 port][string shost][u32 sport]
        using var h = new ChannelTestHarness();

        Task<SshChannel> openTask = SshChannel.OpenDirectTcpIpAsync(
            h.ClientWriter, h.Router,
            host: "github.com", port: 443,
            originatorAddress: "10.0.0.1", originatorPort: 50000,
            cancellationToken: TestContext.Current.CancellationToken);

        RawPacket open = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelOpen, open.Type);
        Assert.Equal("direct-tcpip", ReadString(open.Payload, 1).value);

        byte[] extra = ExtractExtra(open.Payload, "direct-tcpip");
        int o = 0;
        (string? host, int o2) = ReadString(extra, o);
        o = o2;
        (uint port, int o3) = ReadU32(extra, o);
        o = o3;
        (string? shost, int o4) = ReadString(extra, o);
        o = o4;
        (uint sport, int o5) = ReadU32(extra, o);
        o = o5;

        Assert.Equal("github.com", host);
        Assert.Equal(443u, port);
        Assert.Equal("10.0.0.1", shost);
        Assert.Equal(50000u, sport);
        Assert.Equal(extra.Length, o);   // no trailing bytes

        // Reply + complete.
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelOpenConfirmation,
            ChannelTestHarness.BuildOpenConfirmationPayload(
                recipientChannel: 0, senderChannel: 42,
                window: ChannelConstants.WindowDefault, maxPacket: ChannelConstants.PacketDefault)));
        h.CompleteInbound();

        SshChannel ch = await openTask;
        Assert.Equal(0u, ch.LocalId);
        Assert.Equal(42u, ch.RemoteId);
    }

    [Fact]
    public async Task OpenDirectTcpIp_DefaultOriginator_IsLoopbackZeroPort()
    {
        using var h = new ChannelTestHarness();

        Task<SshChannel> openTask = SshChannel.OpenDirectTcpIpAsync(
            h.ClientWriter, h.Router,
            host: "internal.svc", port: 80,
            originatorAddress: "127.0.0.1", originatorPort: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        RawPacket open = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        byte[] extra = ExtractExtra(open.Payload, "direct-tcpip");
        int o = 0;
        (string _, int o1) = ReadString(extra, o);
        o = o1;
        (uint _, int o2) = ReadU32(extra, o);
        o = o2;
        (string? shost, int o3) = ReadString(extra, o);
        o = o3;
        (uint sport, int _) = ReadU32(extra, o);

        Assert.Equal("127.0.0.1", shost);
        Assert.Equal(0u, sport);

        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelOpenConfirmation,
            ChannelTestHarness.BuildOpenConfirmationPayload(0, 9,
                ChannelConstants.WindowDefault, ChannelConstants.PacketDefault)));
        h.CompleteInbound();
        SshChannel ch = await openTask;
        Assert.Equal(9u, ch.RemoteId);
    }

    [Fact]
    public async Task OpenDirectStreamLocal_SendsStreamLocalPayload_NoPortAfterPath()
    {
        // channel.c:486-488 — wire payload:
        //   [90][string "direct-streamlocal@openssh.com"][u32 localId][u32 window][u32 packet]
        //   [string socket_path][string shost][u32 sport]
        // NOTE: no port field after socket_path (diverges from direct-tcpip).
        using var h = new ChannelTestHarness();

        _ = SshChannel.OpenDirectStreamLocalAsync(
            h.ClientWriter, h.Router,
            socketPath: "/var/run/docker.sock",
            originatorAddress: "127.0.0.1", originatorPort: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        RawPacket open = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelOpen, open.Type);
        Assert.Equal("direct-streamlocal@openssh.com", ReadString(open.Payload, 1).value);

        byte[] extra = ExtractExtra(open.Payload, "direct-streamlocal@openssh.com");
        int o = 0;
        (string? path, int o1) = ReadString(extra, o);
        o = o1;
        (string? shost, int o2) = ReadString(extra, o);
        o = o2;
        (uint sport, int o3) = ReadU32(extra, o);
        o = o3;

        Assert.Equal("/var/run/docker.sock", path);
        Assert.Equal("127.0.0.1", shost);
        Assert.Equal(0u, sport);
        Assert.Equal(extra.Length, o);   // exactly three fields, no port-after-path
    }

    [Fact]
    public async Task OpenDirectTcpIp_Failure_PropagatesAsLibSsh2Exception()
    {
        using var h = new ChannelTestHarness();

        Task<SshChannel> openTask = SshChannel.OpenDirectTcpIpAsync(
            h.ClientWriter, h.Router,
            host: "denied.example", port: 22,
            originatorAddress: "127.0.0.1", originatorPort: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        // Consume the CHANNEL_OPEN.
        _ = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);

        // Server refuses — connect-failed is the typical reason for direct-tcpip.
        byte[] failPayload = BuildOpenFailurePayload(
            0, ChannelConstants.OpenConnectFailed, "connection refused");
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelOpenFailure, failPayload));
        h.CompleteInbound();

        SshException ex = await Assert.ThrowsAsync<SshException>(() => openTask);
        Assert.Equal(SshErrorCode.ChannelFailure, ex.ErrorCode);
        Assert.Contains("connect failed", ex.Message);
        Assert.Contains("connection refused", ex.Message);

        // Half-open channel must have been unregistered on failure.
        Assert.False(h.Router.TryGet(0, out _));
    }

    [Fact]
    public async Task OpenDirectTcpIp_AllocatesSequentialLocalIdLikeSessionOpen()
    {
        // The direct-tcpip factory must share the same AllocateLocalId() counter
        // as OpenAsync — they're indistinguishable at the router level.
        using var h = new ChannelTestHarness();

        _ = SshChannel.OpenDirectTcpIpAsync(
            h.ClientWriter, h.Router,
            host: "a", port: 1, originatorAddress: "127.0.0.1", originatorPort: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        RawPacket first = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        // "direct-tcpip" (12 chars) → localId offset = 1 + 4 + 12 = 17.
        const int DirectTcpipLocalIdOffset = 17;
        uint firstId = BinaryPrimitives.ReadUInt32BigEndian(first.Payload.AsSpan(DirectTcpipLocalIdOffset, 4));

        _ = SshChannel.OpenDirectTcpIpAsync(
            h.ClientWriter, h.Router,
            host: "b", port: 2, originatorAddress: "127.0.0.1", originatorPort: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        RawPacket second = await h.ServerReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        uint secondId = BinaryPrimitives.ReadUInt32BigEndian(second.Payload.AsSpan(DirectTcpipLocalIdOffset, 4));

        Assert.Equal(0u, firstId);
        Assert.Equal(1u, secondId);
    }

    [Fact]
    public async Task OpenDirectTcpIp_NullHost_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            SshChannel.OpenDirectTcpIpAsync(
                h.ClientWriter, h.Router,
                host: null!, port: 22, originatorAddress: "x", originatorPort: 0,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OpenDirectStreamLocal_NullPath_ThrowsArgumentNull()
    {
        using var h = new ChannelTestHarness();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            SshChannel.OpenDirectStreamLocalAsync(
                h.ClientWriter, h.Router,
                socketPath: null!, originatorAddress: "x", originatorPort: 0,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// <summary>Builds a CHANNEL_OPEN_FAILURE payload (parity with the
    /// SshChannel.BuildChannelOpenFailurePayload internal helper).</summary>
    private static byte[] BuildOpenFailurePayload(uint recipient, int reason, string description)
    {
        byte[] descBytes = Encoding.UTF8.GetBytes(description);
        byte[] langBytes = Encoding.ASCII.GetBytes(string.Empty);
        byte[] payload = new byte[1 + 4 + 4 + 4 + descBytes.Length + 4 + langBytes.Length];
        int o = 0;
        payload[o++] = (byte)PacketType.ChannelOpenFailure;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), recipient);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)reason);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)descBytes.Length);
        o += 4;
        Buffer.BlockCopy(descBytes, 0, payload, o, descBytes.Length);
        o += descBytes.Length;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), (uint)langBytes.Length);
        return payload;
    }
}
