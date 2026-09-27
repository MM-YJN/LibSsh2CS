using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

public class ForwardingEncodingTests
{
    [Theory]
    [InlineData("empty")]
    [InlineData("ascii")]
    [InlineData("unicode")]
    [InlineData("fallback")]
    [InlineData("long")]
    public void Builders_PreserveAsciiEncodingAndIndependentResults(string kind)
    {
        string text = GetText(kind);
        byte[] extra = [1, 2, 3];
        Check(() => SshChannel.BuildChannelOpenPayload(text, 7, 1024, 2048, extra),
            Packet(90, Encoding.ASCII, text, 7u, 1024u, 2048u).Concat(extra).ToArray());
        foreach (bool wantReply in new[] { false, true })
        {
            Check(() => GlobalRequest.BuildPayload(text, extra, wantReply),
                Packet(80, Encoding.ASCII, text, wantReply ? (byte)1 : (byte)0).Concat(extra).ToArray());
        }
        Assert.Equal(new byte[] { 1, 2, 3 }, extra);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DirectOpen_PreservesUtf8EncodingAndByteLengths(bool streamLocal)
    {
        foreach (string kind in new[] { "empty", "ascii", "unicode", "fallback", "long" })
        {
            string text = GetText(kind);
            using var h = new ChannelTestHarness();
            CancellationToken ct = TestContext.Current.CancellationToken;
            Task<SshChannel> open = streamLocal
                ? SshChannel.OpenDirectStreamLocalAsync(h.ClientWriter, h.Router, text, text, 50000, ct)
                : SshChannel.OpenDirectTcpIpAsync(h.ClientWriter, h.Router, text, 443, text, 50000, ct);
            using RawPacket packet = await h.ServerReader.ReadPacketAsync(ct);
            byte[] expected = streamLocal
                ? Packet(90, Encoding.UTF8, "direct-streamlocal@openssh.com", 0u,
                    ChannelConstants.WindowDefault, ChannelConstants.PacketDefault, text, text, 50000u)
                : Packet(90, Encoding.UTF8, "direct-tcpip", 0u,
                    ChannelConstants.WindowDefault, ChannelConstants.PacketDefault, text, 443u, text, 50000u);
            Assert.Equal(expected, packet.Payload.ToArray());

            await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.ChannelOpenConfirmation,
                ChannelTestHarness.BuildOpenConfirmationPayload(0, 42,
                    ChannelConstants.WindowDefault, ChannelConstants.PacketDefault)));
            SshChannel channel = await open;
            Assert.Equal(42u, channel.RemoteId);
            await h.ClientWriter.DisposeAsync();
            await h.ServerReader.DisposeAsync();
        }
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("ascii")]
    [InlineData("unicode")]
    [InlineData("fallback")]
    [InlineData("long")]
    public async Task RemoteForward_EncodesHostDirectly_ForSetupAndCancellation(string kind)
    {
        string host = GetText(kind);
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var h = new ChannelTestHarness();
        await using var session = new SshSession();
        session.SetChannelRouterForTest(h.Router);
        Task<SshListener> listening = session.ListenForwardAsync(host, 443, cancellationToken: ct);
        using RawPacket request = await h.ServerReader.ReadPacketAsync(ct);
        Assert.Equal(Packet(80, Encoding.UTF8, "tcpip-forward", (byte)1, host, 443u), request.Payload.ToArray());
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(PacketType.RequestSuccess, [(byte)PacketType.RequestSuccess]));
        SshListener listener = await listening;
        await listener.DisposeAsync();
        using RawPacket cancel = await h.ServerReader.ReadPacketAsync(ct);
        Assert.Equal(Packet(80, Encoding.UTF8, "cancel-tcpip-forward", (byte)0, host, 443u), cancel.Payload.ToArray());
        await h.ClientWriter.DisposeAsync();
        await h.ServerReader.DisposeAsync();
    }

    // Construct invalid UTF-16 at runtime so test discovery cannot normalize it.
    private static string GetText(string kind) => kind switch
    {
        "empty" => string.Empty,
        "unicode" => "你好 🌍",
        "fallback" => "bad\ud800text\udc00",
        "long" => new string('x', 4096),
        _ => "example.com",
    };

    private static void Check(Func<byte[]> build, byte[] expected)
    {
        byte[] first = build();
        byte[] second = build();
        Assert.Equal(expected, first);
        Assert.NotSame(first, second);
        first[0] ^= 255;
        Assert.Equal(expected, second);
    }

    // Independent streaming encoder checks field order, byte lengths and fallback behavior.
    private static byte[] Packet(byte type, Encoding encoding, params object[] fields)
    {
        using var stream = new MemoryStream();
        stream.WriteByte(type);
        Span<byte> length = stackalloc byte[4];
        foreach (object field in fields)
        {
            if (field is byte flag)
            {
                stream.WriteByte(flag);
            }
            else if (field is uint value)
            {
                BinaryPrimitives.WriteUInt32BigEndian(length, value);
                stream.Write(length);
            }
            else
            {
                byte[] bytes = encoding.GetBytes((string)field);
                BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
                stream.Write(length);
                stream.Write(bytes);
            }
        }
        return stream.ToArray();
    }
}
