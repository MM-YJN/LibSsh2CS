using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Channel;

public class ChannelRequestEncodingTests
{
    [Theory]
    [InlineData("exec", false)]
    [InlineData("exec", true)]
    [InlineData("subsystem", false)]
    [InlineData("subsystem", true)]
    [InlineData("env", false)]
    [InlineData("env", true)]
    [InlineData("pty-req", false)]
    [InlineData("pty-req", true)]
    [InlineData("signal", false)]
    [InlineData("signal", true)]
    public async Task Strings_PreserveEncodingAndByteLengths(string kind, bool compressed)
    {
        // Construct malformed UTF-16 at runtime: test discovery serialization
        // must not normalize the unpaired surrogate before it reaches the API.
        foreach (string value in new[] { string.Empty, "ascii", "你好 🌍", new string('\ud800', 1), new string('x', kind == "pty-req" ? 128 : 4096) })
        {
            using var h = new ChannelTestHarness();
            SshChannel channel = h.CreateChannel(localId: 0, remoteId: 42);
            CancellationToken ct = TestContext.Current.CancellationToken;
            if (compressed)
            {
                var encrypt = new AesGcmCipher(16);
                var decrypt = new AesGcmCipher(16);
                encrypt.Init(new byte[16], new byte[12], encrypt: true);
                decrypt.Init(new byte[16], new byte[12], encrypt: false);
                var compressor = new ZlibCompression("zlib", useInAuth: true);
                var decompressor = new ZlibCompression("zlib", useInAuth: true);
                compressor.Init(compress: true);
                decompressor.Init(compress: false);
                await h.ClientWriter.SetOutboundKeysAsync(encrypt, MacMethods.Noop, compressor,
                    strictKex: false, compressionActive: true, ct);
                h.ServerReader.SetInboundKeys(decrypt, MacMethods.Noop, decompressor,
                    strictKex: false, compressionActive: true);
            }
            Task send = kind switch
            {
                "exec" => channel.ExecAsync(value, ct),
                "subsystem" => channel.SubsystemAsync(value, ct),
                "env" => channel.SetEnvAsync(value, value, ct),
                "pty-req" => channel.RequestPtyAsync(value, 80, 24, cancellationToken: ct),
                "signal" => channel.SignalAsync(value, ct),
                _ => throw new InvalidOperationException(),
            };
            using RawPacket packet = await h.ServerReader.ReadPacketAsync(ct);
            byte[] payload = packet.Payload.ToArray();
            Assert.Equal(PacketType.ChannelRequest, packet.Type);
            Assert.Equal(42u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1)));
            int offset = 5;
            AssertString(payload, ref offset, Encoding.ASCII.GetBytes(kind));
            Assert.Equal(kind == "signal" ? (byte)0 : (byte)1, payload[offset++]);
            byte[] expected = (kind is "signal" or "pty-req" ? Encoding.ASCII : Encoding.UTF8).GetBytes(value);
            AssertString(payload, ref offset, expected);
            if (kind == "env")
            {
                AssertString(payload, ref offset, expected);
            }
            else if (kind == "pty-req")
            {
                Assert.Equal(80u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset)));
                Assert.Equal(24u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 4)));
                Assert.Equal(new byte[8], payload.AsSpan(offset + 8, 8).ToArray());
                offset += 16;
                AssertString(payload, ref offset, []);
            }

            Assert.Equal(payload.Length, offset);
            if (kind != "signal")
            {
                await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
                    PacketType.ChannelSuccess, [(byte)PacketType.ChannelSuccess, 0, 0, 0, 0]));
            }

            await send;
            await h.ClientWriter.DisposeAsync();
            await h.ServerReader.DisposeAsync();
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StartupDenial_PreservesFallbackNormalizedMessage(bool subsystem)
    {
        using var h = new ChannelTestHarness();
        SshChannel channel = h.CreateChannel(localId: 0);
        string value = "bad" + new string('\ud800', 1);
        CancellationToken ct = TestContext.Current.CancellationToken;
        Task send = subsystem ? channel.SubsystemAsync(value, ct) : channel.ExecAsync(value, ct);
        (await h.ServerReader.ReadPacketAsync(ct)).Dispose();
        await h.FeedInboundAsync(ChannelTestHarness.BuildCleartextPacket(
            PacketType.ChannelFailure, [(byte)PacketType.ChannelFailure, 0, 0, 0, 0]));
        SshException error = await Assert.ThrowsAsync<SshException>(() => send);
        string kind = subsystem ? "subsystem" : "exec";
        Assert.Equal($"Channel {kind} request denied by server for: {kind}: bad\ufffd", error.Message);
    }

    private static void AssertString(byte[] payload, ref int offset, byte[] expected)
    {
        Assert.Equal((uint)expected.Length, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset)));
        offset += 4;
        Assert.Equal(expected, payload.AsSpan(offset, expected.Length).ToArray());
        offset += expected.Length;
    }
}
