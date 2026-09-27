using System.Buffers.Binary;
using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Exercises production request paths; identical source runs against the baseline library.</summary>
[MemoryDiagnoser]
public class OpenAndGlobalRequestAllocBenchmarks
{
    [Params("session", "tcp", "streamlocal", "global", "forward", "keepalive")]
    public string Kind { get; set; } = "session";

    private ChannelBenchmarkHarness _h = null!;
    private SshSession _session = null!;
    private readonly AdvancingTimeProvider _time = new();
    private byte[] _confirmation = null!;
    private byte[] _success = null!;
    private uint _nextId;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness();
        _session = new SshSession(_time);
        _session.SetWriterForTest(_h.ClientWriter);
        _session.SetChannelRouterForTest(_h.Router);
        _session.ConfigureKeepAlive(false, 2);
        _confirmation = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelOpenConfirmation,
            SshChannel.BuildChannelOpenConfirmationPayload(0, 42, 2097152, 32768));
        _success = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.RequestSuccess, [(byte)PacketType.RequestSuccess]);
        _nextId = 0;
    }

    [Benchmark]
    public async Task SendRequest()
    {
        if (Kind is "session" or "tcp" or "streamlocal")
        {
            // The cleartext frame header and type byte precede the recipient id.
            BinaryPrimitives.WriteUInt32BigEndian(_confirmation.AsSpan(6, 4), _nextId++);
            await _h.ServerWriter.WriteAsync(_confirmation).ConfigureAwait(false);
            SshChannel channel = await (Kind switch
            {
                "session" => SshChannel.OpenAsync(_h.ClientWriter, _h.Router, CancellationToken.None),
                "tcp" => SshChannel.OpenDirectTcpIpAsync(_h.ClientWriter, _h.Router,
                    "example.com", 443, "127.0.0.1", 50000, CancellationToken.None),
                _ => SshChannel.OpenDirectStreamLocalAsync(_h.ClientWriter, _h.Router,
                    "/tmp/socket", "127.0.0.1", 50000, CancellationToken.None),
            }).ConfigureAwait(false);
            channel.DeliverClose();
            await channel.DisposeAsync().ConfigureAwait(false);
        }
        else if (Kind == "forward")
        {
            await _h.ServerWriter.WriteAsync(_success).ConfigureAwait(false);
            SshListener listener = await _session.ListenForwardAsync("example.com", 443).ConfigureAwait(false);
            await listener.DisposeAsync().ConfigureAwait(false);
        }
        else if (Kind == "global")
        {
            await _h.Router.SendGlobalRequestAsync("tcpip-forward", ReadOnlyMemory<byte>.Empty,
                false, CancellationToken.None).ConfigureAwait(false);
        }
        else
        {
            _time.Advance();
            await _session.SendKeepAliveAsync().ConfigureAwait(false);
        }
        while (_h.OutboundReader.TryRead(out ReadResult result))
        {
            _h.OutboundReader.AdvanceTo(result.Buffer.End);
        }
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _session.DisposeAsync().ConfigureAwait(false);
        _h.Dispose();
        await _h.Queue.Reader.DisposeAsync().ConfigureAwait(false);
        await _h.ServerReader.DisposeAsync().ConfigureAwait(false);
    }

    private sealed class AdvancingTimeProvider : TimeProvider
    {
        private long _timestamp;
        public override long TimestampFrequency => 1;
        public override long GetTimestamp() => _timestamp;
        public void Advance() => _timestamp += 3;
    }
}
