using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Measures channel-open and global-request encoding without transport costs.</summary>
[MemoryDiagnoser]
public class ForwardingEncodingAllocBenchmarks
{
    private readonly byte[] _extra = new byte[32];

    [Benchmark]
    public byte[] ChannelOpen() => SshChannel.BuildChannelOpenPayload(
        "direct-tcpip", 1, ChannelConstants.WindowDefault, ChannelConstants.PacketDefault, _extra);

    [Benchmark]
    public byte[] GlobalRequestPayload() => GlobalRequest.BuildPayload("tcpip-forward", _extra, true);
}
