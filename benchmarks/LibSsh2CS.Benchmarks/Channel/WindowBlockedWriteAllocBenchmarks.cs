using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Measures writes that must pump a prebuffered window adjustment before sending.</summary>
[MemoryDiagnoser]
[BenchmarkCategory("window-write")]
public class WindowBlockedWriteAllocBenchmarks
{
    [Params(256, 4096, 32700)]
    public int DataSize { get; set; }

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;
    private byte[] _wire = null!;
    private byte[] _data = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(4);
        _channel = _h.CreateChannel(outboundWindow: 0);
        _data = new byte[DataSize];
        _wire = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelWindowAdjust,
            ChannelBenchmarkHarness.BuildWindowAdjustPayload(_channel.LocalId, (uint)DataSize));
        if (!WriteAfterWindowAdjust().IsCompletedSuccessfully)
        {
            throw new InvalidOperationException("Expected a synchronous write after window credit.");
        }
    }

    [Benchmark]
    public async Task WriteAfterWindowAdjust()
    {
        await _h.ServerWriter.WriteAsync(_wire).ConfigureAwait(false);
        await _channel.WriteAsync(_data).ConfigureAwait(false);
        while (_h.OutboundReader.TryRead(out ReadResult result))
        {
            _h.OutboundReader.AdvanceTo(result.Buffer.End);
        }
    }

    [GlobalCleanup]
    public void Cleanup() => _h.Dispose();
}
