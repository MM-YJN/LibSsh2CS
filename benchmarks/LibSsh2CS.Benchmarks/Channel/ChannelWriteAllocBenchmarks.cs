using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Benchmarks.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Isolates the outbound channel-data path: <see cref="SshChannel.WriteAsync"/>
/// builds an intermediate payload array
/// (<c>SshChannel.BuildChannelDataPayload</c>) which <c>PacketWriter</c> then
/// copies into its frame scratch. The benchmark quantifies that removable
/// intermediate copy (the outbound double copy targeted by the Tier-2
/// allocation work).
/// </summary>
/// <remarks>
/// <para>
/// The client's outbound pipe is drained on the benchmark thread after each
/// write, so pipe back-pressure never enters the measured region and the run
/// stays deterministic (single-threaded). The channel's outbound window is
/// re-credited in full each invocation via
/// <see cref="SshChannel.DeliverWindowAdjust"/>, so the write loop never parks
/// on a depleted window regardless of how many invocations BenchmarkDotNet
/// runs. Feeding inbound WINDOW_ADJUST packets instead would drag packet
/// parsing and routing into every measurement.
/// </para>
/// <para>
/// The payload is incompressible so the measurement reflects bulk transfer
/// (the scenario the intermediate copy penalizes most).
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("channel-write")]
public class ChannelWriteAllocBenchmarks
{
    /// <summary>Bytes of channel data per write.</summary>
    [Params(256, 4096, 32700)]
    public int DataSize { get; set; }

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;
    private byte[] _data = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Large pause threshold so a full-size write never back-pressures
        // before the drain below runs.
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 4);
        _channel = _h.CreateChannel();
        _data = DataGenerator.Create(DataShape.Incompressible, DataSize);
    }

    [GlobalCleanup]
    public void Cleanup() => _h.Dispose();

    [Benchmark]
    public async Task<int> WriteChannelData()
    {
        await _channel.WriteAsync(_data.AsMemory(), CancellationToken.None).ConfigureAwait(false);

        int total = DrainOutbound();

        // Re-credit the window consumed above so the next invocation never
        // parks waiting for a WINDOW_ADJUST the mock server never sends.
        _channel.DeliverWindowAdjust((uint)DataSize);
        return total;
    }

    /// <summary>Consumes every packet the client has written, without blocking.</summary>
    private int DrainOutbound()
    {
        PipeReader reader = _h.OutboundReader;
        int read = 0;
        while (reader.TryRead(out ReadResult result))
        {
            foreach (ReadOnlyMemory<byte> segment in result.Buffer)
            {
                read += (int)segment.Length;
            }

            reader.AdvanceTo(result.Buffer.End);
        }

        return read;
    }
}
