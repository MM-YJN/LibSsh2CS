using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Asynchronous controls: deadline setup on empty or partially buffered input.</summary>
/// <remarks>Includes scheduling and pipe feeding. Use buffered cases for isolated allocation comparisons.</remarks>
[MemoryDiagnoser]
public class SuspendedTypedWaitAllocBenchmarks
{
    [Params(false, true)]
    public bool Fragmented { get; set; }

    [Params(false, true)]
    public bool SingleType { get; set; }

    [Params(false, true)]
    public bool UseTimeout { get; set; }

    [Params("none", "cancellable")]
    public string TokenMode { get; set; } = "none";

    private static readonly int[] s_types = [PacketType.ChannelSuccess];
    private static readonly byte[] s_wire = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelSuccess, [(byte)PacketType.ChannelSuccess]);
    private ChannelBenchmarkHarness _h = null!;
    private CancellationTokenSource _cts = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new(readTimeout: UseTimeout ? TimeSpan.FromSeconds(60) : null);
        _cts = new CancellationTokenSource();
    }

    [Benchmark]
    public async Task<int> WaitForPacket()
    {
        int split = Fragmented ? 5 : 0;
        if (split != 0)
        {
            await _h.ServerWriter.WriteAsync(s_wire.AsMemory(0, split)).ConfigureAwait(false);
        }
        CancellationToken token = TokenMode == "cancellable" ? _cts.Token : CancellationToken.None;
        ValueTask<RawPacket> wait = SingleType
            ? _h.Queue.WaitForTypeAsync(PacketType.ChannelSuccess, token)
            : _h.Queue.WaitForTypesAsync(s_types, token);
        if (wait.IsCompleted)
        {
            throw new InvalidOperationException("Expected a suspended read.");
        }
        await Task.Yield();
        await _h.ServerWriter.WriteAsync(s_wire.AsMemory(split)).ConfigureAwait(false);
        using RawPacket packet = await wait.ConfigureAwait(false);
        return packet.Payload.Length;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cts.Dispose();
        _h.Dispose();
        _h.Queue.Reader.DisposeAsync().GetAwaiter().GetResult();
        _h.ClientWriter.DisposeAsync().GetAwaiter().GetResult();
        _h.ServerReader.DisposeAsync().GetAwaiter().GetResult();
    }
}
