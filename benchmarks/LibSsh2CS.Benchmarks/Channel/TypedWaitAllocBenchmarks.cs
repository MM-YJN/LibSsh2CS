using System.Buffers.Binary;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Isolates the per-typed-wait deadline machinery in
/// <see cref="PacketQueue.WaitForTypesAsync"/>: every call constructs a
/// <c>ReadTimeoutScope</c>, whose constructor creates a linked
/// <see cref="CancellationTokenSource"/> plus an <see cref="ITimer"/>. This is
/// the per-wait cost that the Tier-2 work targets (skip the linked source when
/// the caller's token cannot cancel; reuse one scope per queue).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="UseTimeout"/> is the control: <see langword="false"/> disables the
/// deadline, so the typed wait runs with no scope at all. The difference
/// between the two columns is the per-wait linked CTS + timer allocation.
/// <see cref="TokenMode"/> separates the caller-token path: <c>none</c> passes
/// <see cref="CancellationToken.None"/> (the linked source wraps only the
/// deadline timer today), <c>cancellable</c> passes a live token (adds a linked
/// registration).
/// </para>
/// <para>
/// The packet is written into the pipe before the wait begins, so the read
/// finds it buffered and the whole call completes synchronously on the
/// benchmark thread — no thread-pool migration, and
/// <c>TaskCreationOptions</c>-driven continuations cannot skew the per-thread
/// allocation figure. The timeout is ten minutes so it never fires. The wait
/// operates directly on the <see cref="PacketQueue"/> (not the router), because
/// the deadline scope is created by the queue and no routing is needed.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("typed-wait")]
public class TypedWaitAllocBenchmarks
{
    /// <summary><c>none</c> = CancellationToken.None; <c>cancellable</c> = live token.</summary>
    [Params("none", "cancellable")]
    public string TokenMode { get; set; } = "none";

    /// <summary>Whether the queue's read deadline (and thus the scope) is active.</summary>
    [Params(true, false)]
    public bool UseTimeout { get; set; }

    private static readonly int[] s_channelDataTypes = { PacketType.ChannelData };

    private ChannelBenchmarkHarness _h = null!;
    private byte[] _wire = null!;
    private CancellationTokenSource _liveCts = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(
            pipeMegabytes: 4,
            readTimeout: UseTimeout ? TimeSpan.FromMinutes(10) : null);

        byte[] body = new byte[1 + 4 + 4 + 32];
        body[0] = (byte)PacketType.ChannelData;
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(1, 4), 0u);
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(5, 4), 32u);
        _wire = ChannelBenchmarkHarness.BuildCleartextPacket(PacketType.ChannelData, body);

        _liveCts = new CancellationTokenSource();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _liveCts.Dispose();
        _h.Dispose();
    }

    [Benchmark]
    public async Task<int> WaitForOnePacket()
    {
        await _h.ServerWriter.WriteAsync(_wire, CancellationToken.None).ConfigureAwait(false);
        await _h.ServerWriter.FlushAsync(CancellationToken.None).ConfigureAwait(false);

        CancellationToken token = TokenMode == "cancellable" ? _liveCts.Token : CancellationToken.None;
        RawPacket pkt = await _h.Queue.WaitForTypesAsync(s_channelDataTypes, token).ConfigureAwait(false);
        return pkt.Payload.Length;
    }
}
