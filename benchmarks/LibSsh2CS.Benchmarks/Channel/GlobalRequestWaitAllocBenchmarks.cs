using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Isolates the want-reply global-request round trip
/// (<see cref="ChannelRouter.SendGlobalRequestAsync"/>): payload build, the
/// per-request reply <see cref="TaskCompletionSource{TResult}"/>, and one
/// cooperative pump batch, whose typed wait constructs the deadline scope
/// (linked <see cref="CancellationTokenSource"/> + <see cref="ITimer"/>) under
/// test. Covers the router-side half of the Tier-2 wait machinery and the
/// global-request payload allocation.
/// </summary>
/// <remarks>
/// <para>
/// The <c>REQUEST_SUCCESS</c> reply is written into the client's inbound pipe
/// BEFORE the send begins, so the send's first pump cycle consumes it and the
/// whole send → route → reply hand-off completes synchronously on the benchmark
/// thread (the top-of-loop <c>tcs.Task.IsCompleted</c> check breaks out without
/// ever awaiting). No thread-pool migration can skew the per-thread allocation
/// figure, and no blocker task is needed.
/// </para>
/// <para>
/// <see cref="UseTimeout"/> is the control: <see langword="false"/> disables the
/// queue deadline so no scope is constructed. The client's outbound pipe is
/// drained on the benchmark thread after each send so back-pressure never
/// enters the measured region.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("global-request")]
public class GlobalRequestWaitAllocBenchmarks
{
    /// <summary>Whether the queue's read deadline (and thus the scope) is active.</summary>
    [Params(true, false)]
    public bool UseTimeout { get; set; }

    private ChannelBenchmarkHarness _h = null!;
    private byte[] _reply = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(
            pipeMegabytes: 4,
            readTimeout: UseTimeout ? TimeSpan.FromMinutes(10) : null);
        _reply = ChannelBenchmarkHarness.BuildCleartextPacket(
            PacketType.RequestSuccess,
            ChannelBenchmarkHarness.BuildRequestSuccessPayload());
    }

    [GlobalCleanup]
    public void Cleanup() => _h.Dispose();

    [Benchmark]
    public async Task<int> RequestReplyRoundTrip()
    {
        // Pre-feed the reply: the send's first pump cycle consumes it.
        await _h.ServerWriter.WriteAsync(_reply, CancellationToken.None).ConfigureAwait(false);
        await _h.ServerWriter.FlushAsync(CancellationToken.None).ConfigureAwait(false);

        RawPacket reply = await _h.Router.SendGlobalRequestAsync(
            "keepalive@libssh2.org", ReadOnlyMemory<byte>.Empty, wantReply: true, CancellationToken.None)
            .ConfigureAwait(false);

        int total = DrainOutbound();
        return total + reply.Payload.Length;
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
