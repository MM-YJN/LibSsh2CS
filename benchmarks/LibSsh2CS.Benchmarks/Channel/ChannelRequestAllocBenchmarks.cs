using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Isolates the outbound <c>SSH_MSG_CHANNEL_REQUEST</c> builder
/// (<c>SshChannel.SendChannelRequestAsync</c> + the per-request field writers).
/// Each request currently assembles a <c>List&lt;byte&gt;</c>, allocates a
/// temporary <c>byte[4]</c> per integer field, encodes the request-type/signal
/// strings per call, and copies the assembled list to the final payload array.
/// </summary>
/// <remarks>
/// <para>
/// Both variants are <c>want_reply=false</c> (fire-and-forget), so no reply-wait
/// machinery pollutes the measurement. <c>window-change</c> is the worst case
/// for temporary arrays (four integer fields); <c>signal</c> exercises the
/// per-call string encoding.
/// </para>
/// <para>
/// The client's outbound pipe is drained on the benchmark thread after each
/// request, so pipe back-pressure never enters the measured region and the run
/// stays deterministic (single-threaded).
/// </para>
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("channel-request")]
public class ChannelRequestAllocBenchmarks
{
    /// <summary>Which request variant to send.</summary>
    [Params("window-change", "signal")]
    public string RequestKind { get; set; } = "window-change";

    private ChannelBenchmarkHarness _h = null!;
    private SshChannel _channel = null!;

    [GlobalSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 1);
        _h.Queue.ReadTimeout = TimeSpan.Zero;
        _channel = _h.CreateChannel();
    }

    [GlobalCleanup]
    public void Cleanup() => _h.Dispose();

    [Benchmark]
    public async Task SendRequest()
    {
        Task send = RequestKind switch
        {
            "window-change" => _channel.RequestPtyWindowSizeAsync(80, 24, 0, 0, CancellationToken.None),
            "signal" => _channel.SignalAsync(SshSignal.Term, CancellationToken.None),
            _ => throw new InvalidOperationException($"Unknown request kind '{RequestKind}'."),
        };

        await send.ConfigureAwait(false);
        DrainOutbound();
    }

    /// <summary>Consumes every packet the client has written, without blocking.</summary>
    private void DrainOutbound()
    {
        PipeReader reader = _h.OutboundReader;
        while (reader.TryRead(out ReadResult result))
        {
            reader.AdvanceTo(result.Buffer.End);
        }
    }
}
