using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>Measures forwarded responses through a warmed, synchronously drained cleartext pipe.</summary>
[MemoryDiagnoser]
public class ForwardedResponseAllocBenchmarks
{
    [Params("confirmation", "failure", "failure-utf8")]
    public string Response { get; set; } = "confirmation";

    private Pipe _pipe = null!;
    private PacketWriter _writer = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pipe = new Pipe();
        _writer = new PacketWriter(_pipe.Writer);
    }

    [Benchmark]
    public async Task Send()
    {
        if (Response == "confirmation")
        {
            await _writer.WriteChannelOpenConfirmationAsync(42, 7, 2097152, 32768).ConfigureAwait(false);
        }
        else
        {
            await _writer.WriteChannelOpenFailureAsync(42, 1,
                Response == "failure" ? "Connection refused" : "接続拒否", "en").ConfigureAwait(false);
        }
        if (!_pipe.Reader.TryRead(out ReadResult result))
        {
            throw new InvalidOperationException("Expected a complete packet.");
        }
        _pipe.Reader.AdvanceTo(result.Buffer.End);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _writer.DisposeAsync().ConfigureAwait(false);
        await _pipe.Writer.CompleteAsync().ConfigureAwait(false);
        await _pipe.Reader.CompleteAsync().ConfigureAwait(false);
    }
}
