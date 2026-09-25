using System.IO.Pipelines;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Channel;

/// <summary>
/// Measures complete channel requests, including encoding, framing, and reply
/// handling. Inputs, fresh channels, and inbound replies are prepared outside
/// measurement. Correctness is covered by the unit and integration suites.
/// </summary>
[MemoryDiagnoser]
[BenchmarkCategory("channel-request")]
[InvocationCount(1)]
public class ChannelRequestAllocBenchmarks
{
    private const int BatchSize = 64;

    [Params("exec-empty", "exec-ascii", "exec-utf8", "exec-long", "shell",
        "subsystem", "env-empty", "env-ascii", "env-utf8", "pty", "signal", "window-change")]
    public string RequestKind { get; set; } = "exec-ascii";

    private ChannelBenchmarkHarness _h = null!;
    private readonly SshChannel[] _channels = new SshChannel[BatchSize];
    private string _text = null!;

    [IterationSetup]
    public void Setup()
    {
        _h = new ChannelBenchmarkHarness(pipeMegabytes: 1);
        _text = RequestKind switch
        {
            "exec-empty" or "env-empty" => string.Empty,
            "exec-utf8" or "env-utf8" => "echo 你好 🌍",
            "exec-long" => new string('x', 4096),
            _ => "echo hello",
        };
        for (int i = 0; i < BatchSize; i++)
        {
            _channels[i] = _h.CreateChannel();
            if (RequestKind is not ("signal" or "window-change"))
            {
                byte[] reply = ChannelBenchmarkHarness.BuildCleartextPacket(
                    PacketType.ChannelSuccess,
                    ChannelBenchmarkHarness.BuildChannelSuccessPayload(_channels[i].LocalId));
                _h.ServerWriter.WriteAsync(reply).GetAwaiter().GetResult();
            }
        }
    }

    [IterationCleanup]
    public void Cleanup() => _h.Dispose();

    [Benchmark(OperationsPerInvoke = BatchSize)]
    public async Task SendRequests()
    {
        foreach (SshChannel channel in _channels)
        {
            Task send = RequestKind switch
            {
                "exec-empty" or "exec-ascii" or "exec-utf8" or "exec-long" => channel.ExecAsync(_text),
                "shell" => channel.ShellAsync(),
                "subsystem" => channel.SubsystemAsync("sftp"),
                "env-empty" or "env-ascii" or "env-utf8" => channel.SetEnvAsync("LANG", _text),
                "pty" => channel.RequestPtyAsync("xterm-256color", 80, 24),
                "signal" => channel.SignalAsync(SshSignal.Term),
                "window-change" => channel.RequestPtyWindowSizeAsync(80, 24),
                _ => throw new InvalidOperationException($"Unknown request kind '{RequestKind}'."),
            };
            await send.ConfigureAwait(false);
            DrainOutbound();
        }
    }

    private void DrainOutbound()
    {
        PipeReader reader = _h.OutboundReader;
        while (reader.TryRead(out ReadResult result))
        {
            reader.AdvanceTo(result.Buffer.End);
        }
    }
}
