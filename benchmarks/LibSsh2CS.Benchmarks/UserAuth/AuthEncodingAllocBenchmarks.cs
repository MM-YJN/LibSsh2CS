using BenchmarkDotNet.Attributes;

namespace LibSsh2CS.Benchmarks.UserAuth;

/// <summary>Measures authentication payload construction without transport or signing costs.</summary>
[MemoryDiagnoser]
[BenchmarkCategory("auth-encoding")]
public class AuthEncodingAllocBenchmarks
{
    [Params("empty", "ascii", "unicode", "long")]
    public string TextKind { get; set; } = "ascii";

    private string _text = null!;
    private readonly byte[] _key = new byte[51];
    private readonly string[] _zero = [];
    private string[] _one = null!;
    private string[] _eight = null!;

    [GlobalSetup]
    public void Setup()
    {
        _text = TextKind switch
        {
            "empty" => string.Empty,
            "unicode" => "用户 🌍 密码",
            "long" => new string('x', 4096),
            _ => "alice-password",
        };
        _one = [_text];
        _eight = Enumerable.Repeat(_text, 8).ToArray();
    }

    [Benchmark] public byte[] Generic() => SshUserAuth.BuildUserauthRequest(_text, "none", null);
    [Benchmark] public byte[] Password() => SshUserAuth.BuildPasswordRequest(_text, _text, false, null);
    [Benchmark] public byte[] PasswordChange() => SshUserAuth.BuildPasswordRequest(_text, _text, true, _text);
    [Benchmark] public byte[] PublicKeyProbe() => SshUserAuth.BuildPublickeyProbe(_text, "ssh-ed25519", _key);
    [Benchmark] public byte[] KeyboardRequest() => SshUserAuth.BuildKbdIntRequest(_text);
    [Benchmark] public byte[] KeyboardZeroAnswers() => SshUserAuth.BuildKbdIntResponse(_zero);
    [Benchmark] public byte[] KeyboardOneAnswer() => SshUserAuth.BuildKbdIntResponse(_one);
    [Benchmark] public byte[] KeyboardEightAnswers() => SshUserAuth.BuildKbdIntResponse(_eight);
    [Benchmark] public byte[] HostBased() => SshUserAuth.BuildHostbasedRequest(_text, "ssh-ed25519", _key, _text, _text);
}
