using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>Measures KEXINIT construction and PEM conversion, including owned output arrays.</summary>
[MemoryDiagnoser]
public class SerializationAllocBenchmarks
{
    private readonly MethodPreferences _preferences = new();
    private byte[] _rsa = null!;
    private byte[] _ecdsa = null!;
    private byte[] _ed25519 = null!;

    [GlobalSetup]
    public void Setup()
    {
        string? root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, "LibSsh2CS.slnx")))
        {
            root = Path.GetDirectoryName(root);
        }
        string fixtures = Path.Combine(root ?? throw new InvalidOperationException("Repository root not found."),
            "tests", "LibSsh2CS.UnitTests", "Fixtures", "legacy_pem");
        _rsa = File.ReadAllBytes(Path.Combine(fixtures, "pkcs8.pem"));
        _ecdsa = File.ReadAllBytes(Path.Combine(fixtures, "ec_pkcs8.pem"));
        _ed25519 = File.ReadAllBytes(Path.Combine(fixtures, "ed25519_pkcs8.pem"));
    }

    [Benchmark]
    public byte[] KexInit() => KeyExchange.BuildKexInit(_preferences);

    [Benchmark]
    public OpenSshKey RsaPem() => SshPemParser.ParseOpenSshPrivateKey(_rsa);

    [Benchmark]
    public OpenSshKey EcdsaPem() => SshPemParser.ParseOpenSshPrivateKey(_ecdsa);

    [Benchmark]
    public OpenSshKey Ed25519Pem() => SshPemParser.ParseOpenSshPrivateKey(_ed25519);
}
