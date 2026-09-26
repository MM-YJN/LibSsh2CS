using BenchmarkDotNet.Attributes;

namespace LibSsh2CS.Benchmarks.Crypto;

/// <summary>Measures per-derivation allocation as rounds and output blocks increase.</summary>
[MemoryDiagnoser]
public class BcryptAllocBenchmarks
{
    [Params(1, 4, 16)]
    public int Rounds { get; set; }

    [Params(32, 48, 64)]
    public int KeyLength { get; set; }

    private readonly byte[] _password = "allocation benchmark password"u8.ToArray();
    private readonly byte[] _salt = "0123456789abcdef"u8.ToArray();

    [Benchmark]
    public byte[] Derive() => BcryptPbkdf.Derive(_password, _salt, (uint)Rounds, KeyLength);
}
