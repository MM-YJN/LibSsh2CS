using BenchmarkDotNet.Attributes;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.Benchmarks.Crypto;

/// <summary>Measures public-key derivation, including the owned result array.</summary>
[MemoryDiagnoser]
[BenchmarkCategory("crypto")]
public class Ed25519PublicKeyAllocBenchmarks
{
    private readonly byte[] _seed = new byte[32];

    [Benchmark]
    public byte[] GetPublicKey() => Ed25519.GetPublicKey(_seed);
}
