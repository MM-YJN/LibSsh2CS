using BenchmarkDotNet.Attributes;

using LibSsh2CS.Crypto;

namespace LibSsh2CS.Benchmarks.Crypto;

/// <summary>
/// Isolates the Ed25519 sign/verify key operation. Signing is the publickey
/// userauth path; verification is the host-key trust path. Both use the
/// constant-time fixed-base table lookup and scalar arithmetic, whose
/// per-operation temporary arrays dominate the allocation figure.
/// </summary>
/// <remarks>
/// Deterministic seed/message; the signature verified by
/// <see cref="Ed25519Verify"/> is produced once in setup (unmeasured) by
/// <see cref="Ed25519.Sign(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("crypto")]
public class Ed25519AllocBenchmarks
{
    private byte[] _seed = null!;
    private byte[] _publicKey = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;

    [GlobalSetup]
    public void Setup()
    {
        _seed = new byte[32];
        for (int i = 0; i < _seed.Length; i++)
        {
            _seed[i] = (byte)(i * 7 + 1);
        }

        _publicKey = Ed25519.GetPublicKey(_seed);
        _message = "SSH publickey auth challenge (benchmark payload)"u8.ToArray();
        _signature = Ed25519.Sign(_seed, _message);
    }

    [Benchmark]
    public byte[] Ed25519Sign() => Ed25519.Sign(_seed, _message);

    [Benchmark]
    public bool Ed25519Verify() => Ed25519.Verify(_publicKey, _message, _signature);
}
