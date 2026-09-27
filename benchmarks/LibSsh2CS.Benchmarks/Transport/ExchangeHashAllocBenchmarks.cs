using System.Numerics;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.Benchmarks.Transport;

[MemoryDiagnoser]
public class ExchangeHashAllocBenchmarks
{
    [Params("curve25519-sha256", "diffie-hellman-group14-sha256")]
    public string Method { get; set; } = "curve25519-sha256";

    private KexAlgorithm _algorithm;
    private byte[] _public = null!;
    private BigInteger _secret;

    [GlobalSetup]
    public void Setup()
    {
        _algorithm = KexMethods.Lookup(Method);
        _public = Enumerable.Repeat((byte)0x80, Method.StartsWith("curve", StringComparison.Ordinal) ? 32 : 256).ToArray();
        _secret = Endian.BigIntegerFromBigEndian(_public);
    }

    [Benchmark]
    public byte[] ExchangeHash() => KeyExchange.ComputeExchangeHash(_algorithm,
        "SSH-2.0-client"u8, "SSH-2.0-server"u8, _public, _public, _public, _public, _public, _secret);
}

/// <summary>Isolates conversion from DH modular arithmetic and random-number generation.</summary>
[MemoryDiagnoser]
public class BigEndianConversionAllocBenchmarks
{
    private readonly byte[] _input = Enumerable.Repeat((byte)0x80, 256).ToArray();

    [Benchmark(Baseline = true)]
    public BigInteger ReversedArray()
    {
        byte[] littleEndian = new byte[_input.Length + 1];
        for (int i = 0; i < _input.Length; i++)
        {
            littleEndian[i] = _input[_input.Length - 1 - i];
        }
        return new BigInteger(littleEndian);
    }

    [Benchmark]
    public BigInteger DirectSpan() => Endian.BigIntegerFromBigEndian(_input);
}
