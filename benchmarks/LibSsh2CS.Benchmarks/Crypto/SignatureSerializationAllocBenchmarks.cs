using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Crypto;

/// <summary>Measures owned signature serialization outputs with prepared inputs.</summary>
[MemoryDiagnoser]
public class SignatureSerializationAllocBenchmarks
{
    [Params(32, 48, 66)]
    public int CoordinateSize { get; set; }

    private byte[] _r = null!;
    private byte[] _s = null!;
    private byte[] _signature = null!;

    [GlobalSetup]
    public void Setup()
    {
        _r = new byte[CoordinateSize];
        _s = new byte[CoordinateSize];
        Array.Fill(_r, (byte)0x80);
        Array.Fill(_s, (byte)0x7f);
        _signature = new byte[CoordinateSize * 2];
    }

    [Benchmark]
    public byte[] SshBlob() => SshSign.BuildSshSigBlob("ecdsa-sha2-nistp256", _signature);

    [Benchmark]
    public byte[] EcdsaDer() => HostKeyVerifier.EncodeEcdsaDerSig(_r, _s);
}
