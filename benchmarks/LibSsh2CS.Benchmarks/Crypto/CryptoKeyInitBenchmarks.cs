using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Crypto;

/// <summary>
/// Isolates the per-key initialization allocations of the MAC and AEAD cipher
/// adapters (<c>HmacMac.Init</c> / <c>AesGcmCipher.Init</c>), which currently
/// copy the caller's key span into a retained array before handing the key to
/// the underlying BCL primitive. Runs once per NEWKEYS (per direction), so the
/// frequency is per-key-exchange rather than per-packet.
/// </summary>
/// <remarks>
/// Each iteration creates a fresh adapter because the real lifecycle installs a
/// new instance at every NEWKEYS; setup pre-generates the deterministic key
/// material so the measurement covers only initialization.
/// </remarks>
[MemoryDiagnoser]
[BenchmarkCategory("crypto-init")]
public class CryptoKeyInitBenchmarks
{
    private byte[] _macKey = null!;
    private byte[] _gcmKey = null!;
    private byte[] _gcmIv = null!;

    [GlobalSetup]
    public void Setup()
    {
        _macKey = new byte[32];
        _gcmKey = new byte[32];
        _gcmIv = new byte[12];
        for (int i = 0; i < 32; i++)
        {
            _macKey[i] = (byte)(i * 11 + 3);
            _gcmKey[i] = (byte)(i * 13 + 5);
        }

        for (int i = 0; i < _gcmIv.Length; i++)
        {
            _gcmIv[i] = (byte)(i * 17 + 7);
        }
    }

    [Benchmark]
    public void InitHmacSha256()
    {
        var mac = new HmacMac("hmac-sha2-256", System.Security.Cryptography.HashAlgorithmName.SHA256, 32, isEtm: false);
        mac.Init(_macKey);
        mac.Dispose();
    }

    [Benchmark]
    public void InitAes256Gcm()
    {
        var cipher = new AesGcmCipher(32);
        cipher.Init(_gcmKey, _gcmIv, encrypt: true);
        cipher.Dispose();
    }
}
