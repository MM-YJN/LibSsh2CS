using System.Security.Cryptography;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for <see cref="EcdhNistP"/>: ephemeral keypair generation, SEC1
/// uncompressed point format, two-party shared-secret symmetry, and rejection
/// of malformed peer points.
/// </summary>
public class EcdhNistPTests
{
    // algorithm passed as int to keep the public test signature free of the
    // internal KexAlgorithm type (xUnit1000 requires public test classes).
    // (algorithm-int, expected uncompressed-point length = 1 + 2*coordSize)
    public static TheoryData<int, int> CurveSizes => new()
    {
        { (int)KexAlgorithm.EcdhSha2Nistp256, 65 },
        { (int)KexAlgorithm.EcdhSha2Nistp384, 97 },
        { (int)KexAlgorithm.EcdhSha2Nistp521, 133 },
    };

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void PublicKeyPoint_IsSec1Uncompressed(int alg, int expectedLen)
    {
        using var k = new EcdhNistP((KexAlgorithm)alg);
        byte[] q = k.PublicKeyPoint;

        Assert.Equal(expectedLen, q.Length);
        Assert.Equal(0x04, q[0]);   // SEC1 uncompressed marker
    }

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void TwoParty_SharedSecretIsSymmetric(int alg, int _)
    {
        using var alice = new EcdhNistP((KexAlgorithm)alg);
        using var bob = new EcdhNistP((KexAlgorithm)alg);

        byte[] kAlice = alice.ComputeSharedSecret(bob.PublicKeyPoint);
        byte[] kBob = bob.ComputeSharedSecret(alice.PublicKeyPoint);

        Assert.Equal(kAlice, kBob);
        Assert.True(kAlice.Length > 0);
    }

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void ComputeSharedSecret_RejectsWrongLength(int alg, int _)
    {
        using var k = new EcdhNistP((KexAlgorithm)alg);
        byte[] bad = new byte[k.PublicKeyPoint.Length - 1];
        bad[0] = 0x04;

        // Parity: the C maps peer-point failures to KEX_FAILURE ("Unable to
        // create ECDH shared secret", openssl.c:4321-4326 / kex.c:2049-2053).
        SshException ex = Assert.Throws<SshException>(
            () => k.ComputeSharedSecret(bad));
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void ComputeSharedSecret_RejectsCompressedMarker(int alg, int _)
    {
        using var k = new EcdhNistP((KexAlgorithm)alg);
        byte[] bad = new byte[k.PublicKeyPoint.Length];
        bad[0] = 0x02;   // compressed marker — not supported by SSH ECDH

        SshException ex = Assert.Throws<SshException>(
            () => k.ComputeSharedSecret(bad));
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void ComputeSharedSecret_PointNotOnCurve_MapsToKexFailure(int alg, int _)
    {
        // A well-formed-length uncompressed point that is NOT on the curve:
        // the BCL import/derive throws CryptographicException, which must be
        // mapped to KEX_FAILURE (parity with the C) instead of escaping raw.
        using var k = new EcdhNistP((KexAlgorithm)alg);
        int coordSize = (k.PublicKeyPoint.Length - 1) / 2;
        byte[] bad = new byte[k.PublicKeyPoint.Length];
        bad[0] = 0x04;
        // X = p - 1, Y = 0: not a valid curve point (and not the point at
        // infinity in SEC1 uncompressed form).
        bad.AsSpan(1, coordSize).Fill(0xFF);
        if (coordSize == 32)
        {
            bad[1 + coordSize - 1] = 0xFE;   // p-1 mod 2^256 — still off-curve
        }

        SshException ex = Assert.Throws<SshException>(
            () => k.ComputeSharedSecret(bad));
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void PublicKeyPoint_RoundTripsThroughBclImport(int alg, int _)
    {
        // The point we produce must be importable by the BCL's own parser (the
        // same path ComputeSharedSecret uses for the peer point). Deriving
        // against our own public point must not throw — it proves the encoding
        // is BCL-valid.
        using var k = new EcdhNistP((KexAlgorithm)alg);
        using var other = new EcdhNistP((KexAlgorithm)alg);

        byte[] secret = other.ComputeSharedSecret(k.PublicKeyPoint);
        Assert.NotEmpty(secret);
    }

    [Theory]
    [MemberData(nameof(CurveSizes))]
    public void PublicKeyPoint_CoordinatesAreFieldSized(int alg, int expectedLen)
    {
        int coordSize = (expectedLen - 1) / 2;
        using var k = new EcdhNistP((KexAlgorithm)alg);
        byte[] q = k.PublicKeyPoint;
        ECCurve curve = CurveFor((KexAlgorithm)alg);

        using var ecdh = ECDiffieHellman.Create(curve);
        ecdh.ImportParameters(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = q.AsSpan(1, coordSize).ToArray(),
                Y = q.AsSpan(1 + coordSize, coordSize).ToArray(),
            },
        });
        Assert.NotNull(ecdh.PublicKey);
    }

    private static ECCurve CurveFor(KexAlgorithm alg) => alg switch
    {
        KexAlgorithm.EcdhSha2Nistp256 => ECCurve.NamedCurves.nistP256,
        KexAlgorithm.EcdhSha2Nistp384 => ECCurve.NamedCurves.nistP384,
        KexAlgorithm.EcdhSha2Nistp521 => ECCurve.NamedCurves.nistP521,
        _ => throw new ArgumentOutOfRangeException(nameof(alg)),
    };
}
