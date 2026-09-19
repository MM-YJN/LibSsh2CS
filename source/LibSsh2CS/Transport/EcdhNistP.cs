using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// Elliptic-curve Diffie-Hellman key exchange over the NIST prime curves
/// <c>secp256r1</c> / <c>secp384r1</c> / <c>secp521r1</c> (RFC 5656), used by
/// the <c>ecdh-sha2-nistp256</c> / <c>384</c> / <c>521</c> KEX methods.
/// </summary>
/// <remarks>
/// <para>
/// libssh2 C source: <c>kex.c</c> <c>ecdh_sha2_nistp</c> + the OpenSSL backend
/// <c>_libssh2_ecdsa_create_key</c> / <c>_libssh2_ecdh_derive</c>. The backend
/// abstraction collapses to BCL <see cref="ECDiffieHellman"/> here.
/// </para>
/// <para>
/// The client public key is exchanged as a SEC1 uncompressed point
/// (<c>0x04 ‖ X ‖ Y</c>) inside an SSH <c>string</c> — <b>not</b> an mpint (RFC
/// 5656 §4). The shared secret <c>K</c> is the X-coordinate of the derived
/// point, returned here as raw big-endian bytes of the full coordinate length
/// (32 / 48 / 66 bytes); the KEX layer mpint-encodes it for the exchange hash
/// (a leading zero, if the X-coordinate's top bit is clear, is stripped by the
/// mpint encoder — matching libssh2's <c>_libssh2_bn_bytes</c>).
/// </para>
/// </remarks>
internal sealed class EcdhNistP : IDisposable
{
    private readonly ECDiffieHellman _ecdh;
    private readonly ECCurve _curve;
    private readonly int _coordSize;

    /// <summary>
    /// Generates a fresh ephemeral keypair on the curve selected by
    /// <paramref name="algorithm"/> (one of the three ECDH-nistp methods).
    /// </summary>
    public EcdhNistP(KexAlgorithm algorithm)
    {
        (ECCurve curve, int coordSize) = CurveFor(algorithm);
        _curve = curve;
        _coordSize = coordSize;
        _ecdh = ECDiffieHellman.Create(curve);
        ECParameters p = _ecdh.ExportParameters(includePrivateParameters: false);
        PublicKeyPoint = BuildUncompressedPoint(p.Q, coordSize);
    }

    /// <summary>
    /// The client ephemeral public key as a SEC1 uncompressed point
    /// (<c>0x04 ‖ X ‖ Y</c>), to be sent in SSH_MSG_KEX_ECDH_INIT as an SSH
    /// <c>string</c>. Length is <c>1 + 2 * coordSize</c> (65 / 97 / 133).
    /// </summary>
    public byte[] PublicKeyPoint { get; }

    /// <summary>
    /// Derives the shared secret <c>K</c> from the server's ephemeral public key
    /// (<paramref name="serverPublicKeyPoint"/>, a SEC1 uncompressed point).
    /// Returns the raw big-endian X-coordinate of the derived point (32 / 48 /
    /// 66 bytes). This is the value the KEX layer mpint-encodes into the
    /// exchange hash and feeds to key derivation.
    /// </summary>
    /// <remarks>
    /// All peer-point failures (bad length/prefix, point not on the curve, BCL
    /// derive errors) are mapped to <see cref="SshErrorCode.KexFailure"/> —
    /// parity with the C, where <c>EC_POINT_oct2point</c> /
    /// <c>EVP_PKEY_derive</c> failures return <c>LIBSSH2_ERROR_KEX_FAILURE</c>
    /// "Unable to create ECDH shared secret" (openssl.c:4321-4326, 4259-4290;
    /// kex.c:2049-2053). Previously a well-formed-length point not on the curve
    /// let the BCL's raw <c>CryptographicException</c> escape the KEX layer.
    /// </remarks>
    public byte[] ComputeSharedSecret(byte[] serverPublicKeyPoint)
    {
        try
        {
            ECPoint q = ParseUncompressedPoint(serverPublicKeyPoint, _coordSize);
            // Import the peer point into a throwaway ECDH instance to obtain an
            // ECDiffieHellmanPublicKey for DeriveRawSecretAgreement (the BCL takes
            // a key handle, not a raw point). Public-only import (D left null).
            using var peer = ECDiffieHellman.Create(_curve);
            peer.ImportParameters(new ECParameters { Curve = _curve, Q = q });
            return _ecdh.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.Proto)
        {
            throw new SshException(SshErrorCode.KexFailure,
                "Unable to create ECDH shared secret", ex);
        }
        catch (CryptographicException ex)
        {
            throw new SshException(SshErrorCode.KexFailure,
                "Unable to create ECDH shared secret", ex);
        }
        catch (PlatformNotSupportedException ex)
        {
            // Windows CNG surfaces an invalid peer point as
            // PlatformNotSupportedException (wrapping a CryptographicException)
            // instead of CryptographicException directly. The curve was already
            // proven supported by the constructor, so this is a peer-point
            // failure — map it to KEX_FAILURE like the C.
            throw new SshException(SshErrorCode.KexFailure,
                "Unable to create ECDH shared secret", ex);
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _ecdh.Dispose();

    private static (ECCurve Curve, int CoordSize) CurveFor(KexAlgorithm algorithm)
        => algorithm switch
        {
            KexAlgorithm.EcdhSha2Nistp256 => (ECCurve.NamedCurves.nistP256, 32),
            KexAlgorithm.EcdhSha2Nistp384 => (ECCurve.NamedCurves.nistP384, 48),
            KexAlgorithm.EcdhSha2Nistp521 => (ECCurve.NamedCurves.nistP521, 66),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm),
                $"{algorithm} is not an ECDH-nistp KEX method."),
        };

    /// <summary>
    /// Builds a SEC1 uncompressed point (<c>0x04 ‖ X ‖ Y</c>) with both
    /// coordinates left-zero-padded to <paramref name="coordSize"/>. The BCL
    /// already returns padded coordinates, but the pad is defensive against any
    /// backend that trims leading zeros.
    /// </summary>
    private static byte[] BuildUncompressedPoint(ECPoint q, int coordSize)
    {
        byte[] point = new byte[1 + (2 * coordSize)];
        point[0] = 0x04;
        PadLeft(q.X, coordSize).CopyTo(point.AsSpan(1, coordSize));
        PadLeft(q.Y, coordSize).CopyTo(point.AsSpan(1 + coordSize, coordSize));
        return point;
    }

    private static ECPoint ParseUncompressedPoint(byte[] data, int coordSize)
    {
        if (data.Length != 1 + (2 * coordSize) || data[0] != 0x04)
        {
            throw new SshException(SshErrorCode.Proto,
                $"Invalid EC point: len={data.Length}, expected {1 + (2 * coordSize)} uncompressed.");
        }

        return new ECPoint
        {
            X = data.AsSpan(1, coordSize).ToArray(),
            Y = data.AsSpan(1 + coordSize, coordSize).ToArray(),
        };
    }

    private static byte[] PadLeft(byte[]? coord, int size)
    {
        if (coord is null)
        {
            return new byte[size];
        }

        if (coord.Length == size)
        {
            return coord;
        }

        if (coord.Length > size)
        {
            throw new SshException(SshErrorCode.Proto,
                $"EC coordinate ({coord.Length}B) longer than field size ({size}).");
        }

        byte[] padded = new byte[size];
        coord.AsSpan().CopyTo(padded.AsSpan(size - coord.Length));
        return padded;
    }
}
