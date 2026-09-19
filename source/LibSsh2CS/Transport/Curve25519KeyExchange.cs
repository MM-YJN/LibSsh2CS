using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// Curve25519 Diffie-Hellman key exchange (RFC 8731), used by the
/// <c>curve25519-sha256</c> / <c>curve25519-sha256@libssh2.org</c> KEX methods.
/// </summary>
/// <remarks>
/// <para>
/// libssh2 C source: <c>kex.c</c> <c>curve25519_sha256</c> + the in-ported
/// <c>curve25519.c</c>. The scalar-multiplication primitive is the BCL
/// <see cref="X25519DiffieHellman"/> (constant-time, platform-backed), which
/// replaces the previous in-ported RFC 7748 §5 Montgomery ladder.
/// </para>
/// <para>
/// The client public key is exchanged as a 32-byte little-endian u-coordinate
/// inside an SSH <c>string</c> — <b>not</b> an mpint (RFC 8731 §3). The shared
/// secret <c>K</c> is the 32-byte X25519 output, which the KEX layer
/// mpint-encodes (interpreting the little-endian bytes as a big-endian integer,
/// matching libssh2's <c>_libssh2_bn_from_bin</c> over the reversed buffer).
/// </para>
/// </remarks>
internal sealed class Curve25519KeyExchange : IDisposable
{
    private readonly X25519DiffieHellman _key;

    /// <summary>Generates a fresh ephemeral curve25519 keypair.</summary>
    public Curve25519KeyExchange()
    {
        _key = X25519DiffieHellman.GenerateKey();
        PublicKey = _key.ExportPublicKey();
    }

    /// <summary>
    /// Test-only ctor that imports an explicit private key, used to run the
    /// RFC 7748 §6.1 fixed DH vectors through the public surface. Production
    /// code uses the parameterless ctor (<c>X25519DiffieHellman.GenerateKey</c>).
    /// </summary>
    internal Curve25519KeyExchange(byte[] privateKey)
    {
        _key = X25519DiffieHellman.ImportPrivateKey(privateKey);
        PublicKey = _key.ExportPublicKey();
    }

    /// <summary>
    /// The client ephemeral public key (32 bytes, little-endian u-coordinate),
    /// to be sent in SSH_MSG_KEX_ECDH_INIT as an SSH <c>string</c>.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Derives the shared secret <c>K</c> from the server's 32-byte ephemeral
    /// public key. Returns the 32-byte X25519 output (which the KEX layer
    /// mpint-encodes for the exchange hash).
    /// </summary>
    public byte[] ComputeSharedSecret(byte[] serverPublicKey)
    {
        if (serverPublicKey.Length != 32)
        {
            // C parity: kex.c:2691-2694 rejects any Q_S length other than
            // LIBSSH2_ED25519_KEY_LEN with LIBSSH2_ERROR_HOSTKEY_INIT. Here the
            // KEX layer's public error contract maps this to KexFailure, like
            // the sibling ECDH path.
            throw new SshException(SshErrorCode.KexFailure,
                "Unexpected curve25519 server public key length");
        }

        try
        {
            return _key.DeriveRawSecretAgreement(serverPublicKey);
        }
        catch (CryptographicException ex)
        {
            // C parity: kex.c:2720-2725 and openssl.c:_libssh2_curve25519_gen_k
            // map derive failures (including low-order public keys rejected by
            // OpenSSL) to LIBSSH2_ERROR_KEX_FAILURE.
            throw new SshException(SshErrorCode.KexFailure,
                "Unable to create curve25519 shared secret", ex);
        }
        catch (ArgumentException ex)
        {
            // Defensive: the BCL can also throw ArgumentException for invalid
            // public-key input; keep the KEX error contract uniform.
            throw new SshException(SshErrorCode.KexFailure,
                "Unable to create curve25519 shared secret", ex);
        }
        catch (PlatformNotSupportedException ex)
        {
            // Mirror EcdhNistP: some backends surface invalid peer input as
            // PlatformNotSupportedException.
            throw new SshException(SshErrorCode.KexFailure,
                "Unable to create curve25519 shared secret", ex);
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _key.Dispose();
}
