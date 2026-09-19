namespace LibSsh2CS.Transport;

/// <summary>
/// The key-exchange algorithm selected during KEXINIT negotiation. Port of the
/// <c>LIBSSH2_KEX_METHOD</c> discriminator. The dispatch
/// (<c>KeyExchange.RunExchangeAsync</c>) switches on this to drive DH group14,
/// ECDH nistp256/384/521, or X25519.
/// </summary>
internal enum KexAlgorithm
{
    /// <summary>Not yet negotiated.</summary>
    None = 0,

    /// <summary><c>curve25519-sha256</c> (RFC 8731). X25519 scalar mult + SHA-256.</summary>
    Curve25519Sha256,

    /// <summary><c>ecdh-sha2-nistp256</c> (RFC 5656). ECDH on secp256r1 + SHA-256.</summary>
    EcdhSha2Nistp256,

    /// <summary><c>ecdh-sha2-nistp384</c> (RFC 5656). ECDH on secp384r1 + SHA-384.</summary>
    EcdhSha2Nistp384,

    /// <summary><c>ecdh-sha2-nistp521</c> (RFC 5656). ECDH on secp521r1 + SHA-512.</summary>
    EcdhSha2Nistp521,

    /// <summary><c>diffie-hellman-group14-sha256</c> (RFC 8268). modp2048 + SHA-256.</summary>
    DhGroup14Sha256,
}
