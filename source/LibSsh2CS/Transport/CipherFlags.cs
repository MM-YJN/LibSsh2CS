namespace LibSsh2CS.Transport;

/// <summary>
/// Bit flags for <see cref="ICipher"/>, a 1:1 port of the
/// <c>LIBSSH2_CRYPT_FLAG_*</c> defines in <c>libssh2_priv.h:1048</c>. The numeric
/// values are reproduced exactly.
/// </summary>
[Flags]
internal enum CipherFlags
{
    /// <summary><c>LIBSSH2_CRYPT_FLAG_INTEGRATED_MAC 1</c> — cipher has its own
    /// message authentication (AES-GCM). ChaCha20-Poly1305 authenticates too, but
    /// libssh2 leaves this bit clear for it and drives the MAC through
    /// <c>get_len</c>/<c>crypt</c> instead.</summary>
    None = 0,

    /// <summary><c>LIBSSH2_CRYPT_FLAG_INTEGRATED_MAC 1</c>.</summary>
    IntegratedMac = 1,

    /// <summary><c>LIBSSH2_CRYPT_FLAG_PKTLEN_AAD 2</c> — the 4-byte packet length
    /// is authenticated associated data, not encrypted (AES-GCM).</summary>
    PktLenAad = 2,

    /// <summary><c>LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET 4</c> — the whole packet
    /// must be processed in one shot (ChaCha20-Poly1305).</summary>
    RequiresFullPacket = 4,
}
