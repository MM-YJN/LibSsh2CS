namespace LibSsh2CS.Transport;

/// <summary>
/// The managed equivalent of libssh2's <c>struct _LIBSSH2_CRYPT_METHOD</c>
/// (<c>libssh2_priv.h:1017</c>): metadata (name, block/iv/key/tag sizes, flags)
/// plus the <c>init</c>/<c>crypt</c>/<c>get_len</c> function pointers.
/// </summary>
/// <remarks>
/// <para>
/// One instance handles <b>every packet in a single direction</b> for the life of
/// that key — mirroring libssh2 keeping a single cipher context
/// (<c>session-&gt;local.crypt_abstract</c> / <c>session-&gt;remote.crypt_abstract</c>).
/// Therefore chaining state (CBC IV carry, CTR counter carry, the GCM invocation
/// counter) persists across <see cref="Crypt"/>/<see cref="CryptAead"/> calls on
/// the same instance, exactly as OpenSSL's persistent <c>EVP_CIPHER_CTX</c> does
/// under libssh2.
/// </para>
/// <para>
/// Two operation shapes cover the four SSH framing families:
/// <list type="bullet">
/// <item><see cref="Crypt"/> — the standard path for AES-{CTR,CBC} (Standard and
/// ETM framing; the MAC is computed separately by the packet layer).</item>
/// <item><see cref="CryptAead"/> — the AEAD path for AES-GCM and
/// ChaCha20-Poly1305 (length handled as AAD / via the header key).</item>
/// </list>
/// Which path applies is decided by <see cref="CipherMethods.IsAead"/>; a cipher
/// only implements the one matching its family.
/// </para>
/// </remarks>
internal interface ICipher : IDisposable
{
    /// <summary>The SSH algorithm name (e.g. <c>aes256-ctr</c>).</summary>
    string Name { get; }

    /// <summary>Block size in bytes (<c>crypt_method.blocksize</c>). Always 16 for
    /// AES; 8 for ChaCha20-Poly1305 (SSH's minimum block size).</summary>
    int BlockSize { get; }

    /// <summary>IV length in bytes (<c>crypt_method.iv_len</c>).</summary>
    int IvLen { get; }

    /// <summary>Key length in bytes (<c>crypt_method.secret_len</c>).</summary>
    int KeyLen { get; }

    /// <summary>Authentication tag length in bytes (<c>crypt_method.auth_len</c>).
    /// 16 for AES-GCM and ChaCha20-Poly1305; 0 otherwise.</summary>
    int AuthTagLen { get; }

    /// <summary>Capability flags (<c>crypt_method.flags</c>).</summary>
    CipherFlags Flags { get; }

    /// <summary>
    /// Sets up the per-direction crypto context. Port of
    /// <c>crypt_method-&gt;init(session, iv, secret, encrypt)</c>.
    /// </summary>
    void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt);

    /// <summary>
    /// Standard cipher path (AES-{CTR,CBC}): encrypt or decrypt <paramref name="data"/>
    /// in place. Called by the packet layer for Standard/ETM framing, where the MAC
    /// is computed separately. <paramref name="data"/> is a whole number of blocks
    /// (SSH pads to the block boundary). Chaining state persists across calls.
    /// </summary>
    /// <exception cref="NotSupportedException">AEAD ciphers do not support this path.</exception>
    void Crypt(Span<byte> data);

    /// <summary>
    /// AEAD path (AES-GCM, ChaCha20-Poly1305): process a full packet.
    /// <list type="bullet">
    /// <item><c>aadLen</c> — leading authenticated-only bytes (the 4-byte packet
    /// length; AAD for GCM, header-key-encrypted for ChaCha20).</item>
    /// <item><c>payloadLen</c> — bytes after the AAD that get encrypted/decrypted.</item>
    /// <item>encrypt: <paramref name="dest"/> receives the transformed
    /// <c>aadLen + payloadLen</c> bytes followed by <see cref="AuthTagLen"/> tag bytes.</item>
    /// <item>decrypt: the tag at <c>src[aadLen+payloadLen..]</c> is verified first;
    /// on mismatch a <see cref="SshException"/>(<see cref="SshErrorCode.Decrypt"/>)
    /// is thrown and <paramref name="dest"/> is left untouched.</item>
    /// </list>
    /// </summary>
    void CryptAead(uint seqno, Span<byte> dest, ReadOnlySpan<byte> src, int payloadLen, int aadLen, bool encrypt);

    /// <summary>
    /// Port of <c>crypt_method-&gt;get_len</c>: recover the 4-byte packet length
    /// before the full decrypt, for ciphers where it is not simply the first
    /// decrypted block. Returns <c>false</c> for AES-{CTR,CBC} (the packet layer
    /// decrypts the first block to learn the length).
    /// </summary>
    bool TryGetLength(uint seqno, ReadOnlySpan<byte> ciphertext, out uint length);
}

