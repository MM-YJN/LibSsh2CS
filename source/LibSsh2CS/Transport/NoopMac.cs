namespace LibSsh2CS.Transport;

/// <summary>
/// The no-op MAC used alongside AEAD ciphers (<c>mac_method_hmac_aesgcm</c>,
/// <c>mac.c:529</c>, and implicitly for ChaCha20-Poly1305). No bytes are produced
/// or verified; the cipher's own tag provides integrity.
/// </summary>
internal sealed class NoopMac : IMac
{
    public string Name => "none";
    public int MacLen => 0;
    public bool IsEtm => false;

    public void Init(ReadOnlySpan<byte> key)
    {
        // Intentionally empty — no key material for an integrated-MAC cipher.
    }

    public void Compute(uint seqno, ReadOnlySpan<byte> data, Span<byte> mac)
    {
        // No-op; AEAD tag is produced by the cipher.
    }

    public bool Verify(uint seqno, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mac) => true;

    public void Dispose()
    {
    }
}
