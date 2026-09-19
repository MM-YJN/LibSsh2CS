namespace LibSsh2CS.Transport;

/// <summary>
/// The outcome of KEXINIT negotiation — the 8 negotiated algorithms + the
/// strict-KEX flag detected from the server's kex name-list.
/// <c>KeyExchange.RunExchangeAsync</c> consumes this to dispatch the DH/ECDH/
/// X25519 math and to install post-NEWKEYS cipher/MAC/compression instances
/// via <see cref="PacketReader.SetInboundKeys"/> / <see cref="PacketWriter.SetOutboundKeysAsync"/>.
/// </summary>
internal sealed record NegotiatedMethods
{
    /// <summary>The negotiated KEX algorithm (resolved from <see cref="KexName"/>).</summary>
    public required KexAlgorithm Kex { get; init; }

    /// <summary>The negotiated KEX algorithm wire name (e.g. <c>curve25519-sha256</c>).</summary>
    public required string KexName { get; init; }

    /// <summary>The negotiated server host-key type.</summary>
    public required SshHostKeyType HostKey { get; init; }

    /// <summary>The negotiated server host-key wire name (e.g. <c>ssh-ed25519</c>).</summary>
    public required string HostKeyName { get; init; }

    /// <summary>The negotiated client→server cipher name.</summary>
    public required string CipherCs { get; init; }

    /// <summary>The negotiated server→client cipher name.</summary>
    public required string CipherSc { get; init; }

    /// <summary>
    /// The negotiated client→server MAC name. For AES-GCM ciphers this is
    /// <see cref="MacMethods.Noop"/>'s name (<c>"none"</c>) — the
    /// <c>_libssh2_mac_override</c> path (<c>mac.c:542</c>). For ChaCha20-Poly1305
    /// a real MAC is negotiated (mirrors libssh2); the transport layer ignores
    /// it because the AEAD tag provides integrity.
    /// </summary>
    public required string MacCs { get; init; }

    /// <summary>The negotiated server→client MAC name (see <see cref="MacCs"/>).</summary>
    public required string MacSc { get; init; }

    /// <summary>The negotiated client→server compression name.</summary>
    public required string CompCs { get; init; }

    /// <summary>The negotiated server→client compression name.</summary>
    public required string CompSc { get; init; }

    /// <summary>
    /// True iff the server's kex name-list contained
    /// <c>kex-strict-s-v00@openssh.com</c> (Terrapin mitigation, OpenSSH 9.6+).
    /// When true, the transport enforces: KEXINIT must be the first packet, no
    /// unexpected packet types during INITIAL_KEX, and seqno resets to 0 after
    /// NEWKEYS. Detected in <see cref="KeyExchange.Negotiate"/> matching
    /// <c>kex.c:3681-3686</c>.
    /// </summary>
    public required bool StrictKex { get; init; }
}
