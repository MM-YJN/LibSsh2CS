namespace LibSsh2CS.Transport;

/// <summary>
/// A parsed SSH_MSG_KEXINIT payload (RFC 4253 §7.1). A 16-byte cookie followed
/// by 10 name-lists, a boolean <c>first_kex_packet_follows</c>, and a reserved
/// <see cref="uint"/> (always 0 on the wire). Port of libssh2's
/// <c>session-&gt;{local,remote}.kexinit</c> buffers.
/// </summary>
/// <remarks>
/// <see cref="KeyExchange.ParseKexInit(ReadOnlyMemory{byte})"/> consumes the type byte first (the payload passed
/// in begins with <c>SSH_MSG_KEXINIT</c> = 20), so the fields below start after
/// it. <see cref="KeyExchange.BuildKexInit"/> produces a payload INCLUDING the type byte,
/// ready to hand to <see cref="PacketWriter.WritePacketAsync"/>.
/// </remarks>
internal sealed record KexInit
{
    /// <summary>The 16-byte random cookie (RFC 4253 §7.1). Match-protection against
    /// KEXINIT spoofing; otherwise unused by the protocol.</summary>
    public required byte[] Cookie { get; init; }

    /// <summary>1: kex_algorithms (RFC 4253 §7.1). May contain the pseudo-methods
    /// <c>ext-info-c</c> / <c>kex-strict-c-v00@openssh.com</c> in addition to real
    /// KEX algorithms.</summary>
    public required string[] KexAlgorithms { get; init; }

    /// <summary>2: server_host_key_algorithms.</summary>
    public required string[] ServerHostKeyAlgorithms { get; init; }

    /// <summary>3: encryption_algorithms_client_to_server.</summary>
    public required string[] EncryptionAlgorithmsClientToServer { get; init; }

    /// <summary>4: encryption_algorithms_server_to_client.</summary>
    public required string[] EncryptionAlgorithmsServerToClient { get; init; }

    /// <summary>5: mac_algorithms_client_to_server.</summary>
    public required string[] MacAlgorithmsClientToServer { get; init; }

    /// <summary>6: mac_algorithms_server_to_client.</summary>
    public required string[] MacAlgorithmsServerToClient { get; init; }

    /// <summary>7: compression_algorithms_client_to_server.</summary>
    public required string[] CompressionAlgorithmsClientToServer { get; init; }

    /// <summary>8: compression_algorithms_server_to_client.</summary>
    public required string[] CompressionAlgorithmsServerToClient { get; init; }

    /// <summary>9: languages_client_to_server (almost always empty).</summary>
    public required string[] LanguagesClientToServer { get; init; }

    /// <summary>10: languages_server_to_client (almost always empty).</summary>
    public required string[] LanguagesServerToClient { get; init; }

    /// <summary>
    /// <c>first_kex_packet_follows</c> (RFC 4253 §7.1): a boolean indicating
    /// that a first KEX packet follows the KEXINIT. libssh2 always writes
    /// <c>false</c> (0) — there is no optimistic KEX packet. We mirror that.
    /// </summary>
    public required bool FirstKexPacketFollows { get; init; }

    /// <summary>The reserved uint32 (RFC 4253 §7.1); always 0 on the wire.</summary>
    public required uint Reserved { get; init; }
}
