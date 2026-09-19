namespace LibSsh2CS.Transport;

/// <summary>
/// A decrypted, MAC-verified, decompressed inbound SSH packet — the output of
/// <see cref="PacketReader.ReadPacketAsync"/>. The <see cref="Payload"/> begins
/// with the <c>SSH_MSG_*</c> type byte; <see cref="Seqno"/> is the inbound
/// sequence number the packet was sent under (recorded before any strict-KEX
/// NEWKEYS reset, so the caller can observe the reset).
/// </summary>
/// <remarks>
/// Minimal carrier with no queueing logic or type filtering.
/// <see cref="PacketQueue"/> handles inline DISCONNECT / IGNORE / DEBUG / EXT_INFO packets.
/// </remarks>
internal readonly struct RawPacket
{
    /// <summary>The <c>SSH_MSG_*</c> type byte (<see cref="PacketType"/>).</summary>
    public int Type { get; }

    /// <summary>
    /// The full decrypted payload, beginning with the type byte. A copy owned
    /// by the caller (the reader does not retain a reference into the pipe).
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// The inbound sequence number this packet carried (pre-NEWKEYS-reset if
    /// the packet was a NEWKEYS under strict-KEX).
    /// </summary>
    public uint Seqno { get; }

    public RawPacket(int type, byte[] payload, uint seqno)
    {
        Type = type;
        Payload = payload;
        Seqno = seqno;
    }
}
