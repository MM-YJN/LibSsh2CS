namespace LibSsh2CS;

/// <summary>
/// Channel-related constants — verbatim from <c>libssh2.h:824-826</c> (window /
/// packet / min-adjust defaults) and <c>libssh2_priv.h:1183-1186</c>
/// (<c>SSH_MSG_CHANNEL_OPEN_FAILURE</c> reason codes). Pure data; no behaviour.
/// </summary>
/// <remarks>
/// Used by <see cref="SshChannel"/> (the defaults every session-type channel
/// advertises in <c>SSH_MSG_CHANNEL_OPEN</c>) and by
/// <see cref="Transport.ChannelRouter"/> (the min-adjust floor for outbound
/// <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> messages).
/// </remarks>
internal static class ChannelConstants
{
    /// <summary>
    /// <c>LIBSSH2_CHANNEL_WINDOW_DEFAULT (2*1024*1024)</c> (<c>libssh2.h:824</c>) —
    /// the initial receive window (inbound) every channel advertises in
    /// <c>SSH_MSG_CHANNEL_OPEN</c>. This is the number of bytes the peer may send
    /// before we must reply with a <c>WINDOW_ADJUST</c>. Mirrors the value
    /// libssh2 sends for <c>libssh2_channel_open_session</c>
    /// (<c>channel.c:416-417</c>).
    /// </summary>
    public const uint WindowDefault = 2 * 1024 * 1024;

    /// <summary>
    /// <c>LIBSSH2_CHANNEL_PACKET_DEFAULT 32768</c> (<c>libssh2.h:825</c>) — the
    /// maximum channel-data payload (in bytes) every channel advertises it will
    /// accept in a single <c>SSH_MSG_CHANNEL_DATA</c> /
    /// <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> packet. The peer MUST NOT send a
    /// larger payload (RFC 4254 §5); if it does, we MAY truncate
    /// (<c>packet.c:1037-1046</c>).
    /// </summary>
    public const uint PacketDefault = 32768;

    /// <summary>
    /// <c>LIBSSH2_CHANNEL_MINADJUST 1024</c> (<c>libssh2.h:826</c>) — the minimum
    /// <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> increment libssh2 will send
    /// (<c>channel.c:1881-1890</c>, <c>2095-2096</c>). Smaller adjustments are
    /// queued in <c>channel-&gt;adjust_queue</c> until they sum to at least this
    /// much, reducing per-read adjust-packet overhead.
    /// </summary>
    public const uint MinAdjust = 1024;

    /// <summary>
    /// The per-call write cap applied in <c>_libssh2_channel_write</c>
    /// (<c>channel.c:2351</c>): "32K is a conservative limit based on the text in
    /// RFC4253 section 6.1." A larger caller buffer is split across multiple
    /// <c>SSH_MSG_CHANNEL_DATA</c> packets by re-invoking the write loop.
    /// </summary>
    public const int WriteChunkCap = 32700;

    /// <summary>
    /// <c>SSH_EXTENDED_DATA_STDERR (1)</c> — the data_type_code that identifies
    /// stderr in <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> packets (RFC 4254 §5.2).
    /// Used by <see cref="SshChannel.ReadStderrAsync"/> on the receive side and
    /// by <see cref="SshChannel.WriteStderrAsync"/> on the send side.
    /// </summary>
    public const int StreamIdStderr = 1;

    // ── SSH_MSG_CHANNEL_OPEN_FAILURE reason codes (libssh2_priv.h:1183-1186) ──
    // Echoed back by the server when it rejects our CHANNEL_OPEN; mapped to
    // exception messages in SshChannel.OpenAsync (parity channel.c:285-310).

    /// <summary><c>SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1</c>.</summary>
    public const int OpenAdministrativelyProhibited = 1;

    /// <summary><c>SSH_OPEN_CONNECT_FAILED 2</c>.</summary>
    public const int OpenConnectFailed = 2;

    /// <summary><c>SSH_OPEN_UNKNOWN_CHANNELTYPE 3</c>.</summary>
    public const int OpenUnknownChannelType = 3;

    /// <summary><c>SSH_OPEN_RESOURCE_SHORTAGE 4</c>.</summary>
    public const int OpenResourceShortage = 4;
}
