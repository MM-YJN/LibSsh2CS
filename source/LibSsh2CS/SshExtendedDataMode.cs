namespace LibSsh2CS;

/// <summary>
/// Controls how <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> (stderr) is presented to
/// the caller. Mirrors the libssh2 <c>LIBSSH2_CHANNEL_EXTENDED_DATA_*</c>
/// constants (<c>libssh2.h</c>) used by
/// <c>libssh2_channel_handle_extended_data2</c> (<c>channel.c:2027-2039</c>).
/// </summary>
/// <remarks>
/// <para>
/// The mode is set via <see cref="SshChannel.SetExtendedDataModeAsync"/> — the
/// setter is async because transitioning to <see cref="Ignore"/> flushes any
/// already-buffered stderr and refunds the peer's send window
/// (parity intent of <c>channel.c:2010-2016</c>).
/// </para>
/// <list type="bullet">
/// <item><term><see cref="Normal"/></term><description>Default. Stderr is
/// buffered separately and accessed only via <c>ReadStderrAsync</c>. This is
/// the git transport mode.</description></item>
/// <item><term><see cref="Ignore"/></term><description>Stderr packets are
/// dropped at delivery time (router-level, parity <c>packet.c:994-1030</c>);
/// the freed window bytes are immediately refunded to the peer via
/// <c>WINDOW_ADJUST</c>. <c>ReadStderrAsync</c> always returns 0. Use this to
/// discard server diagnostics on stdout-EOF rather than reading them.</description></item>
/// <item><term><see cref="Merge"/></term><description>Stderr is buffered
/// separately (like <see cref="Normal"/>) but is ALSO drained by
/// <c>ReadAsync</c> after stdout. Divergence from libssh2: the C port preserves
/// wire arrival order across stdout+stderr (single packet list); this C# port
/// drains the stdout FIFO first, then the stderr FIFO.</description></item>
/// </list>
/// </remarks>
public enum SshExtendedDataMode
{
    /// <summary>
    /// <c>LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL (0)</c> — stderr buffered
    /// separately; only <c>ReadStderrAsync</c> returns it.
    /// </summary>
    Normal = 0,

    /// <summary>
    /// <c>LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE (1)</c> — stderr dropped at
    /// delivery; window refunded immediately; <c>ReadStderrAsync</c> returns 0.
    /// </summary>
    Ignore = 1,

    /// <summary>
    /// <c>LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE (2)</c> — stderr also drained by
    /// <c>ReadAsync</c> (after stdout).
    /// </summary>
    Merge = 2,
}
