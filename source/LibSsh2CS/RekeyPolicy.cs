namespace LibSsh2CS;

/// <summary>
/// The rekey threshold policy — when the rekey auto-trigger
/// fires <see cref="SshSession.RekeyAsync"/>. A rekey is triggered when ANY of
/// the per-direction thresholds (bytes or packets) is exceeded, OR when the
/// elapsed time since the last NEWKEYS exceeds <see cref="MaxInterval"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>OpenSSH parity (default).</b> OpenSSH's <c>sshd</c> proactively rekeys at
/// 4 GB of data OR 2³¹ packets OR 1 hour by default; <see cref="Default"/>
/// matches those values so the client preempts the server. libssh2 itself has
/// no client-side auto-trigger — it only rekeys when the server initiates; the
/// defaults here go beyond libssh2 to align with the de-facto OpenSSH standard.
/// </para>
/// <para>
/// <b>Time trigger.</b> The elapsed time is measured via the session's
/// <see cref="TimeProvider"/> (production: <see cref="TimeProvider.System"/>;
/// tests: <c>FakeTimeProvider</c>). The time check fires only when a channel
/// operation pumps the transport — a quiet session that has not exchanged any
/// packets in over an hour does NOT auto-rekey on time alone (no data flowing
/// means nothing to protect). This matches OpenSSH's effective behavior
/// (the 1hr timer is reset by activity).
/// </para>
/// <para>
/// <b>Per-direction accounting.</b> The byte/packet counters live on
/// <see cref="Transport.PacketReader"/> and <see cref="Transport.PacketWriter"/>
/// (split by direction, parity with libssh2's transport-layer counters). The
/// trigger fires when EITHER direction exceeds its threshold — either side
/// hitting the RFC 4253 §9 limit is sufficient reason to rekey.
/// </para>
/// </remarks>
public sealed record RekeyPolicy
{
    /// <summary>
    /// Maximum bytes sent OR received under the current key before a rekey is
    /// triggered. <see cref="long.MaxValue"/> disables the byte threshold.
    /// </summary>
    public long MaxBytes { get; init; } = DefaultMaxBytes;

    /// <summary>
    /// Maximum packets sent OR received under the current key before a rekey
    /// is triggered. <see cref="long.MaxValue"/> disables the packet threshold.
    /// </summary>
    public long MaxPackets { get; init; } = DefaultMaxPackets;

    /// <summary>
    /// Maximum elapsed time since the last NEWKEYS before a rekey is triggered,
    /// checked at channel-op boundaries. <see cref="TimeSpan.MaxValue"/>
    /// disables the time threshold.
    /// </summary>
    public TimeSpan MaxInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// OpenSSH-default policy: 4 GB data OR 2³¹ packets OR 1 hour. Used as the
    /// initial value of <see cref="SshSession.RekeyPolicy"/>.
    /// </summary>
    /// <remarks>
    /// The values are inlined (not referencing <c>DefaultMaxBytes</c> etc.) to
    /// avoid C# static-field initialization order hazards —
    /// <see cref="Default"/> initializes before the <c>static readonly</c>
    /// <see cref="DefaultMaxInterval"/> field would, leaving it as
    /// <see cref="TimeSpan.Zero"/>.
    /// </remarks>
    public static RekeyPolicy Default { get; } = new()
    {
        MaxBytes = 4L * 1024 * 1024 * 1024,
        MaxPackets = int.MaxValue,
        MaxInterval = TimeSpan.FromHours(1),
    };

    /// <summary>
    /// Disables all auto-triggers. The session rekeys only when the server
    /// initiates (handled by <see cref="Transport.PacketQueue"/>'s inline
    /// dispatch). Useful for callers that prefer to manage rekey manually via
    /// <see cref="SshSession.RekeyAsync"/>.
    /// </summary>
    public static RekeyPolicy Never { get; } = new()
    {
        MaxBytes = long.MaxValue,
        MaxPackets = long.MaxValue,
        MaxInterval = TimeSpan.MaxValue,
    };

    /// <summary>OpenSSH's 4 GB data threshold. Match the value of <see cref="MaxBytes"/>.</summary>
    public const long DefaultMaxBytes = 4L * 1024 * 1024 * 1024;   // 4 GB

    /// <summary>OpenSSH's 2³¹ packet threshold (RFC 4253 §9 seqno limit). Match <see cref="MaxPackets"/>.</summary>
    public const long DefaultMaxPackets = int.MaxValue;            // 2^31 - 1

    /// <summary>OpenSSH's 1-hour time threshold. Match <see cref="MaxInterval"/>.</summary>
    public static readonly TimeSpan DefaultMaxInterval = TimeSpan.FromHours(1);
}
