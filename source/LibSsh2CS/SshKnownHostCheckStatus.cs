namespace LibSsh2CS;

/// <summary>
/// Outcome of <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType, SshKnownHostFormat)"/>.
/// Mirrors <c>LIBSSH2_KNOWNHOST_CHECK_*</c> at <c>libssh2.h:1218-1221</c>.
/// Numeric values are the C constants verbatim so that callers asserting on
/// specific codes see identical values.
/// </summary>
public enum SshKnownHostCheckStatus
{
    /// <summary>
    /// Hostname matched and the supplied key matches the stored key. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_CHECK_MATCH = 0</c>. The matching entry is surfaced
    /// via <see cref="SshKnownHostCheckResult.Matched"/>.
    /// </summary>
    Match = 0,

    /// <summary>
    /// Hostname matched but the supplied key differs from the stored key, or
    /// the caller passed a SHA1-format input (which is unsupported — see
    /// <c>knownhost.c:367</c>). Mirrors
    /// <c>LIBSSH2_KNOWNHOST_CHECK_MISMATCH = 1</c>. The first-mismatched entry
    /// is surfaced via <see cref="SshKnownHostCheckResult.Matched"/> (parity with
    /// <c>knownhost.c:474-477</c>'s <c>badkey</c> tracking).
    /// </summary>
    Mismatch = 1,

    /// <summary>
    /// No entry matched the supplied hostname. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_CHECK_NOTFOUND = 2</c>.
    /// <see cref="SshKnownHostCheckResult.Matched"/> is <c>null</c>.
    /// </summary>
    NotFound = 2,

    /// <summary>
    /// A parsing/buffer error prevented the check from completing. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_CHECK_FAILURE = 3</c>. In practice this is rare —
    /// the C# port surfaces most such conditions as
    /// <see cref="SshException"/> instead.
    /// </summary>
    Failure = 3,
}
