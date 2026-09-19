namespace LibSsh2CS;

/// <summary>
/// Result of a <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType, SshKnownHostFormat)"/>
/// call. Combines the libssh2 <c>int</c> return code with the matched/mismatched
/// <see cref="SshKnownHostEntry"/> reference that the C API surfaces via an
/// out-parameter (<c>struct libssh2_knownhost **ext</c>).
/// </summary>
/// <param name="Status">
/// The check outcome. When <see cref="SshKnownHostCheckStatus.Match"/>,
/// <paramref name="Matched"/> is the matching entry. When
/// <see cref="SshKnownHostCheckStatus.Mismatch"/>, <paramref name="Matched"/> is
/// the first entry that matched the hostname but not the key (C's
/// <c>badkey</c>). When <see cref="SshKnownHostCheckStatus.NotFound"/> or
/// <see cref="SshKnownHostCheckStatus.Failure"/>, <paramref name="Matched"/> is
/// <c>null</c>.
/// </param>
/// <param name="Matched">
/// The relevant entry, or <c>null</c>. See <paramref name="Status"/>.
/// </param>
public sealed record SshKnownHostCheckResult(
    SshKnownHostCheckStatus Status,
    SshKnownHostEntry? Matched);
