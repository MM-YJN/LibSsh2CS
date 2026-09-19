namespace LibSsh2CS;

/// <summary>
/// Static version + feature surface mirroring <c>libssh2_version()</c>.
/// Replaces the C <c>version.c</c>.
/// </summary>
public static class LibSsh2Version
{
    /// <summary>
    /// The LibSsh2CS version string. Tracks the upstream libssh2 version that
    /// this port was last verified against.
    /// </summary>
    public const string Version = "1.11.1_DEV-LibSsh2CS";

    /// <summary>
    /// Returns <see langword="true"/> if the given feature flag is compiled in.
    /// Equivalent to <c>libssh2_version(flag) != NULL</c>.
    /// </summary>
    /// <param name="feature">A single <see cref="SshFeature"/> flag to query.</param>
    /// <returns><see langword="true"/> if supported.</returns>
    public static bool Supports(SshFeature feature)
    {
        // All supported features are compiled in.
        // Future scope reductions (e.g. building without agent) would gate here.
        SshFeature supported =
            SshFeature.Zlib |
            SshFeature.AuthPassword |
            SshFeature.AuthPublicKey |
            SshFeature.AuthKeyboardInteractive |
            SshFeature.AuthHostBased |
            SshFeature.AuthAgent |
            SshFeature.AuthPublicKeyMemory |
            SshFeature.KnownHosts |
            SshFeature.ForwardListener |
            SshFeature.KeepAlive;
        return (supported & feature) == feature;
    }
}
