namespace LibSsh2CS;

/// <summary>
/// libssh2 feature flags. Mirrors <c>LIBSSH2_VERSION_*)</c> constants used by
/// <c>libssh2_version()</c>. Used by <see cref="LibSsh2Version.Supports"/>.
/// </summary>
[Flags]
public enum SshFeature
{
    /// <summary>No features.</summary>
    None = 0,

    /// <summary>ZLIB compression ("zlib" / "zlib@openssh.com").</summary>
    Zlib = 1 << 0,

    /// <summary>Password authentication.</summary>
    AuthPassword = 1 << 1,

    /// <summary>Public key authentication (file).</summary>
    AuthPublicKey = 1 << 2,

    /// <summary>Keyboard-interactive authentication.</summary>
    AuthKeyboardInteractive = 1 << 3,

    /// <summary>Host-based authentication.</summary>
    AuthHostBased = 1 << 4,

    /// <summary>SSH agent authentication (Unix domain socket).</summary>
    AuthAgent = 1 << 5,

    /// <summary>Public key authentication (memory).</summary>
    AuthPublicKeyMemory = 1 << 6,

    /// <summary>Known hosts file management.</summary>
    KnownHosts = 1 << 7,

    /// <summary>Channel forwarding listener.</summary>
    ForwardListener = 1 << 8,

    /// <summary>Keepalive messages.</summary>
    KeepAlive = 1 << 9,
}
