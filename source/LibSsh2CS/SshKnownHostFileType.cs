namespace LibSsh2CS;

/// <summary>
/// Known-hosts file format. Mirrors <c>LIBSSH2_KNOWNHOST_FILE_*</c> at
/// <c>libssh2.h:1281</c>. Only OpenSSH format is supported by libssh2 1.11;
/// the enum is preserved verbatim for parity with the C API.
/// </summary>
public enum SshKnownHostFileType
{
    /// <summary>
    /// OpenSSH <c>known_hosts</c> format. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_FILE_OPENSSH = 1</c>. Format:
    /// <c>&lt;host&gt; &lt;key-type-name&gt; &lt;base64-key&gt; [comment]</c>
    /// or <c>|1|&lt;salt&gt;|&lt;hash&gt; &lt;...&gt;</c> for hashed hosts.
    /// </summary>
    OpenSsh = 1,
}
