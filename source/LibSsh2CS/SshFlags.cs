using System.IO.Pipelines;

namespace LibSsh2CS;

/// <summary>
/// Session-level behavioral flags. Mirrors <c>LIBSSH2_FLAG_*</c> constants in
/// <c>libssh2.h:420-422</c> and the per-session flag storage at
/// <c>libssh2_priv.h:663-667</c>. Set before handshake via
/// <see cref="SshSession.SetFlag"/>.
/// </summary>
/// <remarks>
/// <b>Value layout is a bitmask, not the C ordinals.</b> The C constants are
/// distinct ordinals (<c>SIGPIPE=1, COMPRESS=2, QUOTE_PATHS=3</c> — not a
/// bitmask, since C stores three independent booleans). This managed enum uses
/// powers of two (<c>1,2,4</c>) so the <see cref="FlagsAttribute"/> semantics
/// hold; <see cref="QuotePaths"/> is <c>4</c>, not the C's <c>3</c>. Do not
/// assert C numeric values on this enum.
/// </remarks>
[Flags]
public enum SshFlag
{
    /// <summary>No flags set.</summary>
    None = 0,

    /// <summary>
    /// <c>LIBSSH2_FLAG_SIGPIPE = 1</c>. Controls whether <c>MSG_NOSIGNAL</c> is
    /// set on socket send/recv to suppress SIGPIPE. On platforms without
    /// <c>MSG_NOSIGNAL</c> this is a no-op. The managed port uses BCL sockets
    /// via <c>IDuplexPipe</c> and never raises SIGPIPE, so this flag is accepted
    /// for API parity but has no behavioral effect.
    /// </summary>
    Sigpipe = 1 << 0,

    /// <summary>
    /// <c>LIBSSH2_FLAG_COMPRESS = 2</c>. Enables negotiation of <c>zlib</c> /
    /// <c>zlib@openssh.com</c> compression during KEXINIT. When false (the
    /// default), the client's compression name-list is filtered to <c>none</c>
    /// only. <see cref="SshSession.HandshakeAsync(IDuplexPipe, HostKeyVerificationCallback, CancellationToken)"/> consults this flag when
    /// building the KEXINIT.
    /// </summary>
    Compress = 1 << 1,

    /// <summary>
    /// <c>LIBSSH2_FLAG_QUOTE_PATHS</c> (C ordinal 3). Affects SCP path quoting
    /// only (default: true, <c>session.c:475</c>). Irrelevant for SSH transport
    /// and userauth; stored for parity and future SCP support. Value <c>4</c> in
    /// this enum (bitmask layout — see type remarks).
    /// </summary>
    QuotePaths = 1 << 2,
}
