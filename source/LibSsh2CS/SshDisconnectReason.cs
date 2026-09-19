namespace LibSsh2CS;

/// <summary>
/// SSH disconnect reason codes the client sends in <c>SSH_MSG_DISCONNECT</c>
/// (RFC 4253 §11.1). Mirrors the subset of <c>SSH_DISCONNECT_*</c> values that
/// <c>session_disconnect</c> (<c>session.c:1189-1238</c>) actually sends on the
/// wire. Server-sent reason codes are surfaced in <see cref="SshException"/>
/// messages (see <c>PacketQueue.ParseDisconnectDescription</c>); they are not
/// members of this enum.
/// </summary>
/// <remarks>
/// Numeric values are the RFC 4253 §11.1 reason codes verbatim.
/// </remarks>
public enum SshDisconnectReason
{
    /// <summary>
    /// RFC 4253 §11.1: "An error occurred that is not covered by any other
    /// disconnect reason code." Value 1.
    /// </summary>
    HostNotAllowedToConnect = 1,

    /// <summary>
    /// RFC 4253 §11.1: "A protocol error occurred." Value 2.
    /// </summary>
    ProtocolError = 2,

    /// <summary>
    /// RFC 4253 §11.1: "A key exchange failed." Value 3.
    /// </summary>
    KeyExchangeFailed = 3,

    /// <summary>
    /// RFC 4253 §11.1: "The requested service is not available." Value 7.
    /// </summary>
    ServiceNotAvailable = 7,

    /// <summary>
    /// RFC 4253 §11.1, SSH-2.0-OpenSSH extension: "The server's host key could
    /// not be verified." Value 9.
    /// </summary>
    HostKeyNotVerifiable = 9,

    /// <summary>
    /// RFC 4253 §11.1: "The connection is being closed at the application's
    /// request." Value 11. The default reason for <c>SshSession.DisposeAsync</c>.
    /// </summary>
    ByApplication = 11,

    /// <summary>
    /// RFC 4253 §11.1: "Too many connections." Value 12. (Previously
    /// mislabeled <c>ServiceNotAvailableAfterAuth</c> with a wrong description
    /// — that is not an RFC 4253 reason code.)
    /// </summary>
    TooManyConnections = 12,

    /// <summary>
    /// RFC 4253 §11.1: "The user cancelled the authentication." Value 13.
    /// </summary>
    AuthCancelledByUser = 13,

    /// <summary>
    /// RFC 4253 §11.1: "No more authentication methods are available." Value 14.
    /// </summary>
    NoMoreAuthMethodsAvailable = 14,
}
