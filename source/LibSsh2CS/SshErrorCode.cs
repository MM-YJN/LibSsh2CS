namespace LibSsh2CS;

/// <summary>
/// libssh2 error codes. Numeric values match <c>LIBSSH2_ERROR_*</c> constants in
/// <c>libssh2.h</c> exactly so that integration tests can assert on specific codes.
/// </summary>
/// <remarks>
/// <see cref="EAgain"/> is included for completeness but is internal-only in
/// async usage — the async SSH API awaits rather than returning EAGAIN to callers.
/// </remarks>
public enum SshErrorCode
{
    /// <summary>No error (LIBSSH2_ERROR_NONE = 0).</summary>
    None = 0,

    /// <summary>Generic session error (LIBSSH2_ERROR_SOCKET_NONE = -1).</summary>
    SocketNone = -1,

    /// <summary>Banner receive failed (LIBSSH2_ERROR_BANNER_RECV = -2).</summary>
    BannerRecv = -2,

    /// <summary>Banner send failed (LIBSSH2_ERROR_BANNER_SEND = -3).</summary>
    BannerSend = -3,

    /// <summary>Invalid MAC on incoming packet (LIBSSH2_ERROR_INVALID_MAC = -4).</summary>
    InvalidMac = -4,

    /// <summary>Key exchange failed (LIBSSH2_ERROR_KEX_FAILURE = -5).</summary>
    KexFailure = -5,

    /// <summary>Allocation failed (LIBSSH2_ERROR_ALLOC = -6).</summary>
    Alloc = -6,

    /// <summary>Socket send failed (LIBSSH2_ERROR_SOCKET_SEND = -7).</summary>
    SocketSend = -7,

    /// <summary>Key exchange failure (LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8).</summary>
    KeyExchangeFailure = -8,

    /// <summary>Timeout (LIBSSH2_ERROR_TIMEOUT = -9).</summary>
    Timeout = -9,

    /// <summary>Hostkey init failed (LIBSSH2_ERROR_HOSTKEY_INIT = -10).</summary>
    HostkeyInit = -10,

    /// <summary>Hostkey sign failed (LIBSSH2_ERROR_HOSTKEY_SIGN = -11).</summary>
    HostkeySign = -11,

    /// <summary>Decryption failed (LIBSSH2_ERROR_DECRYPT = -12).</summary>
    Decrypt = -12,

    /// <summary>Socket disconnected (LIBSSH2_ERROR_SOCKET_DISCONNECT = -13).</summary>
    SocketDisconnect = -13,

    /// <summary>Protocol error (LIBSSH2_ERROR_PROTO = -14).</summary>
    Proto = -14,

    /// <summary>Password expired (LIBSSH2_ERROR_PASSWORD_EXPIRED = -15).
    /// Triggers credential re-prompt loop in libgit2.</summary>
    PasswordExpired = -15,

    /// <summary>File error (LIBSSH2_ERROR_FILE = -16).</summary>
    File = -16,

    /// <summary>No matching method (LIBSSH2_ERROR_METHOD_NONE = -17).</summary>
    MethodNone = -17,

    /// <summary>Authentication failed (LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18).
    /// Triggers credential re-prompt loop in libgit2.</summary>
    AuthenticationFailed = -18,

    /// <summary>Public key unverified (LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19).
    /// Triggers credential re-prompt loop in libgit2.</summary>
    PublicKeyUnverified = -19,

    /// <summary>Channel out of order (LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20).</summary>
    ChannelOutOfOrder = -20,

    /// <summary>Channel failure (LIBSSH2_ERROR_CHANNEL_FAILURE = -21).</summary>
    ChannelFailure = -21,

    /// <summary>Channel request denied (LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22).</summary>
    ChannelRequestDenied = -22,

    /// <summary>Channel unknown (LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23).</summary>
    ChannelUnknown = -23,

    /// <summary>Channel window exceeded (LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24).</summary>
    ChannelWindowExceeded = -24,

    /// <summary>Channel packet exceeded (LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25).</summary>
    ChannelPacketExceeded = -25,

    /// <summary>Channel closed (LIBSSH2_ERROR_CHANNEL_CLOSED = -26).</summary>
    ChannelClosed = -26,

    /// <summary>Channel EOF sent (LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27).</summary>
    ChannelEofSent = -27,

    /// <summary>SCP protocol error (LIBSSH2_ERROR_SCP_PROTOCOL = -28).</summary>
    ScpProtocol = -28,

    /// <summary>ZLIB error (LIBSSH2_ERROR_ZLIB = -29).</summary>
    Zlib = -29,

    /// <summary>Socket timeout (LIBSSH2_ERROR_SOCKET_TIMEOUT = -30).</summary>
    SocketTimeout = -30,

    /// <summary>SFTP protocol error (LIBSSH2_ERROR_SFTP_PROTOCOL = -31).</summary>
    SftpProtocol = -31,

    /// <summary>Request denied (LIBSSH2_ERROR_REQUEST_DENIED = -32).</summary>
    RequestDenied = -32,

    /// <summary>Method not supported (LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33).</summary>
    MethodNotSupported = -33,

    /// <summary>Invalid argument (LIBSSH2_ERROR_INVAL = -34).</summary>
    Inval = -34,

    /// <summary>Invalid poll type (LIBSSH2_ERROR_INVALID_POLL_TYPE = -35).</summary>
    InvalidPollType = -35,

    /// <summary>Public key protocol error (LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36).</summary>
    PublicKeyProtocol = -36,

    /// <summary>Operation would block in non-blocking mode (LIBSSH2_ERROR_EAGAIN = -37).
    /// Internal only in async usage — async methods await rather than returning this.</summary>
    EAgain = -37,

    /// <summary>Buffer too small (LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38).</summary>
    BufferTooSmall = -38,

    /// <summary>Bad use of API (LIBSSH2_ERROR_BAD_USE = -39).</summary>
    BadUse = -39,

    /// <summary>Compression failed (LIBSSH2_ERROR_COMPRESS = -40).</summary>
    Compress = -40,

    /// <summary>Out of boundary (LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41).</summary>
    OutOfBoundary = -41,

    /// <summary>Agent protocol error (LIBSSH2_ERROR_AGENT_PROTOCOL = -42).</summary>
    AgentProtocol = -42,

    /// <summary>Socket receive failed (LIBSSH2_ERROR_SOCKET_RECV = -43).</summary>
    SocketRecv = -43,

    /// <summary>Encryption failed (LIBSSH2_ERROR_ENCRYPT = -44).</summary>
    Encrypt = -44,

    /// <summary>Bad socket (LIBSSH2_ERROR_BAD_SOCKET = -45).</summary>
    BadSocket = -45,

    /// <summary>Known hosts error (LIBSSH2_ERROR_KNOWN_HOSTS = -46).</summary>
    KnownHosts = -46,

    /// <summary>Channel window full (LIBSSH2_ERROR_CHANNEL_WINDOW_FULL = -47).</summary>
    ChannelWindowFull = -47,

    /// <summary>Keyfile authentication failed (LIBSSH2_ERROR_KEYFILE_AUTH_FAILED = -48).</summary>
    KeyfileAuthFailed = -48,

    /// <summary>Random number generation failed (LIBSSH2_ERROR_RANDGEN = -49).</summary>
    Randgen = -49,

    /// <summary>Missing userauth banner (LIBSSH2_ERROR_MISSING_USERAUTH_BANNER = -50).</summary>
    MissingUserauthBanner = -50,

    /// <summary>Algorithm unsupported (LIBSSH2_ERROR_ALGO_UNSUPPORTED = -51).</summary>
    AlgoUnsupported = -51,

    /// <summary>MAC failure (LIBSSH2_ERROR_MAC_FAILURE = -52).</summary>
    MacFailure = -52,

    /// <summary>Hash init failed (LIBSSH2_ERROR_HASH_INIT = -53).</summary>
    HashInit = -53,

    /// <summary>Hash calculation failed (LIBSSH2_ERROR_HASH_CALC = -54).</summary>
    HashCalc = -54,
}
