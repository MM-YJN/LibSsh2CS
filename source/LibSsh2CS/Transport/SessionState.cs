namespace LibSsh2CS.Transport;

/// <summary>
/// Session state bitmask, a 1:1 port of libssh2's
/// <c>session-&gt;state</c> flag constants (<c>libssh2_priv.h:953</c>).
/// Stored as a bitfield on the session and updated by the transport/key-exchange
/// code (see <c>session.c:472</c>, <c>kex.c:800</c>, <c>session.c:952</c>,
/// <c>session.c:1248</c>).
/// </summary>
/// <remarks>
/// The numeric values are reproduced exactly from the C <c>#define</c>s so that
/// any bit test against the original constants matches. <see cref="None"/>
/// (zero) means "no transport state yet" — there is no corresponding C name.
/// </remarks>
[Flags]
internal enum SessionState
{
    /// <summary>No flags set (pre-handshake). No C equivalent; zero value.</summary>
    None = 0x0000_0000,

    /// <summary><c>LIBSSH2_STATE_INITIAL_KEX 0x00000001</c> — first key exchange in progress.</summary>
    InitialKex = 0x0000_0001,

    /// <summary><c>LIBSSH2_STATE_EXCHANGING_KEYS 0x00000002</c> — a (re)key is in progress.</summary>
    ExchangingKeys = 0x0000_0002,

    /// <summary><c>LIBSSH2_STATE_NEWKEYS 0x00000004</c> — NEWKEYS seen, transport encrypted.</summary>
    NewKeys = 0x0000_0004,

    /// <summary><c>LIBSSH2_STATE_AUTHENTICATED 0x00000008</c> — userauth succeeded.</summary>
    Authenticated = 0x0000_0008,

    /// <summary><c>LIBSSH2_STATE_KEX_ACTIVE 0x00000010</c> — kex state machine is mid-flight.</summary>
    KexActive = 0x0000_0010,
}
