namespace LibSsh2CS;

/// <summary>
/// SSH algorithm negotiation categories. Mirrors <c>LIBSSH2_METHOD_*</c>
/// constants in <c>libssh2.h</c>. Used by the session indexer to get/set
/// comma-separated algorithm name lists per category.
/// </summary>
/// <remarks>
/// Values are used as indices into internal storage; do not renumber.
/// </remarks>
public enum SshMethodType
{
    /// <summary>Key exchange algorithms (<c>LIBSSH2_METHOD_KEX = 0</c>).</summary>
    Kex = 0,

    /// <summary>Server host key algorithms (<c>LIBSSH2_METHOD_HOSTKEY = 1</c>).</summary>
    HostKey = 1,

    /// <summary>Client-to-server cipher (<c>LIBSSH2_METHOD_CRYPT_CS = 2</c>).</summary>
    CryptCs = 2,

    /// <summary>Server-to-client cipher (<c>LIBSSH2_METHOD_CRYPT_SC = 3</c>).</summary>
    CryptSc = 3,

    /// <summary>Client-to-server MAC (<c>LIBSSH2_METHOD_MAC_CS = 4</c>).</summary>
    MacCs = 4,

    /// <summary>Server-to-client MAC (<c>LIBSSH2_METHOD_MAC_SC = 5</c>).</summary>
    MacSc = 5,

    /// <summary>Client-to-server compression (<c>LIBSSH2_METHOD_COMP_CS = 6</c>).</summary>
    CompCs = 6,

    /// <summary>Server-to-client compression (<c>LIBSSH2_METHOD_COMP_SC = 7</c>).</summary>
    CompSc = 7,

    /// <summary>Client-to-server language (<c>LIBSSH2_METHOD_LANG_CS = 8</c>).</summary>
    LangCs = 8,

    /// <summary>Server-to-client language (<c>LIBSSH2_METHOD_LANG_SC = 9</c>).</summary>
    LangSc = 9,

    /// <summary>Signature algorithms (<c>LIBSSH2_METHOD_SIGN_ALGO = 10</c>, libssh2 1.11+).</summary>
    SignAlgo = 10,
}
