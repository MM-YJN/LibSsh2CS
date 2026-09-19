using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// Static MAC registry — the managed <c>mac_methods[]</c> (<c>mac.c:455</c>),
/// restricted to the in-scope algorithm subset (HMAC-SHA1/256/512 + their ETM
/// variants). MD5, SHA1-96 and RIPEMD160 are out of scope.
/// </summary>
internal static class MacMethods
{
    // Preference order mirrors mac_methods[] (mac.c:455), restricted to scope.
    private static readonly (string Name, Func<IMac> Factory)[] s_all =
    [
        ("hmac-sha2-256", static () => new HmacMac("hmac-sha2-256", HashAlgorithmName.SHA256, macLen: 32, isEtm: false)),
        ("hmac-sha2-256-etm@openssh.com", static () => new HmacMac("hmac-sha2-256-etm@openssh.com", HashAlgorithmName.SHA256, macLen: 32, isEtm: true)),
        ("hmac-sha2-512", static () => new HmacMac("hmac-sha2-512", HashAlgorithmName.SHA512, macLen: 64, isEtm: false)),
        ("hmac-sha2-512-etm@openssh.com", static () => new HmacMac("hmac-sha2-512-etm@openssh.com", HashAlgorithmName.SHA512, macLen: 64, isEtm: true)),
        ("hmac-sha1", static () => new HmacMac("hmac-sha1", HashAlgorithmName.SHA1, macLen: 20, isEtm: false)),
        ("hmac-sha1-etm@openssh.com", static () => new HmacMac("hmac-sha1-etm@openssh.com", HashAlgorithmName.SHA1, macLen: 20, isEtm: true)),
    ];

    /// <summary>The default client algorithm preference order (best first).</summary>
    public static IReadOnlyList<string> DefaultPreferences { get; } = s_all.Select(t => t.Name).ToArray();

    /// <summary>
    /// Creates a fresh MAC instance for the negotiated name, or <c>null</c> if the
    /// name is not in the in-scope set.
    /// </summary>
    public static IMac? Create(string name)
    {
        foreach ((string n, Func<IMac> f) in s_all)
        {
            if (n == name)
            {
                return f();
            }
        }

        return null;
    }

    /// <summary>
    /// The integrated-MAC no-op override (<c>mac_method_hmac_aesgcm</c>,
    /// <c>mac.c:529</c>): used when an AEAD cipher (AES-GCM, ChaCha20-Poly1305) is
    /// negotiated, since those carry their own authentication tag.
    /// </summary>
    public static IMac Noop => new NoopMac();
}
