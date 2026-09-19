namespace LibSsh2CS.Transport;

/// <summary>
/// Static KEX algorithm registry — the managed subset of libssh2's
/// <c>libssh2_kex_methods[]</c> (<c>kex.c:3248</c>). Provides name lookup and
/// the default client preference order (most-preferred first), restricted to
/// the supported algorithms.
/// </summary>
/// <remarks>
/// The two pseudo-kex extensions <c>ext-info-c</c> and
/// <c>kex-strict-c-v00@openssh.com</c> are NOT registered here — they are
/// pseudo-methods with no <c>exchange_keys</c> implementation. They are
/// prepended to the client's kex name-list by <see cref="KeyExchange.BuildKexInit"/>
/// (matching <c>kex.c:4199</c>) and detected in the server's name-list by
/// <see cref="KeyExchange.Negotiate"/> (setting <see cref="NegotiatedMethods.StrictKex"/>).
/// </remarks>
internal static class KexMethods
{
    // Preference order mirrors libssh2_kex_methods[] (kex.c:3248), restricted to
    // the supported algorithms. The @libssh2.org alias
    // is rejected by OpenSSH 9.6+ so it is NOT
    // registered — only the standardized "curve25519-sha256" name is offered.
    private static readonly (string Name, KexAlgorithm Algo)[] s_all =
    [
        ("curve25519-sha256", KexAlgorithm.Curve25519Sha256),
        ("ecdh-sha2-nistp256", KexAlgorithm.EcdhSha2Nistp256),
        ("ecdh-sha2-nistp384", KexAlgorithm.EcdhSha2Nistp384),
        ("ecdh-sha2-nistp521", KexAlgorithm.EcdhSha2Nistp521),
        ("diffie-hellman-group14-sha256", KexAlgorithm.DhGroup14Sha256),
    ];

    /// <summary>The default client algorithm preference order (best first).</summary>
    public static IReadOnlyList<string> DefaultPreferences { get; } = s_all.Select(t => t.Name).ToArray();

    /// <summary>
    /// Looks up the <see cref="KexAlgorithm"/> for a negotiated name, or
    /// <see cref="KexAlgorithm.None"/> if the name is not a real KEX method
    /// (e.g. <c>ext-info-c</c> / <c>kex-strict-c-v00@openssh.com</c>).
    /// </summary>
    public static KexAlgorithm Lookup(string name)
    {
        foreach ((string n, KexAlgorithm a) in s_all)
        {
            if (n == name)
            {
                return a;
            }
        }

        return KexAlgorithm.None;
    }
}
