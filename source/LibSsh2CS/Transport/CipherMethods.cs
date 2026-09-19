namespace LibSsh2CS.Transport;

/// <summary>
/// Static cipher registry — the managed <c>_libssh2_crypt_methods[]</c>
/// (<c>crypt.c:508</c>). Provides name lookup and the default client preference
/// order (most-preferred first), restricted to the in-scope algorithm subset.
/// </summary>
internal static class CipherMethods
{
    // Preference order mirrors _libssh2_crypt_methods[] (crypt.c:508), restricted
    // to the supported algorithms. Note the position of
    // rijndael-cbc@lysator.liu.se (wire-equivalent to aes256-cbc): the C places
    // it between aes256-cbc and aes192-cbc (crypt.c:519-523), and the port now
    // mirrors that — previously it was listed last, so client-pref-first
    // negotiation could pick aes192/aes128-cbc where the C picks AES-256.
    private static readonly (string Name, Func<ICipher> Factory)[] s_all =
    [
        ("chacha20-poly1305@openssh.com", static () => new ChaChaPolyCipher()),
        ("aes256-gcm@openssh.com", static () => new AesGcmCipher(32)),
        ("aes128-gcm@openssh.com", static () => new AesGcmCipher(16)),
        ("aes256-ctr", static () => new AesCtrCipher(32)),
        ("aes192-ctr", static () => new AesCtrCipher(24)),
        ("aes128-ctr", static () => new AesCtrCipher(16)),
        ("aes256-cbc", static () => new AesCbcCipher(32)),
        // rijndael-cbc@lysator.liu.se is wire-equivalent to aes256-cbc.
        ("rijndael-cbc@lysator.liu.se", static () => new AesCbcCipher(32)),
        ("aes192-cbc", static () => new AesCbcCipher(24)),
        ("aes128-cbc", static () => new AesCbcCipher(16)),
    ];

    /// <summary>The default client algorithm preference order (best first).</summary>
    public static IReadOnlyList<string> DefaultPreferences { get; } = s_all.Select(t => t.Name).ToArray();

    /// <summary>
    /// Creates a fresh cipher instance for the negotiated name, or <c>null</c> if
    /// the name is not in the in-scope set.
    /// </summary>
    public static ICipher? Create(string name)
    {
        foreach ((string n, Func<ICipher> f) in s_all)
        {
            if (n == name)
            {
                return f();
            }
        }

        return null;
    }

    /// <summary>
    /// True for AEAD ciphers (AES-GCM, ChaCha20-Poly1305) — the ones that
    /// integrate their own MAC and require the full-packet <see cref="ICipher.CryptAead"/>
    /// path instead of <see cref="ICipher.Crypt"/> + a separate MAC.
    /// </summary>
    public static bool IsAead(ICipher cipher)
        => (cipher.Flags & (CipherFlags.IntegratedMac | CipherFlags.RequiresFullPacket)) != 0;
}
