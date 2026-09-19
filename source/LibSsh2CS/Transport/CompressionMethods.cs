namespace LibSsh2CS.Transport;

/// <summary>
/// Static compression registry — the managed <c>comp_methods[]</c>
/// (<c>comp.c:359</c>). In scope: <c>zlib</c>, <c>zlib@openssh.com</c>, <c>none</c>.
/// </summary>
internal static class CompressionMethods
{
    // Preference order mirrors comp_methods[] (comp.c:359).
    private static readonly (string Name, Func<ICompression> Factory)[] s_all =
    [
        ("zlib", static () => new ZlibCompression("zlib", useInAuth: true)),
        ("zlib@openssh.com", static () => new ZlibCompression("zlib@openssh.com", useInAuth: false)),
        ("none", static () => new NoneCompression()),
    ];

    /// <summary>The default client algorithm preference order (best first).</summary>
    public static IReadOnlyList<string> DefaultPreferences { get; } = s_all.Select(t => t.Name).ToArray();

    /// <summary>
    /// Creates a fresh compression instance for the negotiated name, or <c>null</c>
    /// if the name is not recognised.
    /// </summary>
    public static ICompression? Create(string name)
    {
        foreach ((string n, Func<ICompression> f) in s_all)
        {
            if (n == name)
            {
                return f();
            }
        }

        return null;
    }
}
