namespace LibSsh2CS;

/// <summary>
/// Immutable comma-separated algorithm preference list per <see cref="SshMethodType"/>.
/// Held inside <c>SshSession</c>; set before handshake to override the default
/// preference order. Matches <c>libssh2_session_method_pref</c> semantics.
/// </summary>
public sealed class MethodPreferences
{
    private readonly string[] _values;

    /// <summary>
    /// Creates a new instance with all categories initialized to empty strings.
    /// </summary>
    public MethodPreferences()
    {
        _values = new string[11];
        for (int i = 0; i < _values.Length; i++)
        {
            _values[i] = string.Empty;
        }
    }

    /// <summary>
    /// Copies another instance's preferences. Used by the KEXINIT build path
    /// to filter a category (e.g. the Compress-flag "none" filter) without
    /// mutating the session's own preferences.
    /// </summary>
    internal MethodPreferences(MethodPreferences other)
    {
        ArgumentNullException.ThrowIfNull(other);
        _values = (string[])other._values.Clone();
    }

    /// <summary>
    /// Gets or sets the comma-separated algorithm name list for the given
    /// category. Returns <see cref="string.Empty"/> if unset.
    /// </summary>
    /// <param name="type">The category to read/write.</param>
    /// <returns>The current comma-separated preference list, or empty.</returns>
    public string this[SshMethodType type]
    {
        get => _values[(int)type];
        set => _values[(int)type] = value ?? string.Empty;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the given category has a non-empty
    /// preference list set.
    /// </summary>
    public bool IsSet(SshMethodType type)
        => !string.IsNullOrEmpty(_values[(int)type]);

    /// <summary>
    /// Resets all categories to empty (the default before user customization).
    /// </summary>
    public void Clear()
    {
        for (int i = 0; i < _values.Length; i++)
        {
            _values[i] = string.Empty;
        }
    }
}
