namespace LibSsh2CS.Transport;

/// <summary>
/// Static host-key algorithm registry — the managed subset of libssh2's
/// <c>hostkey_methods[]</c> (<c>hostkey.c:1346</c>). Delegates to
/// <see cref="SshHostKeyTypeRegistry"/> for the wire-name ↔ enum mapping and the
/// default preference order, restricted to the supported algorithms
/// (no <c>*-cert-v01@openssh.com</c> variants,
/// no deprecated <c>ssh-dss</c>).
/// </summary>
internal static class HostKeyMethods
{
    /// <summary>
    /// The default client algorithm preference order (best first). Mirrors
    /// libssh2's <c>hostkey_methods[]</c> (<c>hostkey.c:1346</c>), restricted
    /// to the in-scope subset. Delegates to
    /// <see cref="SshHostKeyTypeRegistry.NegotiableWireNamesInPreferenceOrder"/>.
    /// </summary>
    public static IReadOnlyList<string> DefaultPreferences
        => SshHostKeyTypeRegistry.NegotiableWireNamesInPreferenceOrder;

    /// <summary>
    /// Looks up the <see cref="SshHostKeyType"/> for a negotiated name, or
    /// <see cref="SshHostKeyType.Unknown"/> if the name is not recognized.
    /// Delegates to <see cref="SshHostKeyTypeRegistry.LookupByWireName"/>.
    /// </summary>
    public static SshHostKeyType Lookup(string name)
        => SshHostKeyTypeRegistry.LookupByWireName(name)?.Host
            ?? SshHostKeyType.Unknown;
}
