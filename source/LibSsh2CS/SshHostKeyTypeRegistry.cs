namespace LibSsh2CS;

/// <summary>
/// Single source of truth for SSH host-key wire names ↔
/// <see cref="SshHostKeyType"/> / <see cref="SshKnownHostKeyType"/> mappings, and the
/// bidirectional conversions between the two enums.
/// </summary>
/// <remarks>
/// <para>
/// <b>Background.</b> The library carries two parallel enums for historical /
/// semantic reasons:
/// <list type="bullet">
/// <item><see cref="SshHostKeyType"/> enumerates algorithms the transport may
/// <em>negotiate</em> during key exchange (includes <see cref="SshHostKeyType.RsaSha256"/>
/// / <see cref="SshHostKeyType.RsaSha512"/>).</item>
/// <item><see cref="SshKnownHostKeyType"/> enumerates algorithms that may appear in
/// a <c>known_hosts</c> file (no <c>rsa-sha2-*</c>; stored RSA is always
/// <c>ssh-rsa</c> per RFC 8332 §3.1).</item>
/// </list>
/// The first eight numeric values of both enums are identical by design, so a
/// narrowing widening cast is well-defined for the shared subset. This registry
/// makes that relationship explicit and replaces the three previously
/// duplicated switch tables in <see cref="SshKnownHosts"/> (<c>MatchKeyTypeName</c>
/// + <c>ResolveKeyTypeName</c>), <c>HostKeyMethods</c> (<c>s_all</c> +
/// <c>Lookup</c>), and <c>HostKeyVerifier</c> (<c>SigWireName</c>).
/// </para>
/// <para>
/// <b>Order matters.</b> <see cref="NegotiableWireNamesInPreferenceOrder"/>
/// preserves the libssh2 preference order from <c>hostkey.c:1346</c>, which the
/// client sends in its KEXINIT. The registry table itself lists negotiable
/// algorithms first (in that same order), then the known-hosts-only entries
/// (<c>ssh-dss</c>, <c>rsa1</c>) which are parsed but never offered.
/// </para>
/// </remarks>
internal static class SshHostKeyTypeRegistry
{
    private sealed record Entry(string? WireName, SshHostKeyType Host, SshKnownHostKeyType? Known);

    // One row per in-scope host-key algorithm, plus the known-hosts-only entries
    // (ssh-dss, rsa1) kept so the registry is the single resolver for both enums.
    // Order: negotiable algorithms in libssh2 hostkey.c:1346 preference, then
    // known-hosts-only. Unknown (0) has no row; it is handled directly by the
    // conversion methods (numeric identity).
    private static readonly Entry[] s_entries =
    [
        new("ecdsa-sha2-nistp256", SshHostKeyType.Ecdsa256, SshKnownHostKeyType.Ecdsa256),
        new("ecdsa-sha2-nistp384", SshHostKeyType.Ecdsa384, SshKnownHostKeyType.Ecdsa384),
        new("ecdsa-sha2-nistp521", SshHostKeyType.Ecdsa521, SshKnownHostKeyType.Ecdsa521),
        new("ssh-ed25519",         SshHostKeyType.Ed25519,   SshKnownHostKeyType.Ed25519),
        new("rsa-sha2-512",        SshHostKeyType.RsaSha512, null),
        new("rsa-sha2-256",        SshHostKeyType.RsaSha256, null),
        new("ssh-rsa",             SshHostKeyType.SshRsa,    SshKnownHostKeyType.SshRsa),
        // Below: known-hosts-only — parsed but never offered for negotiation.
        new("ssh-dss",             SshHostKeyType.SshDss,    SshKnownHostKeyType.SshDss),
        new(null,                  SshHostKeyType.Rsa1,      SshKnownHostKeyType.Rsa1),
    ];

    /// <summary>
    /// The negotiable host-key wire names in libssh2 preference order
    /// (<c>hostkey.c:1346</c>), restricted to the supported algorithms.
    /// Excludes <c>ssh-dss</c> (deprecated),
    /// <c>rsa1</c> (SSH1), and <c>*-cert-v01@openssh.com</c> (deferred).
    /// </summary>
    public static IReadOnlyList<string> NegotiableWireNamesInPreferenceOrder { get; } = s_entries
        .Where(e => e.WireName is not null && e.Host is not SshHostKeyType.SshDss)
        .Select(e => e.WireName!)
        .ToArray();

    /// <summary>
    /// Returns the SSH wire name for an <see cref="SshHostKeyType"/>, or
    /// <c>null</c> for <see cref="SshHostKeyType.Unknown"/> and
    /// <see cref="SshHostKeyType.Rsa1"/> (which has no SSH2 wire name — SSH1 RSA
    /// stores its key as decimal text in <c>known_hosts</c>).
    /// </summary>
    public static string? WireNameFor(SshHostKeyType type)
    {
        foreach (Entry e in s_entries)
        {
            if (e.Host == type)
            {
                return e.WireName;
            }
        }

        return null;
    }

    /// <summary>
    /// Returns the SSH wire name for a <see cref="SshKnownHostKeyType"/>, or
    /// <c>null</c> for <see cref="SshKnownHostKeyType.Unknown"/> and
    /// <see cref="SshKnownHostKeyType.Rsa1"/>.
    /// </summary>
    public static string? WireNameFor(SshKnownHostKeyType type)
    {
        foreach (Entry e in s_entries)
        {
            if (e.Known == type)
            {
                return e.WireName;
            }
        }

        return null;
    }

    /// <summary>
    /// Looks up the registry entry for a wire name (exact match).
    /// Returns <c>null</c> for unrecognized names — callers preserve the
    /// original name string for round-tripping (parity with
    /// <see cref="SshKnownHosts"/>'s <see cref="SshKnownHostKeyType.Unknown"/> path).
    /// </summary>
    public static (SshHostKeyType Host, SshKnownHostKeyType? Known)? LookupByWireName(ReadOnlySpan<char> name)
    {
        foreach (Entry e in s_entries)
        {
            if (e.WireName is not null && name.SequenceEqual(e.WireName))
            {
                return (e.Host, e.Known);
            }
        }

        return null;
    }

    /// <summary>
    /// Narrows a negotiated <see cref="SshHostKeyType"/> to its
    /// <see cref="SshKnownHostKeyType"/> equivalent. The SHA-2 RSA variants
    /// (<see cref="SshHostKeyType.RsaSha256"/> / <see cref="SshHostKeyType.RsaSha512"/>)
    /// have no known-hosts equivalent — RFC 8332 §3.1 mandates stored RSA keys
    /// are always <c>ssh-rsa</c> regardless of signing variant.
    /// </summary>
    /// <param name="type">The negotiated host-key type to narrow.</param>
    /// <returns>The equivalent <see cref="SshKnownHostKeyType"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown for <see cref="SshHostKeyType.RsaSha256"/> /
    /// <see cref="SshHostKeyType.RsaSha512"/> (no on-disk representation) and
    /// <see cref="SshHostKeyType.Unknown"/>.
    /// </exception>
    public static SshKnownHostKeyType ToKnownHostKeyType(SshHostKeyType type)
    {
        if (TryAsKnownHostKeyType(type, out SshKnownHostKeyType known))
        {
            return known;
        }

        throw new ArgumentOutOfRangeException(
            nameof(type),
            $"{type} has no KnownHostKeyType equivalent (RSA-SHA2 variants use ssh-rsa on disk; Unknown is not storable).");
    }

    /// <summary>
    /// Attempts to narrow a negotiated <see cref="SshHostKeyType"/> to its
    /// <see cref="SshKnownHostKeyType"/> equivalent. Returns <c>false</c> for
    /// <see cref="SshHostKeyType.RsaSha256"/> / <see cref="SshHostKeyType.RsaSha512"/>
    /// (no on-disk representation) and <see cref="SshHostKeyType.Unknown"/>.
    /// On failure <paramref name="known"/> is set to
    /// <see cref="SshKnownHostKeyType.Unknown"/>.
    /// </summary>
    public static bool TryAsKnownHostKeyType(SshHostKeyType type, out SshKnownHostKeyType known)
    {
        foreach (Entry e in s_entries)
        {
            if (e.Host == type && e.Known is not null)
            {
                known = e.Known.Value;
                return true;
            }
        }

        known = SshKnownHostKeyType.Unknown;
        return false;
    }

    /// <summary>
    /// Widens a <see cref="SshKnownHostKeyType"/> to its <see cref="SshHostKeyType"/>
    /// equivalent. Every <see cref="SshKnownHostKeyType"/> value (including
    /// <see cref="SshKnownHostKeyType.Unknown"/>) has an <see cref="SshHostKeyType"/>
    /// counterpart — the negotiation enum is a strict superset by design, and
    /// <see cref="SshKnownHostKeyType.Unknown"/> / <see cref="SshHostKeyType.Unknown"/>
    /// share numeric value 0.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown for values outside the <see cref="SshKnownHostKeyType"/> enum range
    /// (only possible via invalid casts).
    /// </exception>
    public static SshHostKeyType ToHostKeyType(SshKnownHostKeyType type)
    {
        foreach (Entry e in s_entries)
        {
            if (e.Known == type)
            {
                return e.Host;
            }
        }

        // Unknown maps directly (numeric identity; both enums use 0).
        return type == SshKnownHostKeyType.Unknown
            ? SshHostKeyType.Unknown
            : throw new ArgumentOutOfRangeException(nameof(type), $"Unrecognized {nameof(SshKnownHostKeyType)} value: {type}.");
    }
}
