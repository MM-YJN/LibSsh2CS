namespace LibSsh2CS.UnitTests;

/// <summary>
/// Tests for <see cref="SshHostKeyTypeRegistry"/> — the single source of truth for
/// SSH host-key wire names ↔ <see cref="SshHostKeyType"/> / <see cref="SshKnownHostKeyType"/>
/// mappings. Verifies the registry round-trips correctly for every in-scope
/// algorithm and that the narrowing/widening conversions between the two enums
/// behave as documented (RSA-SHA2 variants have no known-hosts equivalent).
/// </summary>
/// <remarks>
/// The registry replaces the previously duplicated switch tables in
/// <see cref="SshKnownHosts"/>, <c>HostKeyMethods</c>, and <c>HostKeyVerifier</c>;
/// these tests pin the behavior those call sites relied on.
/// </remarks>
public class HostKeyTypeRegistryTests
{
    // ── NegotiableWireNamesInPreferenceOrder ─────────────────────────

    /// <summary>
    /// The negotiable preference list must match libssh2's
    /// <c>hostkey_methods[]</c> (<c>hostkey.c:1346</c>) restricted to the
    /// in-scope subset: ECDSA in curve-size order, Ed25519, then RSA
    /// (SHA-512 first, SHA-256 next, SHA-1 last). Parity-pinned because
    /// <see cref="LibSsh2CS.Transport.HostKeyMethods.DefaultPreferences"/>
    /// feeds this verbatim into the client KEXINIT.
    /// </summary>
    [Fact]
    public void NegotiableWireNames_MatchesLibssh2PreferenceOrder()
    {
        IReadOnlyList<string> names = SshHostKeyTypeRegistry.NegotiableWireNamesInPreferenceOrder;

        Assert.Equal(
            new[] { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                    "ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" },
            names);
    }

    /// <summary>
    /// <c>ssh-dss</c> is excluded from negotiation (deprecated) but is
    /// still in the registry for parsing known_hosts files that contain DSS
    /// entries (parity with <c>LIBSSH2_DSA</c>).
    /// </summary>
    [Fact]
    public void NegotiableWireNames_ExcludesSshDss()
        => Assert.DoesNotContain("ssh-dss", SshHostKeyTypeRegistry.NegotiableWireNamesInPreferenceOrder);

    /// <summary>
    /// SSH1 RSA1 has no SSH2 wire name and is excluded from negotiation.
    /// </summary>
    [Fact]
    public void NegotiableWireNames_ExcludesRsa1()
        => Assert.DoesNotContain(null, SshHostKeyTypeRegistry.NegotiableWireNamesInPreferenceOrder);

    // ── WireNameFor(HostKeyType) ─────────────────────────────────────

    [Theory]
    [InlineData(SshHostKeyType.SshRsa, "ssh-rsa")]
    [InlineData(SshHostKeyType.RsaSha256, "rsa-sha2-256")]
    [InlineData(SshHostKeyType.RsaSha512, "rsa-sha2-512")]
    [InlineData(SshHostKeyType.Ecdsa256, "ecdsa-sha2-nistp256")]
    [InlineData(SshHostKeyType.Ecdsa384, "ecdsa-sha2-nistp384")]
    [InlineData(SshHostKeyType.Ecdsa521, "ecdsa-sha2-nistp521")]
    [InlineData(SshHostKeyType.Ed25519, "ssh-ed25519")]
    [InlineData(SshHostKeyType.SshDss, "ssh-dss")]
    public void WireNameForHostKeyType_ReturnsExpectedName(SshHostKeyType type, string expected)
        => Assert.Equal(expected, SshHostKeyTypeRegistry.WireNameFor(type));

    [Theory]
    [InlineData(SshHostKeyType.Unknown, null)]
    [InlineData(SshHostKeyType.Rsa1, null)]
    public void WireNameForHostKeyType_ReturnsNullForUnnamedTypes(SshHostKeyType type, string? expected)
        => Assert.Equal(expected, SshHostKeyTypeRegistry.WireNameFor(type));

    // ── WireNameFor(KnownHostKeyType) ────────────────────────────────

    [Theory]
    [InlineData(SshKnownHostKeyType.SshRsa, "ssh-rsa")]
    [InlineData(SshKnownHostKeyType.SshDss, "ssh-dss")]
    [InlineData(SshKnownHostKeyType.Ecdsa256, "ecdsa-sha2-nistp256")]
    [InlineData(SshKnownHostKeyType.Ecdsa384, "ecdsa-sha2-nistp384")]
    [InlineData(SshKnownHostKeyType.Ecdsa521, "ecdsa-sha2-nistp521")]
    [InlineData(SshKnownHostKeyType.Ed25519, "ssh-ed25519")]
    public void WireNameForKnownHostKeyType_ReturnsExpectedName(SshKnownHostKeyType type, string expected)
        => Assert.Equal(expected, SshHostKeyTypeRegistry.WireNameFor(type));

    [Theory]
    [InlineData(SshKnownHostKeyType.Unknown, null)]
    [InlineData(SshKnownHostKeyType.Rsa1, null)]
    public void WireNameForKnownHostKeyType_ReturnsNullForUnnamedTypes(SshKnownHostKeyType type, string? expected)
        => Assert.Equal(expected, SshHostKeyTypeRegistry.WireNameFor(type));

    // ── LookupByWireName ─────────────────────────────────────────────

    [Theory]
    [InlineData("ssh-rsa", SshHostKeyType.SshRsa, SshKnownHostKeyType.SshRsa)]
    [InlineData("rsa-sha2-256", SshHostKeyType.RsaSha256, null)]
    [InlineData("rsa-sha2-512", SshHostKeyType.RsaSha512, null)]
    [InlineData("ecdsa-sha2-nistp256", SshHostKeyType.Ecdsa256, SshKnownHostKeyType.Ecdsa256)]
    [InlineData("ecdsa-sha2-nistp384", SshHostKeyType.Ecdsa384, SshKnownHostKeyType.Ecdsa384)]
    [InlineData("ecdsa-sha2-nistp521", SshHostKeyType.Ecdsa521, SshKnownHostKeyType.Ecdsa521)]
    [InlineData("ssh-ed25519", SshHostKeyType.Ed25519, SshKnownHostKeyType.Ed25519)]
    [InlineData("ssh-dss", SshHostKeyType.SshDss, SshKnownHostKeyType.SshDss)]
    public void LookupByWireName_ReturnsEntryForKnownNames(
        string name, SshHostKeyType expectedHost, SshKnownHostKeyType? expectedKnown)
    {
        (SshHostKeyType Host, SshKnownHostKeyType? Known)? entry = SshHostKeyTypeRegistry.LookupByWireName(name);

        Assert.NotNull(entry);
        Assert.Equal(expectedHost, entry!.Value.Host);
        Assert.Equal(expectedKnown, entry.Value.Known);
    }

    [Theory]
    [InlineData("ssh-foo")]
    [InlineData("")]
    [InlineData("rsa-sha2-1024")]   // plausible-but-unsupported SHA-2 variant
    [InlineData("x509v3-ssh-rsa")] // deferred cert-signing variant
    public void LookupByWireName_ReturnsNullForUnknownNames(string name)
        => Assert.Null(SshHostKeyTypeRegistry.LookupByWireName(name));

    // ── ToKnownHostKeyType / TryAsKnownHostKeyType ───────────────────

    [Theory]
    [InlineData(SshHostKeyType.SshRsa, SshKnownHostKeyType.SshRsa)]
    [InlineData(SshHostKeyType.SshDss, SshKnownHostKeyType.SshDss)]
    [InlineData(SshHostKeyType.Ecdsa256, SshKnownHostKeyType.Ecdsa256)]
    [InlineData(SshHostKeyType.Ecdsa384, SshKnownHostKeyType.Ecdsa384)]
    [InlineData(SshHostKeyType.Ecdsa521, SshKnownHostKeyType.Ecdsa521)]
    [InlineData(SshHostKeyType.Ed25519, SshKnownHostKeyType.Ed25519)]
    [InlineData(SshHostKeyType.Rsa1, SshKnownHostKeyType.Rsa1)]
    public void ToKnownHostKeyType_NarrowsSharedSubset(
        SshHostKeyType host, SshKnownHostKeyType expected)
        => Assert.Equal(expected, SshHostKeyTypeRegistry.ToKnownHostKeyType(host));

    [Theory]
    [InlineData(SshHostKeyType.RsaSha256)]
    [InlineData(SshHostKeyType.RsaSha512)]
    [InlineData(SshHostKeyType.Unknown)]
    public void ToKnownHostKeyType_ThrowsForUnstorableTypes(SshHostKeyType type)
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => SshHostKeyTypeRegistry.ToKnownHostKeyType(type));

    [Theory]
    [InlineData(SshHostKeyType.SshRsa, SshKnownHostKeyType.SshRsa, true)]
    [InlineData(SshHostKeyType.SshDss, SshKnownHostKeyType.SshDss, true)]
    [InlineData(SshHostKeyType.Ecdsa256, SshKnownHostKeyType.Ecdsa256, true)]
    [InlineData(SshHostKeyType.Ecdsa384, SshKnownHostKeyType.Ecdsa384, true)]
    [InlineData(SshHostKeyType.Ecdsa521, SshKnownHostKeyType.Ecdsa521, true)]
    [InlineData(SshHostKeyType.Ed25519, SshKnownHostKeyType.Ed25519, true)]
    [InlineData(SshHostKeyType.Rsa1, SshKnownHostKeyType.Rsa1, true)]
    [InlineData(SshHostKeyType.RsaSha256, SshKnownHostKeyType.Unknown, false)]
    [InlineData(SshHostKeyType.RsaSha512, SshKnownHostKeyType.Unknown, false)]
    [InlineData(SshHostKeyType.Unknown, SshKnownHostKeyType.Unknown, false)]
    public void TryAsKnownHostKeyType_DistinguishesStorableFromUnstorable(
        SshHostKeyType host, SshKnownHostKeyType expectedKnown, bool expectedResult)
    {
        bool result = SshHostKeyTypeRegistry.TryAsKnownHostKeyType(host, out SshKnownHostKeyType known);

        Assert.Equal(expectedResult, result);
        Assert.Equal(expectedKnown, known);
    }

    // ── ToHostKeyType ────────────────────────────────────────────────

    [Theory]
    [InlineData(SshKnownHostKeyType.SshRsa, SshHostKeyType.SshRsa)]
    [InlineData(SshKnownHostKeyType.SshDss, SshHostKeyType.SshDss)]
    [InlineData(SshKnownHostKeyType.Ecdsa256, SshHostKeyType.Ecdsa256)]
    [InlineData(SshKnownHostKeyType.Ecdsa384, SshHostKeyType.Ecdsa384)]
    [InlineData(SshKnownHostKeyType.Ecdsa521, SshHostKeyType.Ecdsa521)]
    [InlineData(SshKnownHostKeyType.Ed25519, SshHostKeyType.Ed25519)]
    [InlineData(SshKnownHostKeyType.Rsa1, SshHostKeyType.Rsa1)]
    [InlineData(SshKnownHostKeyType.Unknown, SshHostKeyType.Unknown)]
    public void ToHostKeyType_WidensEveryKnownHostKeyType(
        SshKnownHostKeyType known, SshHostKeyType expected)
        => Assert.Equal(expected, SshHostKeyTypeRegistry.ToHostKeyType(known));

    // ── Numeric-identity invariant ───────────────────────────────────

    /// <summary>
    /// The first 8 values of both enums are numerically identical by design —
    /// a direct cast between them is well-defined for the shared subset. This
    /// pins the invariant the registry relies on: if anyone reorders either
    /// enum, this test fails.
    /// </summary>
    [Theory]
    [InlineData(SshKnownHostKeyType.Unknown, SshHostKeyType.Unknown)]
    [InlineData(SshKnownHostKeyType.Rsa1, SshHostKeyType.Rsa1)]
    [InlineData(SshKnownHostKeyType.SshRsa, SshHostKeyType.SshRsa)]
    [InlineData(SshKnownHostKeyType.SshDss, SshHostKeyType.SshDss)]
    [InlineData(SshKnownHostKeyType.Ecdsa256, SshHostKeyType.Ecdsa256)]
    [InlineData(SshKnownHostKeyType.Ecdsa384, SshHostKeyType.Ecdsa384)]
    [InlineData(SshKnownHostKeyType.Ecdsa521, SshHostKeyType.Ecdsa521)]
    [InlineData(SshKnownHostKeyType.Ed25519, SshHostKeyType.Ed25519)]
    public void SharedSubset_HasIdenticalNumericValues(
        SshKnownHostKeyType known, SshHostKeyType host)
    {
        Assert.Equal((int)known, (int)host);
        Assert.Equal((SshHostKeyType)known, host);
        Assert.Equal(known, (SshKnownHostKeyType)host);
    }

    // ── Round-trip through the registry ──────────────────────────────

    /// <summary>
    /// For every entry in the negotiable preference list,
    /// <see cref="SshHostKeyTypeRegistry.LookupByWireName"/> must find it (the
    /// preference list is a subset of the registry). This catches
    /// accidental divergence if the two tables are edited separately.
    /// </summary>
    [Fact]
    public void NegotiableWireNames_AllResolvableThroughLookup()
    {
        foreach (string name in SshHostKeyTypeRegistry.NegotiableWireNamesInPreferenceOrder)
        {
            Assert.NotNull(SshHostKeyTypeRegistry.LookupByWireName(name));
        }
    }

    /// <summary>
    /// For every storable <see cref="SshKnownHostKeyType"/> (i.e. not Unknown),
    /// the wire-name → enum → wire-name round-trip is the identity. Pins the
    /// invariant that <see cref="SshKnownHosts.WriteLine"/> relies on to emit
    /// the same name <see cref="SshKnownHosts.ReadLine"/> parsed.
    /// </summary>
    [Theory]
    [InlineData(SshKnownHostKeyType.SshRsa)]
    [InlineData(SshKnownHostKeyType.SshDss)]
    [InlineData(SshKnownHostKeyType.Ecdsa256)]
    [InlineData(SshKnownHostKeyType.Ecdsa384)]
    [InlineData(SshKnownHostKeyType.Ecdsa521)]
    [InlineData(SshKnownHostKeyType.Ed25519)]
    public void WireNameLookupRoundTrips_KnownHostKeyType(SshKnownHostKeyType type)
    {
        string? wireName = SshHostKeyTypeRegistry.WireNameFor(type);
        Assert.NotNull(wireName);

        (SshHostKeyType Host, SshKnownHostKeyType? Known)? entry = SshHostKeyTypeRegistry.LookupByWireName(wireName!);
        Assert.NotNull(entry);
        Assert.Equal(type, entry!.Value.Known);
    }

    /// <summary>
    /// For every negotiable <see cref="SshHostKeyType"/>, the wire-name → enum →
    /// wire-name round-trip is the identity. Pins the invariant that
    /// <c>HostKeyMethods.Lookup</c> + <c>HostKeyVerifier.SigWireName</c> rely on
    /// to validate sig-blob names during the SSH handshake.
    /// </summary>
    [Theory]
    [InlineData(SshHostKeyType.SshRsa)]
    [InlineData(SshHostKeyType.RsaSha256)]
    [InlineData(SshHostKeyType.RsaSha512)]
    [InlineData(SshHostKeyType.Ecdsa256)]
    [InlineData(SshHostKeyType.Ecdsa384)]
    [InlineData(SshHostKeyType.Ecdsa521)]
    [InlineData(SshHostKeyType.Ed25519)]
    [InlineData(SshHostKeyType.SshDss)]
    public void WireNameLookupRoundTrips_HostKeyType(SshHostKeyType type)
    {
        string? wireName = SshHostKeyTypeRegistry.WireNameFor(type);
        Assert.NotNull(wireName);

        (SshHostKeyType Host, SshKnownHostKeyType? Known)? entry = SshHostKeyTypeRegistry.LookupByWireName(wireName!);
        Assert.NotNull(entry);
        Assert.Equal(type, entry!.Value.Host);
    }
}
