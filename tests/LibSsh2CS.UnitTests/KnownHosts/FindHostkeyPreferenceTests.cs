namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Phase 3 increment 3.1.7: Preview of the Phase N
/// <c>find_hostkey_preference</c> probing pattern. Mirrors
/// <c>ssh_libssh2.c:523-587</c> in libgit2 — the SshTransport will use this
/// exact <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType)"/>
/// call sequence to build the hostkey method preference string before
/// <c>SshSession.HandshakeAsync</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>How the probe works</b>: for each <see cref="SshKnownHostKeyType"/> in
/// priority order, call <see cref="SshKnownHosts.Check"/> with a dummy zero-byte
/// key. A <see cref="SshKnownHostCheckStatus.Mismatch"/> result means the host IS
/// known for that key type (the hostname matched, the key type matched, but the
/// dummy key bytes differ from the stored key). A
/// <see cref="SshKnownHostCheckStatus.NotFound"/> result means no entry exists for
/// that host + key type combination.
/// </para>
/// <para>
/// This test does <em>not</em> implement the Phase N wiring — it only verifies
/// that <see cref="SshKnownHosts"/> supports the probe pattern correctly. When
/// Phase N ships, <c>SshTransport</c> will replicate this loop verbatim, then
/// feed the resulting preference string into
/// <c>session[MethodType.HostKey] = prefs</c> before handshake.
/// </para>
/// </remarks>
public class FindHostkeyPreferenceTests
{
    // 32-byte placeholder keys (one per type, so each entry is distinct).
    private static readonly byte[] s_ed25519Key = new byte[32];
    private static readonly byte[] s_rsaKey = new byte[32];
    private static readonly byte[] s_ecdsa256Key = new byte[32];

    static FindHostkeyPreferenceTests()
    {
        s_ed25519Key[0] = 0xED;
        s_rsaKey[0] = 0xDA;
        s_ecdsa256Key[0] = 0xEC;
    }

    /// <summary>
    /// Simulates the full <c>find_hostkey_preference</c> flow: a known_hosts
    /// with Ed25519 + RSA entries for the same host. The probe should discover
    /// both types and produce a preference string with Ed25519 first (higher
    /// priority) and RSA second (expanded to include rsa-sha2-512/256).
    /// </summary>
    [Fact]
    public void Probe_BuildsPreferenceStringInPriorityOrder()
    {
        using var known = new SshKnownHosts();

        // Populate known_hosts as if loaded from ~/.ssh/known_hosts.
        known.Add("git.example.com", null, s_ed25519Key, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain);
        known.Add("git.example.com", null, s_rsaKey, SshKnownHostKeyType.SshRsa, SshKnownHostFormat.Plain);

        // Run the probe — this is the exact loop Phase N's SshTransport will use.
        List<string> prefs = FindHostkeyPreferences(known, "git.example.com", 22);

        // Expected: ed25519 first, then ecdsa types are absent (not in known_hosts),
        // then rsa-sha2-512, rsa-sha2-256, ssh-rsa (the RSA triple).
        Assert.Equal("ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa", string.Join(",", prefs));
    }

    /// <summary>
    /// A host known only for Ed25519 should produce a single-entry preference list.
    /// </summary>
    [Fact]
    public void Probe_OnlyEd25519_ProducesSingleEntry()
    {
        using var known = new SshKnownHosts();
        known.Add("host.example.com", null, s_ed25519Key, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain);

        List<string> prefs = FindHostkeyPreferences(known, "host.example.com", 22);

        Assert.Equal("ssh-ed25519", string.Join(",", prefs));
    }

    /// <summary>
    /// A host known only for RSA should produce the RSA triple
    /// (rsa-sha2-512,rsa-sha2-256,ssh-rsa) — the modern SHA-2 variants first,
    /// the legacy SHA-1 variant last.
    /// </summary>
    [Fact]
    public void Probe_OnlyRsa_ExpandsToSha2Triple()
    {
        using var known = new SshKnownHosts();
        known.Add("legacy.example.com", null, s_rsaKey, SshKnownHostKeyType.SshRsa, SshKnownHostFormat.Plain);

        List<string> prefs = FindHostkeyPreferences(known, "legacy.example.com", 22);

        Assert.Equal("rsa-sha2-512,rsa-sha2-256,ssh-rsa", string.Join(",", prefs));
    }

    /// <summary>
    /// A completely unknown host should produce an empty preference list.
    /// Phase N's SshTransport will skip setting a hostkey preference in this
    /// case (letting the server pick), so the known_hosts check happens later
    /// via the verifyHostKeyAsync callback.
    /// </summary>
    [Fact]
    public void Probe_UnknownHost_ProducesEmptyList()
    {
        using var known = new SshKnownHosts();
        known.Add("known.example.com", null, s_ed25519Key, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain);

        List<string> prefs = FindHostkeyPreferences(known, "unknown.example.com", 22);

        Assert.Empty(prefs);
    }

    /// <summary>
    /// ECDSA entries should be probed and included in the correct priority
    /// position (after Ed25519, before RSA).
    /// </summary>
    [Fact]
    public void Probe_AllKeyTypes_CorrectPriorityOrder()
    {
        using var known = new SshKnownHosts();
        known.Add("all.example.com", null, s_ecdsa256Key, SshKnownHostKeyType.Ecdsa256, SshKnownHostFormat.Plain);
        known.Add("all.example.com", null, s_ed25519Key, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain);
        known.Add("all.example.com", null, s_rsaKey, SshKnownHostKeyType.SshRsa, SshKnownHostFormat.Plain);

        List<string> prefs = FindHostkeyPreferences(known, "all.example.com", 22);

        // Full priority order: ed25519 > ecdsa-256 > ecdsa-384 > ecdsa-521 >
        // rsa-sha2-512 > rsa-sha2-256 > ssh-rsa. We only have ed25519,
        // ecdsa-256, and ssh-rsa entries.
        Assert.Equal("ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
            string.Join(",", prefs));
    }

    /// <summary>
    /// Hashed entries (|1|salt|hash) should also be probed successfully — the
    /// Check method recomputes the HMAC and matches the plaintext probe host.
    /// </summary>
    [Fact]
    public void Probe_HashedKnownHost_FindsEntry()
    {
        using var known = new SshKnownHosts();

        // Add a hashed entry for "hashed.example.com".
        byte[] salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        byte[] hash;
        using (var hmac = System.Security.Cryptography.IncrementalHash.CreateHMAC(
            System.Security.Cryptography.HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(System.Text.Encoding.UTF8.GetBytes("hashed.example.com"));
            hash = hmac.GetHashAndReset();
        }

        known.Add(
            host: Convert.ToBase64String(hash),
            salt: salt,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1);

        List<string> prefs = FindHostkeyPreferences(known, "hashed.example.com", 22);

        Assert.Equal("ssh-ed25519", string.Join(",", prefs));
    }

    // ── The probe loop itself (Phase N will inline this into SshTransport) ──

    /// <summary>
    /// Replicates libgit2's <c>find_hostkey_preference</c> probe loop. For each
    /// known hostkey type, checks whether the host appears in known_hosts for
    /// that type (using a dummy zero-byte key — MISMATCH means "found but key
    /// differs", NOTFOUND means "not in known_hosts for this type").
    /// </summary>
    /// <remarks>
    /// The probe order mirrors the libssh2/OpenSSH preference: Ed25519 first,
    /// then ECDSA in curve-size order, then the RSA triple (rsa-sha2-512 >
    /// rsa-sha2-256 > ssh-rsa). An RSA entry in known_hosts expands to all
    /// three because they share the same key material (the SHA-2 variants use
    /// a stronger signature hash over the same RSA modulus).
    /// </remarks>
    private static List<string> FindHostkeyPreferences(SshKnownHosts known, string host, int port)
    {
        // Dummy key: a single zero byte. Will never match a real key, so any
        // Check that returns MISMATCH indicates the host IS known for that type.
        byte[] dummyKey = new byte[1];

        var prefs = new List<string>();

        // Probe each KnownHostKeyType in priority order.
        foreach (SshKnownHostKeyType type in s_hostkeyProbeOrder)
        {
            SshKnownHostCheckResult result = known.Check(host, port, dummyKey, type);

            if (result.Status == SshKnownHostCheckStatus.Mismatch)
            {
                // Host is known for this key type — expand to wire-format names.
                prefs.AddRange(HostkeyWireNames(type));
            }
        }

        return prefs;
    }

    /// <summary>
    /// The probe order, mirroring OpenSSH/libssh2's preference priority.
    /// </summary>
    private static readonly SshKnownHostKeyType[] s_hostkeyProbeOrder =
    {
        SshKnownHostKeyType.Ed25519,
        SshKnownHostKeyType.Ecdsa256,
        SshKnownHostKeyType.Ecdsa384,
        SshKnownHostKeyType.Ecdsa521,
        SshKnownHostKeyType.SshRsa,
    };

    /// <summary>
    /// Maps a <see cref="SshKnownHostKeyType"/> to the wire-format algorithm names
    /// it implies for hostkey negotiation. RSA expands to three names (the
    /// SHA-2 variants + the legacy SHA-1 variant) because they share the same
    /// key material. Other types delegate to
    /// <see cref="SshHostKeyTypeRegistry.WireNameFor(SshKnownHostKeyType)"/>.
    /// </summary>
    private static string[] HostkeyWireNames(SshKnownHostKeyType type)
    {
        // RSA expands to the SHA-2 triple per RFC 8332 §3.1: the stored ssh-rsa
        // key material can be signed with any of the three RSA algorithms.
        if (type == SshKnownHostKeyType.SshRsa)
        {
            return new[] { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" };
        }

        // Single-wire-name types delegate to the shared registry. Non-null
        // because the probe order only enumerates storable, named types.
        string? wire = SshHostKeyTypeRegistry.WireNameFor(type);
        return wire is not null ? new[] { wire } : Array.Empty<string>();
    }
}
