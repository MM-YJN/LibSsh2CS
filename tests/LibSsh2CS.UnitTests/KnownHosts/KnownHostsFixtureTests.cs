using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Phase 3.6 parity-hardening tests: load real <c>ssh-keygen</c>-produced
/// known_hosts fixtures (plain + <c>ssh-keygen -H</c> hashed forms) covering
/// all 5 in-scope host key types, and verify byte-exact <see cref="SshKnownHosts"/>
/// behavior end-to-end.
/// </summary>
/// <remarks>
/// <para>
/// Complements <see cref="KnownHostsSha1CheckTests"/> /
/// <see cref="KnownHostsFileTests"/> (hand-crafted inputs) with real
/// <c>ssh-keygen</c> output. The fixtures under <c>Fixtures/known_hosts/</c>
/// are produced by <c>generate-goldens.sh</c>; CI runs these tests against the
/// committed fixtures (no <c>ssh-keygen</c> needed at test time).
/// </para>
/// <para>
/// <b>What this pins.</b>
/// <list type="bullet">
/// <item><see cref="SshKnownHosts.ReadFileAsync"/> / <see cref="SshKnownHosts.ReadLine"/>
/// parse every in-scope host-key line type correctly.</item>
/// <item><see cref="SshKnownHosts.Check(string,int,byte[],SshKnownHostKeyType)"/> matches
/// a plain-input host against both plain and SHA1-hashed stored entries.</item>
/// <item>The SHA1-hashed digest matches an independent BCL HMAC-SHA1 recomputation
/// (byte-exact OpenSSH <c>ssh-keygen -H</c> parity).</item>
/// <item>RSA entries store <c>ssh-rsa</c> (never <c>rsa-sha2-*</c>) per RFC 8332 §3.1.</item>
/// <item><see cref="SshKnownHosts.WriteLine"/> round-trips real entries byte-identically.</item>
/// </list>
/// </para>
/// </remarks>
public class KnownHostsFixtureTests
{
    // Hard-coded from Fixtures/known_hosts/meta.json — the
    // Meta_Records_Expected_Host_Port test below pins these to the fixture.
    private const string FixtureHost = "127.0.0.1";
    private const int FixturePort = 2222;
    private const string FixtureHostForm = "[127.0.0.1]:2222";

    // The 5 in-scope host-key types, in the fixture's file order (matches
    // OpenSSH's priority: ed25519 > ecdsa-256 > ecdsa-384 > ecdsa-521 > rsa).
    // Exposed both as a typed array (for internal iteration) and as
    // TheoryData (for [MemberData] parameterized tests).
    internal static readonly (string WireName, SshKnownHostKeyType Type, string Blob)[] s_typesList =
    {
        ("ssh-ed25519",         SshKnownHostKeyType.Ed25519, "ed25519_blob.bin"),
        ("ecdsa-sha2-nistp256", SshKnownHostKeyType.Ecdsa256, "ecdsa256_blob.bin"),
        ("ecdsa-sha2-nistp384", SshKnownHostKeyType.Ecdsa384, "ecdsa384_blob.bin"),
        ("ecdsa-sha2-nistp521", SshKnownHostKeyType.Ecdsa521, "ecdsa521_blob.bin"),
        ("ssh-rsa",             SshKnownHostKeyType.SshRsa,   "rsa_blob.bin"),
    };

    public static TheoryData<string, SshKnownHostKeyType, string> Types
    {
        get
        {
            var td = new TheoryData<string, SshKnownHostKeyType, string>();
            foreach ((string w, SshKnownHostKeyType t, string b) in s_typesList)
            {
                td.Add(w, t, b);
            }

            return td;
        }
    }

    // ── meta.json consistency ────────────────────────────────────────

    [Fact]
    public void Meta_Records_Expected_Host_Port_And_Types()
    {
        // Pins the meta.json contents to the hard-coded constants the rest of
        // the test class uses. If generate-goldens.sh changes the host or
        // port, this test fails first with a clear message before the rest
        // of the suite runs.
        string metaJson = FixtureLoader.LoadText("known_hosts.meta.json");

        Assert.Contains($"\"host\": \"{FixtureHost}\"", metaJson);
        Assert.Contains($"\"port\": {FixturePort}", metaJson);
        Assert.Contains($"\"hostForm\": \"{FixtureHostForm}\"", metaJson);

        foreach ((string wireName, SshKnownHostKeyType _, string blob) in s_typesList)
        {
            Assert.Contains(wireName, metaJson);
            Assert.Contains(blob, metaJson);
        }
    }

    // ── Plain file loading ───────────────────────────────────────────

    [Fact]
    public async Task Load_PlainFile_AddsAllFiveEntries()
    {
        using var known = new SshKnownHosts();

        string content = FixtureLoader.LoadText("known_hosts.keyscan_plain.txt");
        int added = await LoadFromTextAsync(known, content);

        Assert.Equal(5, added);

        // Verify iteration yields all 5 (in file order — pinned by the next test).
        int count = 0;
        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            count++;
        }

        Assert.Equal(5, count);
    }

    [Fact]
    public async Task Load_PlainFile_AllEntriesArePlainFormat()
    {
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            Assert.Equal(SshKnownHostFormat.Plain, e!.Format);
            // Plain entries store the host form verbatim (no salt).
            Assert.Null(e.Salt);
        }
    }

    [Fact]
    public async Task Load_PlainFile_EntriesInFileOrder()
    {
        // The plain fixture lists types in priority order (ed25519 first,
        // rsa last). GetFirst/GetNext must yield them in that order — pins
        // the documented insertion-order iteration (KnownHostKeyType
        // round-trips without re-sorting).
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        // Expected order: ed25519, ecdsa-256, ecdsa-384, ecdsa-521, rsa.
        SshKnownHostKeyType[] expected =
        {
            SshKnownHostKeyType.Ed25519,
            SshKnownHostKeyType.Ecdsa256,
            SshKnownHostKeyType.Ecdsa384,
            SshKnownHostKeyType.Ecdsa521,
            SshKnownHostKeyType.SshRsa,
        };

        int i = 0;
        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            Assert.Equal(expected[i++], e!.KeyType);
        }

        Assert.Equal(expected.Length, i);
    }

    // ── Hashed file loading ──────────────────────────────────────────

    [Fact]
    public async Task Load_HashedFile_AddsAllFiveEntriesAsSha1()
    {
        using var known = new SshKnownHosts();
        int added = await LoadFromTextAsync(
            known, FixtureLoader.LoadText("known_hosts.keyscan_hashed.txt"));

        Assert.Equal(5, added);

        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            Assert.Equal(SshKnownHostFormat.Sha1, e!.Format);
            // SHA1 entries: Name is the base64-encoded HMAC-SHA1 digest; Salt
            // is the raw salt bytes (caller decodes from base64 at Add time).
            Assert.NotNull(e.Salt);
            Assert.NotEmpty(e.Salt);
        }
    }

    // ── Check: plain input matches both plain and hashed stored entries ──

    [Theory]
    [MemberData(nameof(Types))]
    public async Task Check_PlainFileEntry_ReturnsMatch(
        string wireName, SshKnownHostKeyType keyType, string blobName)
    {
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        byte[] blob = FixtureLoader.LoadBytes($"known_hosts.{blobName}");

        SshKnownHostCheckResult result = known.Check(FixtureHost, FixturePort, blob, keyType);

        Assert.True(result.Status == SshKnownHostCheckStatus.Match,
            $"{wireName}: expected Match, got {result.Status}");
        Assert.NotNull(result.Matched);
        Assert.Equal(keyType, result.Matched!.KeyType);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public async Task Check_HashedFileEntry_ReturnsMatch(
        string wireName, SshKnownHostKeyType keyType, string blobName)
    {
        // The most important parity check: a plain-input host must match a
        // SHA1-hashed stored entry. This is the path ssh-keygen -H produces
        // and the path libgit2's SshTransport must handle.
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_hashed.txt"));

        byte[] blob = FixtureLoader.LoadBytes($"known_hosts.{blobName}");

        SshKnownHostCheckResult result = known.Check(FixtureHost, FixturePort, blob, keyType);

        Assert.True(result.Status == SshKnownHostCheckStatus.Match,
            $"{wireName}: expected Match (hashed), got {result.Status}");
        Assert.NotNull(result.Matched);
        Assert.Equal(keyType, result.Matched!.KeyType);
    }

    // ── Wrong key bytes / wrong host ─────────────────────────────────

    [Theory]
    [MemberData(nameof(Types))]
    public async Task Check_WrongKeyBytes_ReturnsMismatch(
        string wireName, SshKnownHostKeyType keyType, string _)
    {
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        // A different in-scope blob — should be a key-type-matching but
        // key-byte-mismatching entry, surfacing the badkey.
        byte[] wrongBlob = GetDifferentBlob(keyType);

        SshKnownHostCheckResult result = known.Check(FixtureHost, FixturePort, wrongBlob, keyType);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
        Assert.NotNull(result.Matched); // The badkey entry.
        Assert.Equal(keyType, result.Matched!.KeyType);
        Assert.Equal(wireName, SshHostKeyTypeRegistry.WireNameFor(result.Matched!.KeyType));
    }

    [Theory]
    [MemberData(nameof(Types))]
    public async Task Check_UnknownHost_ReturnsNotFound(
        string wireName, SshKnownHostKeyType keyType, string blobName)
    {
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        byte[] blob = FixtureLoader.LoadBytes($"known_hosts.{blobName}");

        SshKnownHostCheckResult result = known.Check("not-the-fixture-host.example", FixturePort, blob, keyType);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
        Assert.Null(result.Matched);
        // Pin the wire-name/key-type pairing pinned by the fixture's meta.json.
        Assert.Equal(wireName, SshHostKeyTypeRegistry.WireNameFor(keyType));
    }

    // ── Plain / hashed agreement ─────────────────────────────────────

    [Theory]
    [MemberData(nameof(Types))]
    public async Task HashedAndPlain_AgreeOnKeyBytes(
        string wireName, SshKnownHostKeyType keyType, string _)
    {
        // The hashed and plain fixtures were generated from the SAME set of
        // ssh-keygen .pub files (one fixture pass). So the stored base64 Key
        // for a given type must be byte-identical between the two files.
        using var plain = new SshKnownHosts();
        await LoadFromTextAsync(plain, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        using var hashed = new SshKnownHosts();
        await LoadFromTextAsync(hashed, FixtureLoader.LoadText("known_hosts.keyscan_hashed.txt"));

        SshKnownHostEntry? plainEntry = FindByType(plain, keyType);
        SshKnownHostEntry? hashedEntry = FindByType(hashed, keyType);

        Assert.NotNull(plainEntry);
        Assert.NotNull(hashedEntry);
        Assert.Equal(plainEntry!.Key, hashedEntry!.Key);
        Assert.Equal(wireName, SshHostKeyTypeRegistry.WireNameFor(plainEntry!.KeyType));
    }

    // ── Independent HMAC-SHA1 recompute (strongest SHA1 parity check) ──

    [Theory]
    [MemberData(nameof(Types))]
    public async Task HashedEntry_IndependentHmacRecomputation_Agrees(
        string wireName, SshKnownHostKeyType keyType, string _)
    {
        // Independently compute HMAC-SHA1(salt, hostForm) using the BCL and
        // compare to the SHA1-stored entry's Name (base64 of the digest).
        // This is byte-exact OpenSSH ssh-keygen -H parity — if both the
        // library and this test agree, the HMAC path matches the C reference.
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_hashed.txt"));

        SshKnownHostEntry? entry = FindByType(known, keyType);
        Assert.NotNull(entry);
        Assert.NotNull(entry!.Salt);
        Assert.Equal(wireName, SshHostKeyTypeRegistry.WireNameFor(entry!.KeyType));

        byte[] expectedDigest;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, entry.Salt!))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes(FixtureHostForm));
            expectedDigest = hmac.GetHashAndReset();
        }

        Assert.Equal(20, expectedDigest.Length);
        Assert.Equal(Base64.EncodeToString(expectedDigest), entry.Name);
    }

    // ── WriteLine round-trip ─────────────────────────────────────────

    [Fact]
    public async Task WriteLine_RoundTripsRealPlainEntries_ByteIdentical()
    {
        // ReadLine → WriteLine must produce byte-identical output for the
        // plain fixture. Pins the WriteLine format + ReadLine parse symmetry
        // against real ssh-keygen output.
        string original = FixtureLoader.LoadText("known_hosts.keyscan_plain.txt");

        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, original);

        // Re-emit every entry in iteration order. WriteLine includes a
        // trailing '\n' per entry, matching the file's record separator.
        var sb = new StringBuilder();
        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            sb.Append(known.WriteLine(e!, SshKnownHostFileType.OpenSsh));
        }

        Assert.Equal(original, sb.ToString());
    }

    // ── RFC 8332 §3.1 invariant ──────────────────────────────────────

    [Fact]
    public async Task RsaEntry_IsStoredAs_SshRsa_Not_Sha2Variant()
    {
        // RFC 8332 §3.1: the wire keytype for stored RSA keys is ALWAYS
        // "ssh-rsa", regardless of which SHA-2 variant the server signs with.
        // The fixture's RSA line must parse to KnownHostKeyType.SshRsa —
        // never RsaSha256 / RsaSha512 (which KnownHostKeyType doesn't even
        // have, by design).
        using var known = new SshKnownHosts();
        await LoadFromTextAsync(known, FixtureLoader.LoadText("known_hosts.keyscan_plain.txt"));

        SshKnownHostEntry? rsa = FindByType(known, SshKnownHostKeyType.SshRsa);
        Assert.NotNull(rsa);
        Assert.Equal(SshKnownHostKeyType.SshRsa, rsa!.KeyType);

        // WriteLine must emit "ssh-rsa" (the on-disk wire name), not any
        // rsa-sha2-* variant. The wire-name lookup delegates to
        // HostKeyTypeRegistry — this pins the registry's RSA-stored-as-ssh-rsa
        // behavior against accidental divergence.
        string line = known.WriteLine(rsa, SshKnownHostFileType.OpenSsh);
        Assert.Contains(" ssh-rsa ", line);
        Assert.DoesNotContain("rsa-sha2-", line);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static async Task<int> LoadFromTextAsync(SshKnownHosts known, string content)
    {
        // ReadFileAsync needs a path; write the embedded content to a temp
        // file so we exercise the same code path the production caller does
        // (the KnownHosts.ReadFileAsync → ReadLine pipeline).
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, content);
            return await known.ReadFileAsync(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static SshKnownHostEntry? FindByType(SshKnownHosts known, SshKnownHostKeyType type)
    {
        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            if (e!.KeyType == type)
            {
                return e;
            }
        }

        return null;
    }

    private static byte[] GetDifferentBlob(SshKnownHostKeyType targetType)
    {
        // Returns a blob from a DIFFERENT type (so the key bytes differ
        // bit-for-bit). Picks any type != targetType from the fixture.
        foreach ((_, SshKnownHostKeyType t, string blob) in s_typesList)
        {
            if (t != targetType)
            {
                return FixtureLoader.LoadBytes($"known_hosts.{blob}");
            }
        }

        throw new InvalidOperationException($"No other type available for {targetType}.");
    }
}
