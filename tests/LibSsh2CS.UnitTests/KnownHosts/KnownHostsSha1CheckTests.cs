using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Tests for <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType, SshKnownHostFormat)"/>
/// against <see cref="SshKnownHostFormat.Sha1"/>-stored entries — Phase 3 increment 3.1.3.
/// </summary>
/// <remarks>
/// Exercises the HMAC-SHA1 hostname-hashing path of <c>knownhost_check</c>
/// (<c>knownhost.c:416-446</c>): the caller supplies a plaintext hostname, the
/// library recomputes <c>HMAC-SHA1(salt, hostname)</c>, and compares to the
/// stored digest. This is the format OpenSSH produces via <c>ssh-keygen -H</c>.
/// </remarks>
public class KnownHostsSha1CheckTests
{
    // 32-byte placeholder keys.
    private static readonly byte[] s_keyA = new byte[]
    {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
    };

    private static readonly byte[] s_keyB = new byte[]
    {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };

    // Realistic 20-byte salt (OpenSSH uses 20-byte random salts).
    private static readonly byte[] s_salt = new byte[]
    {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc,
    };

    // ── Core SHA1 stored + Plain input ───────────────────────────────

    [Fact]
    public void Check_Sha1StoredMatchingHost_ReturnsMatch()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_Sha1StoredWrongHost_ReturnsNotFound()
    {
        using var known = new SshKnownHosts();
        AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("other.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
        Assert.Null(result.Matched);
    }

    [Fact]
    public void Check_Sha1StoredWrongKey_ReturnsMismatchWithBadkey()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_Sha1StoredWithPort_BracketedHostFormHashed()
    {
        // When a port is specified, the check first tries "[host]:port" against
        // SHA1 entries (the bracketed form is HMAC'd, not just the plain host).
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddSha1Entry(known, "[example.com]:22", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_Sha1StoredFallsBackToPlainHost()
    {
        // SHA1 entry for plain "example.com"; Check with port=22 should still
        // match via the fallback to plain host.
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    // ── Cross-format isolation ───────────────────────────────────────

    [Fact]
    public void Check_Sha1StoredCustomInput_NoMatch()
    {
        // Custom input only matches Custom stored; SHA1 entries are invisible.
        using var known = new SshKnownHosts();
        AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check(
            "example.com",
            s_keyA,
            SshKnownHostKeyType.Ed25519,
            inputFormat: SshKnownHostFormat.Custom);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    [Fact]
    public void Check_Sha1InputVsSha1Stored_ReturnsMismatchImmediately()
    {
        // Re-affirms the knownhost.c:367-369 guard: SHA1 *input* is always
        // rejected, even when the stored entry is also SHA1.
        using var known = new SshKnownHosts();
        AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check(
            "example.com",
            s_keyA,
            SshKnownHostKeyType.Ed25519,
            inputFormat: SshKnownHostFormat.Sha1);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
    }

    // ── Different salts produce different hashes ────────────────────

    [Fact]
    public void Check_Sha1DifferentSaltDoesNotMatch()
    {
        // Two entries for the same hostname but with different salts produce
        // different HMAC-SHA1 digests. Asking with the key of one should match
        // only the entry whose salt was used to compute the probe hash.
        using var known = new SshKnownHosts();

        byte[] saltA = s_salt;
        byte[] saltB = new byte[]
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        };

        SshKnownHostEntry entryA = AddSha1Entry(known, "example.com", saltA, s_keyA, SshKnownHostKeyType.Ed25519);
        AddSha1Entry(known, "example.com", saltB, s_keyB, SshKnownHostKeyType.Ed25519);

        // Check with key-A should match entry-A (probed hostname hashes to
        // entry-A's stored digest under salt-A, and to entry-B's under salt-B;
        // the library computes both HMACs and only entry-A's key matches).
        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entryA, result.Matched);
    }

    // ── Length/corruption guards ─────────────────────────────────────

    [Fact]
    public void Check_Sha1StoredHashWithWrongLength_NoMatch()
    {
        // Parity with knownhost.c:427-431 — a stored "hash" that isn't exactly
        // 20 bytes is silently skipped (it can't be a real HMAC-SHA1 output).
        using var known = new SshKnownHosts();

        // 16 bytes instead of 20 — will decode fine but fails the length gate.
        string badHashBase64 = Base64.EncodeToString(new byte[16]);

        known.Add(
            host: badHashBase64,
            salt: s_salt,
            key: s_keyA,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    [Fact]
    public void Check_Sha1StoredHashInvalidBase64_NoMatch()
    {
        // A corrupt stored hash that isn't valid base64 should not throw — the
        // library treats it as a non-matching entry.
        using var known = new SshKnownHosts();

        known.Add(
            host: "this!!!is!!!not!!!base64!!!",
            salt: s_salt,
            key: s_keyA,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    [Theory]
    [InlineData(22)]   // 4·5+2: lenient decoder writes idx 16 into the 16-byte bucket (1 past)
    [InlineData(23)]   // 4·5+3: writes idx 17 into the 16-byte bucket (2 past)
    [InlineData(86)]   // 4·21+2: writes idx 64 into the 64-byte bucket (1 past)
    [InlineData(87)]   // 4·21+3: writes idx 65 into the 64-byte bucket (2 past)
    [InlineData(171)]  // 4·42+3: writes idx 128 into the 128-byte bucket (1 past)
    public void Check_UnpaddedStoredHashWithPartialTail_ReturnsNotFound(int hashLength)
    {
        // Regression: a corrupt known_hosts line whose stored hash is
        // unpadded with a partial trailing group. Base64.GetMaxDecodedLength
        // (3·⌊L/4⌋, the BCL strict decoder's floor bound) is up to 2 bytes
        // short for the lenient decoder, which writes the partial tail — the
        // decode must never escape the rented buffer (pre-fix this threw
        // IndexOutOfRangeException from the Span bounds check).
        using var known = new SshKnownHosts();

        // 28 base64 chars (< the 32-char salt cap in ParseHashedHostLine).
        string saltBase64 = Base64.EncodeToString(s_salt);
        string unpaddedHash = new('A', hashLength);
        string line = $"|1|{saltBase64}|{unpaddedHash} ssh-ed25519 {Base64.EncodeToString(s_keyA)}";

        known.ReadLine(line, SshKnownHostFileType.OpenSsh);

        // The decoded hash is 16/17/64/65/128 bytes — never 20 — so the
        // length gate (knownhost.c:427-431) silently skips it.
        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
        Assert.Null(result.Matched);
    }

    // ── Mixed entries: SHA1 + Plain coexist ─────────────────────────

    [Fact]
    public void Check_MixedSha1AndPlainEntries_MatchEither()
    {
        // A collection can have both hashed and plaintext entries for the same
        // host; Check should match whichever entry's key the caller supplies.
        using var known = new SshKnownHosts();
        SshKnownHostEntry sha1Entry = AddSha1Entry(known, "example.com", s_salt, s_keyA, SshKnownHostKeyType.Ed25519);
        SshKnownHostEntry plainEntry = known.Add(
            host: "example.com",
            salt: null,
            key: s_keyB,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Plain);

        SshKnownHostCheckResult resultA = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);
        SshKnownHostCheckResult resultB = known.Check("example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, resultA.Status);
        Assert.Same(sha1Entry, resultA.Matched);
        Assert.Equal(SshKnownHostCheckStatus.Match, resultB.Status);
        Assert.Same(plainEntry, resultB.Matched);
    }

    // ── Real-world known_hosts fixture parity ────────────────────────

    /// <summary>
    /// Reproduces a real <c>ssh-keygen -H</c> hashed entry end-to-end: the test
    /// computes the HMAC-SHA1 the same way OpenSSH does (salt + hostname) and
    /// confirms <see cref="SshKnownHosts.Check"/> produces the same digest match.
    /// This is the strongest parity check — if both the library and this test
    /// agree on the digest for a given (salt, host) pair, the HMAC path matches
    /// the C reference byte-for-byte.
    /// </summary>
    [Fact]
    public void Check_Sha1Entry_IndependentHmacRecomputation_Agrees()
    {
        const string hostname = "github.com";

        // Salt chosen to be a realistic 20-byte value.
        byte[] salt = new byte[]
        {
            0x53, 0x9b, 0x7a, 0xbb, 0x37, 0xa4, 0x4c, 0xc2,
            0x93, 0x4d, 0x4e, 0x96, 0xc7, 0xeb, 0x88, 0x38,
            0xf6, 0x6c, 0x07, 0xa1,
        };

        // Compute the expected HMAC-SHA1 digest independently, using the BCL
        // directly (not through KnownHosts internals).
        byte[] expectedDigest;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes(hostname));
            expectedDigest = hmac.GetHashAndReset();
        }

        Assert.Equal(20, expectedDigest.Length);

        using var known = new SshKnownHosts();

        // Store an entry with this salt and the independently-computed digest.
        SshKnownHostEntry entry = known.Add(
            host: Base64.EncodeToString(expectedDigest),
            salt: salt,
            key: s_keyA,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1);

        // Check should recompute the HMAC internally and match.
        SshKnownHostCheckResult result = known.Check(hostname, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Adds a SHA1-format entry by computing HMAC-SHA1(salt, hostname)
    /// independently — the same computation OpenSSH performs when writing a
    /// hashed known_hosts entry via <c>ssh-keygen -H</c>.
    /// </summary>
    private static SshKnownHostEntry AddSha1Entry(
        SshKnownHosts known,
        string hostname,
        byte[] salt,
        byte[] key,
        SshKnownHostKeyType keyType)
    {
        byte[] hash;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes(hostname));
            hash = hmac.GetHashAndReset();
        }

        return known.Add(
            host: Base64.EncodeToString(hash),
            salt: salt,
            key: key,
            keyType: keyType,
            format: SshKnownHostFormat.Sha1);
    }
}
