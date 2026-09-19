using System.Buffers.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Tests for <see cref="SshKnownHosts"/> Phase 3 increment 3.1.1: construction,
/// disposal, <see cref="SshKnownHosts.Add"/>, <see cref="SshKnownHosts.Delete"/>, and
/// <see cref="SshKnownHosts.GetFirst"/>/<see cref="SshKnownHosts.GetNext"/> iteration.
/// </summary>
/// <remarks>
/// <see cref="SshKnownHosts.Check"/> / <see cref="SshKnownHosts.ReadLine"/> /
/// <see cref="SshKnownHosts.WriteLine"/> / file IO are delivered in subsequent
/// increments; this file exercises only the storage layer.
/// </remarks>
public class SshKnownHostsTests
{
    // SHA1 host hashes are arbitrary 20-byte values; salts are arbitrary too.
    // Real parsing of <c>|1|salt|hash</c> lines lands in increment 3.1.4.
    private static readonly byte[] s_sha1HashBytes = new byte[]
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14,
    };

    private static readonly byte[] s_sha1SaltBytes = new byte[]
    {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    };

    private static readonly byte[] s_ed25519Key = new byte[]
    {
        // 32-byte Ed25519 public key placeholder; real fixtures land in 3.1.4.
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
    };

    // ── Add: returns entry with correct fields ───────────────────────

    [Fact]
    public void Add_PlainHost_StoresHostNameAndBase64Key()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry entry = known.Add(
            host: "example.com",
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Plain);

        Assert.Equal("example.com", entry.Name);
        Assert.Null(entry.Salt);
        Assert.Equal(Base64.EncodeToString(s_ed25519Key), entry.Key);
        Assert.Equal(SshKnownHostKeyType.Ed25519, entry.KeyType);
        Assert.Equal(SshKnownHostFormat.Plain, entry.Format);
        Assert.Null(entry.Comment);
    }

    [Fact]
    public void Add_WithComment_StoresCommentVerbatim()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry entry = known.Add(
            host: "example.com",
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Plain,
            comment: "key from work laptop");

        Assert.Equal("key from work laptop", entry.Comment);
    }

    [Fact]
    public void Add_EmptyComment_IsPreservedDistinctFromNull()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry entry = known.Add(
            host: "h",
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain,
            comment: string.Empty);

        // Null means "no comment written"; empty means "trailing space written".
        // WriteLine (increment 3.1.5) distinguishes them; here we just verify
        // empty round-trips through Add without being normalized to null.
        Assert.NotNull(entry.Comment);
        Assert.Equal(string.Empty, entry.Comment);
    }

    [Fact]
    public void Add_Sha1Format_StoresHashAsBase64StringAndSaltAsRawBytes()
    {
        using var known = new SshKnownHosts();

        string hashBase64 = Base64.EncodeToString(s_sha1HashBytes);

        SshKnownHostEntry entry = known.Add(
            host: hashBase64,
            salt: s_sha1SaltBytes,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1);

        Assert.Equal(hashBase64, entry.Name);
        Assert.Equal(s_sha1SaltBytes, entry.Salt);
        Assert.Equal(SshKnownHostFormat.Sha1, entry.Format);
    }

    [Fact]
    public void Add_PlainFormat_IgnoresProvidedSalt()
    {
        using var known = new SshKnownHosts();

        // A caller passing a salt with a Plain format entry should not crash.
        // Parity: knownhost_add's Plain branch never touches the salt parameter.
        SshKnownHostEntry entry = known.Add(
            host: "example.com",
            salt: s_sha1SaltBytes,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain);

        Assert.Null(entry.Salt);
    }

    [Fact]
    public void Add_CustomFormat_StoresHostNameAsProvided()
    {
        using var known = new SshKnownHosts();

        string preHashed = "deadbeefcafebabe";

        SshKnownHostEntry entry = known.Add(
            host: preHashed,
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ecdsa256,
            format: SshKnownHostFormat.Custom);

        Assert.Equal(preHashed, entry.Name);
        Assert.Equal(SshKnownHostFormat.Custom, entry.Format);
    }

    [Fact]
    public void Add_Base64EncodesRawKey()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry entry = known.Add(
            host: "h",
            salt: null,
            key: new byte[] { 0x01, 0x02, 0x03 },
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain);

        // BCL Convert.ToBase64String of {1,2,3} is "AQID".
        Assert.Equal("AQID", entry.Key);
    }

    // ── Add: argument validation ─────────────────────────────────────

    [Fact]
    public void Add_NullHost_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();

        Assert.Throws<ArgumentNullException>(() => known.Add(
            host: null!,
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain));
    }

    [Fact]
    public void Add_NullKey_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();

        Assert.Throws<ArgumentNullException>(() => known.Add(
            host: "h",
            salt: null,
            key: null!,
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain));
    }

    [Fact]
    public void Add_Sha1FormatWithoutSalt_ThrowsInval()
    {
        using var known = new SshKnownHosts();

        SshException ex = Assert.Throws<SshException>(() => known.Add(
            host: Base64.EncodeToString(s_sha1HashBytes),
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1));

        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
    }

    [Fact]
    public void Add_Sha1FormatWithEmptySalt_ThrowsInval()
    {
        using var known = new SshKnownHosts();

        Assert.Throws<SshException>(() => known.Add(
            host: Base64.EncodeToString(s_sha1HashBytes),
            salt: Array.Empty<byte>(),
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1));
    }

    [Fact]
    public void Add_AfterDispose_ThrowsObjectDisposedException()
    {
        var known = new SshKnownHosts();
        known.Dispose();

        Assert.Throws<ObjectDisposedException>(() => known.Add(
            host: "h",
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain));
    }

    // ── GetFirst / GetNext iteration ─────────────────────────────────

    [Fact]
    public void GetFirst_EmptyCollection_ReturnsNull()
    {
        using var known = new SshKnownHosts();
        Assert.Null(known.GetFirst());
    }

    [Fact]
    public void GetFirst_AfterAdd_ReturnsFirstEntry()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = AddPlain(known, "host1");
        SshKnownHostEntry e2 = AddPlain(known, "host2");

        SshKnownHostEntry? first = known.GetFirst();
        Assert.Same(e1, first);
        Assert.NotSame(e2, first);
    }

    [Fact]
    public void GetNext_WalksInInsertionOrder()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = AddPlain(known, "host1");
        SshKnownHostEntry e2 = AddPlain(known, "host2");
        SshKnownHostEntry e3 = AddPlain(known, "host3");

        Assert.Same(e1, known.GetFirst());
        Assert.Same(e2, known.GetNext(e1));
        Assert.Same(e3, known.GetNext(e2));
        Assert.Null(known.GetNext(e3));
    }

    [Fact]
    public void GetNext_AcrossValueEqualDuplicates_LocatesExactHandle()
    {
        // GetNext locates `previous` by reference (mirrors knownhost.c's pointer
        // walk in libssh2_knownhost_get), NOT by record value equality. With two
        // value-equal entries, GetNext(e1) must return e2 — e1's actual successor —
        // and GetNext(e2) must return null, not re-resolve to the first value-equal
        // sibling.
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = known.Add(
            host: "dup", salt: null, key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa, format: SshKnownHostFormat.Plain);
        SshKnownHostEntry e2 = known.Add(
            host: "dup", salt: null, key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa, format: SshKnownHostFormat.Plain);

        Assert.NotSame(e1, e2);
        Assert.Equal(e1, e2); // records are value-equal — the trap precondition

        Assert.Same(e1, known.GetFirst());
        Assert.Same(e2, known.GetNext(e1));
        Assert.Null(known.GetNext(e2));
    }

    [Fact]
    public void GetNext_AfterDeleteOfMiddle_SkipsRemoved()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = AddPlain(known, "host1");
        SshKnownHostEntry e2 = AddPlain(known, "host2");
        SshKnownHostEntry e3 = AddPlain(known, "host3");

        Assert.True(known.Delete(e2));

        Assert.Same(e1, known.GetFirst());
        Assert.Same(e3, known.GetNext(e1));
        Assert.Null(known.GetNext(e3));
    }

    [Fact]
    public void GetNext_AfterDeleteOfFirst_AdvancesFirst()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = AddPlain(known, "host1");
        SshKnownHostEntry e2 = AddPlain(known, "host2");

        Assert.True(known.Delete(e1));

        Assert.Same(e2, known.GetFirst());
        Assert.Null(known.GetNext(e2));
    }

    [Fact]
    public void GetNext_UnknownEntry_ReturnsNull()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry orphan = AddPlain(new SshKnownHosts(), "ghost");

        // An entry that isn't in `known` should not yield a successor.
        Assert.Null(known.GetNext(orphan));
    }

    [Fact]
    public void GetNext_NullArgument_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();
        Assert.Throws<ArgumentNullException>(() => known.GetNext(null!));
    }

    [Fact]
    public void Iteration_Disposed_ThrowsObjectDisposedException()
    {
        var known = new SshKnownHosts();
        known.Dispose();

        Assert.Throws<ObjectDisposedException>(() => known.GetFirst());
        Assert.Throws<ObjectDisposedException>(() => known.GetNext(AddPlain(new SshKnownHosts(), "h")));
    }

    // ── Delete ───────────────────────────────────────────────────────

    [Fact]
    public void Delete_RemovesEntryAndReturnsTrue()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e = AddPlain(known, "host");

        Assert.True(known.Delete(e));
        Assert.Null(known.GetFirst());
    }

    [Fact]
    public void Delete_NotPresent_ReturnsFalse()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry orphan = AddPlain(new SshKnownHosts(), "ghost");

        Assert.False(known.Delete(orphan));
    }

    [Fact]
    public void Delete_AlreadyDeleted_ReturnsFalse()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e = AddPlain(known, "host");

        Assert.True(known.Delete(e));
        Assert.False(known.Delete(e));
    }

    [Fact]
    public void Delete_TwoEntriesWithIdenticalFields_UsesReferenceIdentity()
    {
        // Parity with libssh2's pointer-based deletion: two adds with identical
        // fields are distinct handles. Deleting one leaves the other in place.
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = known.Add(
            host: "dup", salt: null, key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa, format: SshKnownHostFormat.Plain);
        SshKnownHostEntry e2 = known.Add(
            host: "dup", salt: null, key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa, format: SshKnownHostFormat.Plain);

        Assert.NotSame(e1, e2);
        Assert.True(known.Delete(e1));

        // Only e2 should remain.
        Assert.Same(e2, known.GetFirst());
        Assert.Null(known.GetNext(e2));
    }

    [Fact]
    public void Delete_MiddleOfValueEqualTriples_RemovesOnlyTargetedHandle()
    {
        using var known = new SshKnownHosts();

        SshKnownHostEntry e1 = AddPlain(known, "dup");
        SshKnownHostEntry e2 = AddPlain(known, "dup");
        SshKnownHostEntry e3 = AddPlain(known, "dup");

        Assert.True(known.Delete(e2));

        // FindIndex(e => ReferenceEquals(e, entry)) must land on the middle slot,
        // not the first value-equal sibling.
        Assert.Same(e1, known.GetFirst());
        Assert.Same(e3, known.GetNext(e1));
        Assert.Null(known.GetNext(e3));
    }

    [Fact]
    public void Delete_HandleFromOtherCollection_IsRejectedEvenWhenValueEqual()
    {
        // Handles are scoped to the collection that issued them (parity with the C
        // struct known_host* being node pointers inside a specific
        // LIBSSH2_KNOWNHOSTS). A foreign handle must be rejected even when its
        // record is value-equal to one of our entries.
        using var ours = new SshKnownHosts();
        using var theirs = new SshKnownHosts();

        SshKnownHostEntry oursHandle = AddPlain(ours, "shared");
        SshKnownHostEntry theirHandle = AddPlain(theirs, "shared");

        Assert.NotSame(oursHandle, theirHandle);
        Assert.Equal(oursHandle, theirHandle); // value-equal across collections

        Assert.False(ours.Delete(theirHandle));
        Assert.Same(oursHandle, ours.GetFirst());

        Assert.Null(ours.GetNext(theirHandle));
    }

    [Fact]
    public void Delete_NullArgument_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();
        Assert.Throws<ArgumentNullException>(() => known.Delete(null!));
    }

    // ── Dispose ──────────────────────────────────────────────────────

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var known = new SshKnownHosts();
        known.Dispose();
        known.Dispose();
    }

    [Fact]
    public void Dispose_ClearsEntriesSoSubsequentGetFirstThrows()
    {
        var known = new SshKnownHosts();
        AddPlain(known, "h");
        known.Dispose();

        // Even before checking ObjectDisposedException, the list is gone.
        Assert.Throws<ObjectDisposedException>(() => known.GetFirst());
    }

    // ── KnownHostCheckResult record ──────────────────────────────────

    [Fact]
    public void KnownHostCheckResult_CapturesStatusAndMatched()
    {
        var entry = new SshKnownHostEntry(
            "h", null, "AQID", SshKnownHostKeyType.SshRsa, SshKnownHostFormat.Plain, null);

        var match = new SshKnownHostCheckResult(SshKnownHostCheckStatus.Match, entry);
        var miss = new SshKnownHostCheckResult(SshKnownHostCheckStatus.NotFound, null);

        Assert.Equal(SshKnownHostCheckStatus.Match, match.Status);
        Assert.Same(entry, match.Matched);
        Assert.Null(miss.Matched);
    }

    // ── Enum value parity with libssh2.h ─────────────────────────────

    [Fact]
    public void KnownHostCheckStatus_NumericValues_MatchLibssh2Constants()
    {
        // libssh2.h:1218-1221: MATCH=0, MISMATCH=1, NOTFOUND=2, FAILURE=3.
        Assert.Equal(0, (int)SshKnownHostCheckStatus.Match);
        Assert.Equal(1, (int)SshKnownHostCheckStatus.Mismatch);
        Assert.Equal(2, (int)SshKnownHostCheckStatus.NotFound);
        Assert.Equal(3, (int)SshKnownHostCheckStatus.Failure);
    }

    [Fact]
    public void KnownHostFileType_OpenSsh_IsOne()
    {
        // libssh2.h:1281: LIBSSH2_KNOWNHOST_FILE_OPENSSH = 1.
        Assert.Equal(1, (int)SshKnownHostFileType.OpenSsh);
    }

    [Fact]
    public void KnownHostFormat_ValuesMatchCTypeConstants()
    {
        // libssh2.h:1136-1138: PLAIN=1, SHA1=2, CUSTOM=3.
        Assert.Equal(1, (int)SshKnownHostFormat.Plain);
        Assert.Equal(2, (int)SshKnownHostFormat.Sha1);
        Assert.Equal(3, (int)SshKnownHostFormat.Custom);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static SshKnownHostEntry AddPlain(SshKnownHosts known, string host)
        => known.Add(
            host: host,
            salt: null,
            key: s_ed25519Key,
            keyType: SshKnownHostKeyType.SshRsa,
            format: SshKnownHostFormat.Plain);
}
