namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Tests for <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType, SshKnownHostFormat)"/>
/// — Phase 3 increment 3.1.2: Plain and Custom stored formats (no SHA1 yet).
/// </summary>
/// <remarks>
/// <see cref="SshKnownHostFormat.Sha1"/>-stored entries (HMAC-SHA1 hostname hashing)
/// are delivered in increment 3.1.3 with their own test file. This file
/// exercises every other branch of <c>knownhost_check</c> (<c>knownhost.c:350-497</c>).
/// </remarks>
public class KnownHostsCheckTests
{
    // Distinct 32-byte placeholder keys so key-A != key-B at the byte level.
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

    // ── Plain stored + Plain input ───────────────────────────────────

    [Fact]
    public void Check_PlainHostMatchingKey_ReturnsMatch()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_PlainHostWrongKey_ReturnsMismatchWithBadkey()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_UnknownHost_ReturnsNotFoundWithNullMatched()
    {
        using var known = new SshKnownHosts();
        AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("other.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
        Assert.Null(result.Matched);
    }

    [Fact]
    public void Check_SameHostDifferentKeyType_ReturnsNotFoundNoBadkey()
    {
        // Parity with knownhost.c:459-461 — key-type mismatch does NOT register
        // as badkey. The C code only updates badkey inside the key-type-matched
        // branch. So asking for Ed25519 against an RSA-stored entry yields
        // NotFound (not Mismatch), even though the host matches.
        using var known = new SshKnownHosts();
        AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.SshRsa);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
        Assert.Null(result.Matched);
    }

    // ── Port handling: [host]:port form ──────────────────────────────

    [Fact]
    public void Check_WithPort_FindsBracketedEntry()
    {
        using var known = new SshKnownHosts();
        // Stored as "[example.com]:22" — what ssh-keygen writes for non-22 ports
        // (and what OpenSSH writes unconditionally for any port once seen).
        SshKnownHostEntry entry = AddPlain(known, "[example.com]:22", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_WithPort_FallsBackToPlainHost()
    {
        // When no [host]:port entry exists, the check falls back to plain host.
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_PortSpecificEntry_DoesNotMatchPlainOnlyCall()
    {
        // An entry stored as [host]:22 should NOT match a port-less Check
        // (the port-less check only tries the plain host form).
        using var known = new SshKnownHosts();
        AddPlain(known, "[example.com]:22", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    [Fact]
    public void Check_PortFormPreferredOverPlainForm()
    {
        // Two entries: [host]:22 with key-A, plain host with key-B. Asking for
        // [host]:22 with key-A should match the bracketed entry, not fall back.
        using var known = new SshKnownHosts();
        SshKnownHostEntry bracketed = AddPlain(known, "[example.com]:22", s_keyA, SshKnownHostKeyType.Ed25519);
        AddPlain(known, "example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(bracketed, result.Matched);
    }

    [Fact]
    public void Check_BadkeyFromBracketedForm_ResolvesOnPlainFallback()
    {
        // [host]:22 has key-A; plain host has key-B. Asking for [host]:22 with
        // key-C: the bracketed form yields a badkey (key mismatch), then the
        // plain form yields another badkey. The FIRST badkey (bracketed) wins.
        using var known = new SshKnownHosts();
        SshKnownHostEntry bracketed = AddPlain(known, "[example.com]:22", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyB, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
        Assert.Same(bracketed, result.Matched);
    }

    [Fact]
    public void Check_NegativePort_SkipsBracketedForm()
    {
        // port = -1 means "only check plain host" (parity with knownhost.c:384-387).
        using var known = new SshKnownHosts();
        AddPlain(known, "[example.com]:22", s_keyA, SshKnownHostKeyType.Ed25519);
        SshKnownHostEntry plain = AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", -1, s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(plain, result.Matched);
    }

    // ── SHA1 input rejected immediately ──────────────────────────────

    [Fact]
    public void Check_Sha1Input_ReturnsMismatchImmediately()
    {
        // Parity with knownhost.c:367-369 — hashed inputs are unsupported.
        using var known = new SshKnownHosts();
        AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check(
            "example.com",
            -1,
            s_keyA,
            SshKnownHostKeyType.Ed25519,
            inputFormat: SshKnownHostFormat.Sha1);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
        Assert.Null(result.Matched);
    }

    // ── Unknown keyType never matches ────────────────────────────────

    [Fact]
    public void Check_CallerKeyTypeUnknown_ReturnsNotFound()
    {
        // Parity with knownhost.c:459 — host_key_type == UNKNOWN means "never
        // compare keys". The host may match, but no key comparison occurs, so
        // no badkey is registered either.
        using var known = new SshKnownHosts();
        AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyA, SshKnownHostKeyType.Unknown);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
        Assert.Null(result.Matched);
    }

    // ── Multiple entries / badkey ordering ───────────────────────────

    [Fact]
    public void Check_FirstBadkeyWins()
    {
        // Two entries with the same host and key type but different keys.
        // Asking with yet another key: the first entry is remembered as badkey.
        using var known = new SshKnownHosts();
        SshKnownHostEntry first = AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);
        AddPlain(known, "example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        byte[] keyC = new byte[32];
        SshKnownHostCheckResult result = known.Check("example.com", keyC, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Mismatch, result.Status);
        Assert.Same(first, result.Matched);
    }

    [Fact]
    public void Check_MultipleKeyTypes_OnlyMatchingTypeCompared()
    {
        // Two entries for the same host: RSA with key-A, Ed25519 with key-B.
        // Asking for Ed25519 with key-B should match (RSA entry ignored).
        using var known = new SshKnownHosts();
        AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.SshRsa);
        SshKnownHostEntry ed = AddPlain(known, "example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(ed, result.Matched);
    }

    [Fact]
    public void Check_MatchClearsBadkeyFromEarlierMismatch()
    {
        // [host]:22 has Ed25519/key-A; plain host has Ed25519/key-B.
        // Asking for [host]:22 with key-B: bracketed form yields badkey=bracketed,
        // then plain form yields a full match. Result should be MATCH (badkey
        // cleared on full match — parity with knownhost.c:467).
        using var known = new SshKnownHosts();
        AddPlain(known, "[example.com]:22", s_keyA, SshKnownHostKeyType.Ed25519);
        SshKnownHostEntry plain = AddPlain(known, "example.com", s_keyB, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check("example.com", 22, s_keyB, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(plain, result.Matched);
    }

    // ── Custom stored + Custom input ─────────────────────────────────

    [Fact]
    public void Check_CustomInputCustomStored_MatchByStringEquality()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = known.Add(
            host: "deadbeefcafebabe",
            salt: null,
            key: s_keyA,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Custom);

        SshKnownHostCheckResult result = known.Check(
            "deadbeefcafebabe",
            s_keyA,
            SshKnownHostKeyType.Ed25519,
            inputFormat: SshKnownHostFormat.Custom);

        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.Same(entry, result.Matched);
    }

    [Fact]
    public void Check_CustomInputVsPlainStored_NoMatch()
    {
        // Format mismatch: Custom input only matches Custom stored entries.
        using var known = new SshKnownHosts();
        AddPlain(known, "example.com", s_keyA, SshKnownHostKeyType.Ed25519);

        SshKnownHostCheckResult result = known.Check(
            "example.com",
            s_keyA,
            SshKnownHostKeyType.Ed25519,
            inputFormat: SshKnownHostFormat.Custom);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    [Fact]
    public void Check_PlainInputVsCustomStored_NoMatch()
    {
        using var known = new SshKnownHosts();
        known.Add(
            host: "deadbeef",
            salt: null,
            key: s_keyA,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Custom);

        SshKnownHostCheckResult result = known.Check("deadbeef", s_keyA, SshKnownHostKeyType.Ed25519);

        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    // ── Argument validation / disposed ───────────────────────────────

    [Fact]
    public void Check_NullHost_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();
        Assert.Throws<ArgumentNullException>(() => known.Check(null!, s_keyA, SshKnownHostKeyType.Ed25519));
    }

    [Fact]
    public void Check_NullKey_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();
        Assert.Throws<ArgumentNullException>(() => known.Check("h", null!, SshKnownHostKeyType.Ed25519));
    }

    [Fact]
    public void Check_Disposed_ThrowsObjectDisposedException()
    {
        var known = new SshKnownHosts();
        known.Dispose();

        Assert.Throws<ObjectDisposedException>(() => known.Check("h", s_keyA, SshKnownHostKeyType.Ed25519));
    }

    [Fact]
    public void Check_EmptyCollection_ReturnsNotFound()
    {
        using var known = new SshKnownHosts();
        SshKnownHostCheckResult result = known.Check("h", s_keyA, SshKnownHostKeyType.Ed25519);
        Assert.Equal(SshKnownHostCheckStatus.NotFound, result.Status);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static SshKnownHostEntry AddPlain(SshKnownHosts known, string host, byte[] key, SshKnownHostKeyType keyType)
        => known.Add(
            host: host,
            salt: null,
            key: key,
            keyType: keyType,
            format: SshKnownHostFormat.Plain);
}
