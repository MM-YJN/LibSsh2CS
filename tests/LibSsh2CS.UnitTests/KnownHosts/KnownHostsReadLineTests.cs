using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Tests for <see cref="SshKnownHosts.ReadLine"/> — Phase 3 increment 3.1.4.
/// </summary>
/// <remarks>
/// Exercises every branch of the OpenSSH known_hosts line parser:
/// <c>hostline</c> (<c>knownhost.c:744-848</c>),
/// <c>oldstyle_hostline</c> (<c>knownhost.c:620-674</c>),
/// <c>hashed_hostline</c> (<c>knownhost.c:677-732</c>),
/// <c>libssh2_knownhost_readline</c> (<c>knownhost.c:878-948</c>).
/// </remarks>
public class KnownHostsReadLineTests
{
    // A realistic Ed25519 public key blob (base64-encoded). Not a real key —
    // just valid base64 that's long enough to pass the 20-char minimum.
    private const string Ed25519KeyBase64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEhLd7tZ3rV+fVj5wE2dFjJvKj8r4tZ1a2b3c4d5e6f7";
    private const string SshRsaKeyBase64 = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCryptoKeyDataForTestingPurposesOnly1234";

    // ── Basic parsing: single plain host + known key type ────────────

    [Fact]
    public void ReadLine_PlainHostEd25519_AddsEntryWithCorrectFields()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"example.com ssh-ed25519 {Ed25519KeyBase64}", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        Assert.Equal("example.com", entry!.Name);
        Assert.Equal(Ed25519KeyBase64, entry.Key);
        Assert.Equal(SshKnownHostKeyType.Ed25519, entry.KeyType);
        Assert.Equal(SshKnownHostFormat.Plain, entry.Format);
        Assert.Null(entry.Comment);
        Assert.Null(entry.KeyTypeName);
    }

    [Theory]
    [InlineData("ssh-rsa", SshKnownHostKeyType.SshRsa)]
    [InlineData("ssh-ed25519", SshKnownHostKeyType.Ed25519)]
    [InlineData("ecdsa-sha2-nistp256", SshKnownHostKeyType.Ecdsa256)]
    [InlineData("ecdsa-sha2-nistp384", SshKnownHostKeyType.Ecdsa384)]
    [InlineData("ecdsa-sha2-nistp521", SshKnownHostKeyType.Ecdsa521)]
    [InlineData("ssh-dss", SshKnownHostKeyType.SshDss)]
    public void ReadLine_KnownKeyType_MapsToEnum(string wireName, SshKnownHostKeyType expected)
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"h {wireName} {SshRsaKeyBase64}", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.Equal(expected, entry!.KeyType);
        Assert.Null(entry.KeyTypeName); // Known types don't store the wire name.
    }

    [Fact]
    public void ReadLine_UnknownKeyType_StoresTypeNameForRoundTrip()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"h sk-ssh-ed25519@openssh.com {Ed25519KeyBase64}", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.Equal(SshKnownHostKeyType.Unknown, entry!.KeyType);
        Assert.Equal("sk-ssh-ed25519@openssh.com", entry.KeyTypeName);
    }

    // ── Comma-separated hosts ────────────────────────────────────────

    [Fact]
    public void ReadLine_CommaSeparatedHosts_AddsEntryPerName()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host1,host2,host3 ssh-ed25519 {Ed25519KeyBase64}", SshKnownHostFileType.OpenSsh);

        var hosts = new List<string>();
        for (SshKnownHostEntry? e = known.GetFirst(); e is not null; e = known.GetNext(e))
        {
            hosts.Add(e.Name);
        }

        // Parity with knownhost.c:636-671 — the C parser scans the comma list
        // RIGHT-TO-LEFT, adding entries in reverse order. This matches the
        // upstream linked-list insertion sequence exactly.
        Assert.Equal(new[] { "host3", "host2", "host1" }, hosts);

        // All entries share the same key.
        foreach (SshKnownHostEntry? e in known.GetFirst() is { } first
            ? EnumerateFrom(known, first)
            : Enumerable.Empty<SshKnownHostEntry>())
        {
            Assert.Equal(Ed25519KeyBase64, e.Key);
        }
    }

    [Fact]
    public void ReadLine_SingleHostInCommaList_WorksAsNormalEntry()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"lonely-host ssh-rsa {SshRsaKeyBase64}", SshKnownHostFileType.OpenSsh);

        Assert.Single(EnumerateAll(known));
        Assert.Equal("lonely-host", known.GetFirst()!.Name);
    }

    // ── Hashed hosts (|1|salt|hash) ──────────────────────────────────

    [Fact]
    public void ReadLine_HashedHost_AddsSha1EntryWithDecodedSalt()
    {
        using var known = new SshKnownHosts();

        // Generate a real HMAC-SHA1 hash for "example.com" with a known salt.
        byte[] salt = new byte[]
        {
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        };
        byte[] hash;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes("example.com"));
            hash = hmac.GetHashAndReset();
        }

        string saltB64 = Base64.EncodeToString(salt);
        string hashB64 = Base64.EncodeToString(hash);
        string line = $"|1|{saltB64}|{hashB64} ssh-ed25519 {Ed25519KeyBase64}";

        known.ReadLine(line, SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        Assert.Equal(SshKnownHostFormat.Sha1, entry!.Format);
        Assert.Equal(hashB64, entry.Name); // Hash stored as base64 text.
        Assert.Equal(salt, entry.Salt);    // Salt stored as raw bytes.
    }

    [Fact]
    public void ReadLine_HashedHost_ThenCheckMatches()
    {
        using var known = new SshKnownHosts();

        byte[] salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        byte[] hash;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes("myhost.example.org"));
            hash = hmac.GetHashAndReset();
        }

        // Construct a raw key that matches the one we'll check with.
        byte[] rawKey = new byte[32];
        rawKey[0] = 0x42;
        string line = $"|1|{Base64.EncodeToString(salt)}|{Base64.EncodeToString(hash)} ssh-ed25519 {Base64.EncodeToString(rawKey)}";

        known.ReadLine(line, SshKnownHostFileType.OpenSsh);

        // The parsed entry should match a Check for the plaintext hostname.
        SshKnownHostCheckResult result = known.Check("myhost.example.org", rawKey, SshKnownHostKeyType.Ed25519);
        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
    }

    [Fact]
    public void ReadLine_HashedHostMalformed_SilentlySkipped()
    {
        // Parity with knownhost.c:730-731 — a hashed host without the second '|'
        // separator returns success without adding an entry.
        using var known = new SshKnownHosts();

        known.ReadLine("|1|noseparator ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI1234567890", SshKnownHostFileType.OpenSsh);

        Assert.Null(known.GetFirst());
    }

    // ── RSA1 keys ────────────────────────────────────────────────────

    [Fact]
    public void ReadLine_Rsa1Key_DetectedByDigitFirstChar()
    {
        using var known = new SshKnownHosts();

        // RSA1 key format: "host 65537 23456789..." (decimal modulus).
        // The 20-char minimum means we need at least 20 chars after the space.
        known.ReadLine("rsa1host.example.com 65537 23456789012345678901234567890", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        Assert.Equal(SshKnownHostKeyType.Rsa1, entry!.KeyType);
        // RSA1 stores the full key text (not base64).
        Assert.Equal("65537 23456789012345678901234567890", entry.Key);
        Assert.Null(entry.Comment);
    }

    // ── Comment handling ─────────────────────────────────────────────

    [Fact]
    public void ReadLine_WithComment_StoresCommentText()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host ssh-ed25519 {Ed25519KeyBase64} key from laptop", SshKnownHostFileType.OpenSsh);

        Assert.Equal("key from laptop", known.GetFirst()!.Comment);
    }

    [Fact]
    public void ReadLine_WithTrailingSpaceOnly_StoresEmptyComment()
    {
        // Parity with knownhost.c:818-820: a trailing space (no comment text)
        // produces an empty-string comment (distinct from null).
        using var known = new SshKnownHosts();

        known.ReadLine($"host ssh-ed25519 {Ed25519KeyBase64} ", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        Assert.NotNull(entry!.Comment);
        Assert.Equal(string.Empty, entry.Comment);
    }

    [Fact]
    public void ReadLine_NoComment_StoresNullComment()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host ssh-ed25519 {Ed25519KeyBase64}", SshKnownHostFileType.OpenSsh);

        Assert.Null(known.GetFirst()!.Comment);
    }

    [Fact]
    public void ReadLine_CommentWithLeadingMultipleSpaces_TrimsWhitespace()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host ssh-ed25519 {Ed25519KeyBase64}    multi-spaced comment", SshKnownHostFileType.OpenSsh);

        Assert.Equal("multi-spaced comment", known.GetFirst()!.Comment);
    }

    // ── No-op lines ──────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\t")]
    [InlineData("# this is a comment")]
    [InlineData("   # indented comment")]
    public void ReadLine_BlankOrCommentLine_NoOp(string line)
    {
        using var known = new SshKnownHosts();
        known.ReadLine(line, SshKnownHostFileType.OpenSsh);
        Assert.Null(known.GetFirst());
    }

    // ── Newline handling ─────────────────────────────────────────────

    [Fact]
    public void ReadLine_TrailingNewline_StrippedBeforeParsing()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host ssh-ed25519 {Ed25519KeyBase64}\n", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        // The key should not contain the trailing newline.
        Assert.Equal(Ed25519KeyBase64, entry!.Key);
    }

    [Fact]
    public void ReadLine_TrailingCRLF_StrippedBeforeParsing()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host ssh-ed25519 {Ed25519KeyBase64}\r\n", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        Assert.Equal(Ed25519KeyBase64, entry!.Key);
        Assert.Null(entry.Comment);
    }

    // ── Error cases ──────────────────────────────────────────────────

    [Fact]
    public void ReadLine_KeyTooShort_ThrowsMethodNotSupported()
    {
        using var known = new SshKnownHosts();

        Assert.Throws<SshException>(() =>
            known.ReadLine("host ssh-ed25519 short", SshKnownHostFileType.OpenSsh));
    }

    [Fact]
    public void ReadLine_MissingKey_ThrowsMethodNotSupported()
    {
        using var known = new SshKnownHosts();

        Assert.Throws<SshException>(() =>
            known.ReadLine("host ", SshKnownHostFileType.OpenSsh));
    }

    [Fact]
    public void ReadLine_UnsupportedFileType_ThrowsMethodNotSupported()
    {
        using var known = new SshKnownHosts();

        Assert.Throws<SshException>(() =>
            known.ReadLine("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI1234", (SshKnownHostFileType)99));
    }

    [Fact]
    public void ReadLine_Disposed_ThrowsObjectDisposedException()
    {
        var known = new SshKnownHosts();
        known.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            known.ReadLine("h ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI1234", SshKnownHostFileType.OpenSsh));
    }

    // ── Tab-separated fields ─────────────────────────────────────────

    [Fact]
    public void ReadLine_TabSeparatedFields_ParsesCorrectly()
    {
        using var known = new SshKnownHosts();

        known.ReadLine($"host\tssh-ed25519\t{Ed25519KeyBase64}", SshKnownHostFileType.OpenSsh);

        SshKnownHostEntry? entry = known.GetFirst();
        Assert.NotNull(entry);
        Assert.Equal("host", entry!.Name);
        Assert.Equal(Ed25519KeyBase64, entry.Key);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static List<SshKnownHostEntry> EnumerateAll(SshKnownHosts known)
    {
        var result = new List<SshKnownHostEntry>();
        SshKnownHostEntry? e = known.GetFirst();
        while (e is not null)
        {
            result.Add(e);
            e = known.GetNext(e);
        }

        return result;
    }

    private static IEnumerable<SshKnownHostEntry> EnumerateFrom(SshKnownHosts known, SshKnownHostEntry first)
    {
        SshKnownHostEntry? e = first;
        while (e is not null)
        {
            yield return e;
            e = known.GetNext(e);
        }
    }
}
