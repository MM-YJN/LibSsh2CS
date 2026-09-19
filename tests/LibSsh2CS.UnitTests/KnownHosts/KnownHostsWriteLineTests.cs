using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Tests for <see cref="SshKnownHosts.WriteLine"/> and ReadLine → WriteLine
/// round-trip parity — Phase 3 increment 3.1.5.
/// </summary>
/// <remarks>
/// Mirrors the eight sub-format branches of <c>knownhost_writeline</c>
/// (<c>knownhost.c:1003-1166</c>) and verifies that a parsed known_hosts line
/// round-trips through WriteLine to produce byte-identical output.
/// </remarks>
public class KnownHostsWriteLineTests
{
    private const string KeyBase64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEhLd7tZ3rV+fVj5wE2dFjJvKj8r4tZ1a2b3c4d5e6f7";

    // ── WriteLine: basic format variants ─────────────────────────────

    [Fact]
    public void WriteLine_PlainEntryWithKeyType_ProducesCorrectLine()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "example.com", KeyBase64, SshKnownHostKeyType.Ed25519);

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        Assert.Equal($"example.com ssh-ed25519 {KeyBase64}\n", line);
    }

    [Fact]
    public void WriteLine_PlainEntryWithComment_IncludesComment()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = known.Add(
            host: "example.com",
            salt: null,
            key: Base64.DecodeFromChars(KeyBase64),
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Plain,
            comment: "my work key");

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        Assert.Equal($"example.com ssh-ed25519 {KeyBase64} my work key\n", line);
    }

    [Fact]
    public void WriteLine_PlainEntryWithEmptyComment_ProducesTrailingSpace()
    {
        // Parity with knownhost.c:1091-1092 — a non-null comment (even empty)
        // produces " key comment" with the separator space.
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = known.Add(
            host: "example.com",
            salt: null,
            key: Base64.DecodeFromChars(KeyBase64),
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Plain,
            comment: string.Empty);

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        // Trailing space before the newline — the "empty comment" marker.
        Assert.Equal($"example.com ssh-ed25519 {KeyBase64} \n", line);
    }

    [Fact]
    public void WriteLine_PlainEntryNullComment_NoTrailingSpace()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "example.com", KeyBase64, SshKnownHostKeyType.SshRsa);

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        Assert.Equal($"example.com ssh-rsa {KeyBase64}\n", line);
        Assert.DoesNotContain(" \n", line);
    }

    // ── WriteLine: all key type names ────────────────────────────────

    [Theory]
    [InlineData(SshKnownHostKeyType.SshRsa, "ssh-rsa")]
    [InlineData(SshKnownHostKeyType.SshDss, "ssh-dss")]
    [InlineData(SshKnownHostKeyType.Ecdsa256, "ecdsa-sha2-nistp256")]
    [InlineData(SshKnownHostKeyType.Ecdsa384, "ecdsa-sha2-nistp384")]
    [InlineData(SshKnownHostKeyType.Ecdsa521, "ecdsa-sha2-nistp521")]
    [InlineData(SshKnownHostKeyType.Ed25519, "ssh-ed25519")]
    public void WriteLine_KeyType_EmitsCorrectWireName(SshKnownHostKeyType keyType, string expectedName)
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "h", KeyBase64, keyType);

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        Assert.StartsWith($"h {expectedName} ", line);
    }

    // ── WriteLine: RSA1 ──────────────────────────────────────────────

    [Fact]
    public void WriteLine_Rsa1Entry_NoKeyTypeNameEmitted()
    {
        using var known = new SshKnownHosts();
        // RSA1 entries store the full key text (not base64). Use AddParsed to
        // avoid re-encoding.
        SshKnownHostEntry entry = known.AddParsed(
            host: "rsa1host",
            salt: null,
            base64Key: "65537 23456789012345678901234567890",
            keyType: SshKnownHostKeyType.Rsa1,
            format: SshKnownHostFormat.Plain,
            comment: null,
            keyTypeName: null);

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        // RSA1 has no key type name — format is "host key\n".
        Assert.Equal("rsa1host 65537 23456789012345678901234567890\n", line);
    }

    // ── WriteLine: Unknown key type ──────────────────────────────────

    [Fact]
    public void WriteLine_UnknownTypeWithStoredName_UsesStoredName()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = known.AddParsed(
            host: "h",
            salt: null,
            base64Key: KeyBase64,
            keyType: SshKnownHostKeyType.Unknown,
            format: SshKnownHostFormat.Plain,
            comment: null,
            keyTypeName: "sk-ssh-ed25519@openssh.com");

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        Assert.Equal($"h sk-ssh-ed25519@openssh.com {KeyBase64}\n", line);
    }

    [Fact]
    public void WriteLine_UnknownTypeWithoutStoredName_Throws()
    {
        using var known = new SshKnownHosts();
        // Manually construct an UNKNOWN entry with no KeyTypeName.
        SshKnownHostEntry entry = known.AddParsed(
            host: "h",
            salt: null,
            base64Key: KeyBase64,
            keyType: SshKnownHostKeyType.Unknown,
            format: SshKnownHostFormat.Plain,
            comment: null,
            keyTypeName: null);

        Assert.Throws<SshException>(() => known.WriteLine(entry, SshKnownHostFileType.OpenSsh));
    }

    // ── WriteLine: hashed entries ────────────────────────────────────

    [Fact]
    public void WriteLine_HashedEntry_ProducesPipeOneFormat()
    {
        using var known = new SshKnownHosts();

        byte[] salt = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd };
        byte[] rawKey = Base64.DecodeFromChars(KeyBase64);

        // Compute HMAC-SHA1 to get a realistic hash.
        byte[] hash;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes("example.com"));
            hash = hmac.GetHashAndReset();
        }

        string saltB64 = Base64.EncodeToString(salt);
        string hashB64 = Base64.EncodeToString(hash);

        SshKnownHostEntry entry = known.Add(
            host: hashB64,
            salt: salt,
            key: rawKey,
            keyType: SshKnownHostKeyType.Ed25519,
            format: SshKnownHostFormat.Sha1);

        string line = known.WriteLine(entry, SshKnownHostFileType.OpenSsh);

        Assert.Equal($"|1|{saltB64}|{hashB64} ssh-ed25519 {KeyBase64}\n", line);
    }

    // ── WriteLine: argument validation ───────────────────────────────

    [Fact]
    public void WriteLine_NullEntry_ThrowsArgumentNullException()
    {
        using var known = new SshKnownHosts();
        Assert.Throws<ArgumentNullException>(() => known.WriteLine(null!, SshKnownHostFileType.OpenSsh));
    }

    [Fact]
    public void WriteLine_UnsupportedFileType_Throws()
    {
        using var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "h", KeyBase64, SshKnownHostKeyType.Ed25519);

        Assert.Throws<SshException>(() => known.WriteLine(entry, (SshKnownHostFileType)99));
    }

    [Fact]
    public void WriteLine_Disposed_ThrowsObjectDisposedException()
    {
        var known = new SshKnownHosts();
        SshKnownHostEntry entry = AddPlain(known, "h", KeyBase64, SshKnownHostKeyType.Ed25519);
        known.Dispose();

        Assert.Throws<ObjectDisposedException>(() => known.WriteLine(entry, SshKnownHostFileType.OpenSsh));
    }

    // ── ReadLine → WriteLine round-trip ──────────────────────────────

    [Fact]
    public void RoundTrip_PlainEntryWithComment_ProducesIdenticalLine()
    {
        string original = $"example.com ssh-ed25519 {KeyBase64} work laptop\n";

        using var known = new SshKnownHosts();
        known.ReadLine(original, SshKnownHostFileType.OpenSsh);

        string written = known.WriteLine(known.GetFirst()!, SshKnownHostFileType.OpenSsh);

        Assert.Equal(original, written);
    }

    [Fact]
    public void RoundTrip_PlainEntryNoComment_ProducesIdenticalLine()
    {
        string original = $"example.com ssh-rsa {KeyBase64}\n";

        using var known = new SshKnownHosts();
        known.ReadLine(original, SshKnownHostFileType.OpenSsh);

        string written = known.WriteLine(known.GetFirst()!, SshKnownHostFileType.OpenSsh);

        Assert.Equal(original, written);
    }

    [Fact]
    public void RoundTrip_HashedEntry_ProducesIdenticalLine()
    {
        // Generate a realistic hashed entry.
        byte[] salt = new byte[] { 0x53, 0x39, 0x6b, 0x7a, 0xbb, 0x37, 0xa4, 0x4c };
        byte[] hash;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(Encoding.UTF8.GetBytes("myhost.example.org"));
            hash = hmac.GetHashAndReset();
        }

        string saltB64 = Base64.EncodeToString(salt);
        string hashB64 = Base64.EncodeToString(hash);
        string original = $"|1|{saltB64}|{hashB64} ssh-ed25519 {KeyBase64}\n";

        using var known = new SshKnownHosts();
        known.ReadLine(original, SshKnownHostFileType.OpenSsh);

        string written = known.WriteLine(known.GetFirst()!, SshKnownHostFileType.OpenSsh);

        Assert.Equal(original, written);
    }

    [Fact]
    public void RoundTrip_UnknownKeyType_PreservesOriginalName()
    {
        string original = $"host sk-ssh-ed25519@openssh.com {KeyBase64}\n";

        using var known = new SshKnownHosts();
        known.ReadLine(original, SshKnownHostFileType.OpenSsh);

        string written = known.WriteLine(known.GetFirst()!, SshKnownHostFileType.OpenSsh);

        Assert.Equal(original, written);
    }

    [Fact]
    public void RoundTrip_MultipleEntries_AllRoundTrip()
    {
        string[] originals =
        {
            $"host1 ssh-ed25519 {KeyBase64}\n",
            $"host2 ssh-rsa {KeyBase64} with comment\n",
            $"host3,host4 ssh-ed25519 {KeyBase64}\n",
        };

        using var known = new SshKnownHosts();
        foreach (string line in originals)
        {
            known.ReadLine(line, SshKnownHostFileType.OpenSsh);
        }

        // Collect written lines.
        var written = new List<string>();
        SshKnownHostEntry? e = known.GetFirst();
        while (e is not null)
        {
            written.Add(known.WriteLine(e, SshKnownHostFileType.OpenSsh));
            e = known.GetNext(e);
        }

        // host3,host4 expands into two entries (reverse insertion order).
        // Expected output order: host1, host2, host4, host3.
        Assert.Equal(4, written.Count);
        Assert.Equal($"host1 ssh-ed25519 {KeyBase64}\n", written[0]);
        Assert.Equal($"host2 ssh-rsa {KeyBase64} with comment\n", written[1]);
        Assert.Equal($"host4 ssh-ed25519 {KeyBase64}\n", written[2]);
        Assert.Equal($"host3 ssh-ed25519 {KeyBase64}\n", written[3]);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static SshKnownHostEntry AddPlain(SshKnownHosts known, string host, string base64Key, SshKnownHostKeyType keyType)
        => known.Add(
            host: host,
            salt: null,
            key: Base64.DecodeFromChars(base64Key),
            keyType: keyType,
            format: SshKnownHostFormat.Plain);
}
