using System.Buffers.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.KnownHosts;

/// <summary>
/// Tests for <see cref="SshKnownHosts.ReadFileAsync"/> and
/// <see cref="SshKnownHosts.WriteFileAsync"/> — Phase 3 increment 3.1.6.
/// </summary>
/// <remarks>
/// Exercises the file IO pipeline: <c>ReadFile</c> → <see cref="SshKnownHosts.ReadLine"/>
/// → <see cref="SshKnownHosts.AddParsed"/>, and the reverse
/// <see cref="SshKnownHosts.GetFirst"/>/<see cref="SshKnownHosts.GetNext"/> →
/// <see cref="SshKnownHosts.WriteLine"/> → <c>WriteFile</c>.
/// </remarks>
public class KnownHostsFileTests
{
    private const string KeyBase64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEhLd7tZ3rV+fVj5wE2dFjJvKj8r4tZ1a2b3c4d5e6f7";

    // ── ReadFileAsync ────────────────────────────────────────────────

    [Fact]
    public async Task ReadFileAsync_MalformedFileAbortsTrustLoading()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "example.com\n", ct);
            using var known = new SshKnownHosts();
            await Assert.ThrowsAsync<SshException>(() => known.ReadFileAsync(path, cancellationToken: ct));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadFileAsync_PlainEntries_AddsAllToCollection()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path,
                $"example.com ssh-ed25519 {KeyBase64}\n" +
                $"other.com ssh-rsa {KeyBase64}\n", cancellationToken);

            using var known = new SshKnownHosts();
            int added = await known.ReadFileAsync(path, cancellationToken: cancellationToken);

            Assert.Equal(2, added);
            List<SshKnownHostEntry> entries = EnumerateAll(known);
            Assert.Equal(2, entries.Count);
            Assert.Equal("example.com", entries[0].Name);
            Assert.Equal(SshKnownHostKeyType.Ed25519, entries[0].KeyType);
            Assert.Equal("other.com", entries[1].Name);
            Assert.Equal(SshKnownHostKeyType.SshRsa, entries[1].KeyType);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadFileAsync_CommentsAndBlanksIgnored()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path,
                "# This is a comment\n" +
                "\n" +
                "   # indented comment\n" +
                $"example.com ssh-ed25519 {KeyBase64}\n", cancellationToken);

            using var known = new SshKnownHosts();
            int added = await known.ReadFileAsync(path, cancellationToken: cancellationToken);

            Assert.Equal(1, added);
            Assert.Single(EnumerateAll(known));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadFileAsync_EmptyFile_AddsNothing()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "", cancellationToken);

            using var known = new SshKnownHosts();
            int added = await known.ReadFileAsync(path, cancellationToken: cancellationToken);

            Assert.Equal(0, added);
            Assert.Null(known.GetFirst());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadFileAsync_CRLFLineEndings_ParsesCorrectly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // The parser strips trailing \r (handled by ReadLine's TrimEnd).
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path,
                $"example.com ssh-ed25519 {KeyBase64}\r\n" +
                $"other.com ssh-rsa {KeyBase64}\r\n", cancellationToken);

            using var known = new SshKnownHosts();
            int added = await known.ReadFileAsync(path, cancellationToken: cancellationToken);

            Assert.Equal(2, added);
            // Verify no \r leaked into the key.
            Assert.Equal(KeyBase64, known.GetFirst()!.Key);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadFileAsync_CommaHosts_ExpandsIntoMultipleEntries()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path,
                $"host1,host2,host3 ssh-ed25519 {KeyBase64}\n", cancellationToken);

            using var known = new SshKnownHosts();
            int added = await known.ReadFileAsync(path, cancellationToken: cancellationToken);

            Assert.Equal(3, added);
            Assert.Equal(3, EnumerateAll(known).Count);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadFileAsync_NonExistentFile_ThrowsFileNotFoundException()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var known = new SshKnownHosts();

        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            known.ReadFileAsync(Path.Combine(Path.GetTempPath(), "nonexistent_" + Guid.NewGuid() + ".txt"), cancellationToken: cancellationToken));
    }

    [Fact]
    public async Task ReadFileAsync_NullPath_ThrowsArgumentNullException()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var known = new SshKnownHosts();
        await Assert.ThrowsAsync<ArgumentNullException>(() => known.ReadFileAsync(null!, cancellationToken: cancellationToken));
    }

    // ── WriteFileAsync ───────────────────────────────────────────────

    [Fact]
    public async Task WriteFileAsync_WritesAllEntries()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            byte[] keyBytes = Base64.DecodeFromChars(KeyBase64);

            using var known = new SshKnownHosts();
            known.Add("host1.com", null, keyBytes, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain);
            known.Add("host2.com", null, keyBytes, SshKnownHostKeyType.SshRsa, SshKnownHostFormat.Plain);

            await known.WriteFileAsync(path, cancellationToken: cancellationToken);

            string written = await File.ReadAllTextAsync(path, cancellationToken);

            Assert.Equal(
                $"host1.com ssh-ed25519 {KeyBase64}\n" +
                $"host2.com ssh-rsa {KeyBase64}\n",
                written);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task WriteFileAsync_EmptyCollection_WritesEmptyFile()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            using var known = new SshKnownHosts();
            await known.WriteFileAsync(path, cancellationToken: cancellationToken);

            string written = await File.ReadAllTextAsync(path, cancellationToken);
            Assert.Equal(string.Empty, written);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ── Full round-trip: write → read → verify ──────────────────────

    [Fact]
    public async Task RoundTrip_WriteThenRead_PreservesEntries()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.GetTempFileName();
        try
        {
            byte[] keyBytes = Base64.DecodeFromChars(KeyBase64);

            // Write.
            using (var known = new SshKnownHosts())
            {
                known.Add("example.com", null, keyBytes, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain, "my key");
                known.Add("other.com", null, keyBytes, SshKnownHostKeyType.SshRsa, SshKnownHostFormat.Plain);
                await known.WriteFileAsync(path, cancellationToken: cancellationToken);
            }

            // Read back into a fresh collection.
            using var readBack = new SshKnownHosts();
            int added = await readBack.ReadFileAsync(path, cancellationToken: cancellationToken);

            Assert.Equal(2, added);
            List<SshKnownHostEntry> entries = EnumerateAll(readBack);
            Assert.Equal("example.com", entries[0].Name);
            Assert.Equal(SshKnownHostKeyType.Ed25519, entries[0].KeyType);
            Assert.Equal("my key", entries[0].Comment);
            Assert.Equal("other.com", entries[1].Name);
            Assert.Equal(SshKnownHostKeyType.SshRsa, entries[1].KeyType);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task RoundTrip_WriteReadByteIdentical()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        // Strongest parity check: write entries, read the file back as raw text,
        // and verify the content matches what WriteLine produces.
        string path = Path.GetTempFileName();
        try
        {
            byte[] keyBytes = Base64.DecodeFromChars(KeyBase64);

            using var known = new SshKnownHosts();
            known.Add("example.com", null, keyBytes, SshKnownHostKeyType.Ed25519, SshKnownHostFormat.Plain);
            await known.WriteFileAsync(path, cancellationToken: cancellationToken);

            string fileContent = await File.ReadAllTextAsync(path, cancellationToken);
            string expected = known.WriteLine(known.GetFirst()!, SshKnownHostFileType.OpenSsh);

            Assert.Equal(expected, fileContent);
        }
        finally
        {
            File.Delete(path);
        }
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
}
