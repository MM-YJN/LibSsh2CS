using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Phase B live integration tests for known-hosts verification during the SSH
/// transport handshake. Probes a live OpenSSH server in Docker (via the
/// shared <see cref="AlpineNoKeySshImageFixture"/> assembly fixture) to
/// capture its host key, builds a <see cref="SshKnownHosts"/> collection,
/// round-trips it through a known_hosts file, then reconnects with a
/// <c>verifyHostKeyAsync</c> callback wired to
/// <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType, SshKnownHostFormat)"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why two connections to the same container.</b> The host keys are
/// baked into the assembly image at build time (via <c>ssh-keygen -A</c>),
/// so they are stable across container forks from the same image. Both the
/// probe and the verify connection target <c>(SshDockerFixture.Host,
/// container.Port)</c> from a single per-test container started via
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>.
/// </para>
/// <para>
/// <b>Coverage target.</b> Lights up <see cref="SshKnownHosts"/>'s
/// <see cref="SshKnownHosts.ReadLine"/>,
/// <see cref="SshKnownHosts.WriteLine(SshKnownHostEntry, SshKnownHostFileType)"/>,
/// <see cref="SshKnownHosts.ReadFileAsync"/>,
/// <see cref="SshKnownHosts.WriteFileAsync"/>,
/// <see cref="SshKnownHosts.Add(string, byte[]?, byte[], SshKnownHostKeyType, SshKnownHostFormat, string?)"/>,
/// and the three branches of
/// <see cref="SshKnownHosts.Check(string, int, byte[], SshKnownHostKeyType, SshKnownHostFormat)"/>
/// (Match / Mismatch / NotFound) — ~370 lines that are otherwise dark because
/// <see cref="SshDockerFixture.ConnectAsync"/> always skips hostkey verification.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerKnownHostsTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerKnownHostsTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Captures the server host key on a probe connection, builds a known_hosts
    /// file from it, round-trips the file through
    /// <see cref="SshKnownHosts.WriteFileAsync"/> +
    /// <see cref="SshKnownHosts.ReadFileAsync"/>, then reconnects with a
    /// <c>verifyHostKeyAsync</c> callback whose
    /// <see cref="SshKnownHosts.Check"/> returns
    /// <see cref="SshKnownHostCheckStatus.Match"/>. The second handshake must
    /// complete without throwing.
    /// </summary>
    [Fact]
    public async Task KnownHosts_MatchingEntry_HandshakeSucceeds()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        // ── Probe connection: capture the host key blob + its wire key-type ──
        // ConnectAsync skips hostkey verification (verifyHostKeyAsync: (_, _, _) => Task.FromResult(true)),
        // so the probe handshake completes purely on the cryptographic
        // signature check inside KeyExchange.RunExchangeAsync.
        byte[] hostKey;
        string hostKeyWireName;
        SshKnownHostKeyType knownType;
        await using (SshSession probe = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken))
        {
            hostKey = probe.HostKey.ToArray();
            (hostKeyWireName, knownType) = ReadHostKeyType(hostKey);
        }

        // ── Build a known_hosts line and round-trip it through a file ───────
        // Exercises WriteFileAsync + ReadFileAsync (the file-IO path) rather
        // than just the in-memory Add → Check loop.
        string b64 = Convert.ToBase64String(hostKey);
        string knownHostsLine = SshDockerFixture.Host + " " + hostKeyWireName + " " + b64 + "\n";

        string tmpFile = Path.Combine(Path.GetTempPath(), "libssh2cs-known-hosts-" + Guid.NewGuid().ToString("N"));
        using var knownHosts = new SshKnownHosts();
        try
        {
            // Writer instance: parses the line, writes the file, then disposes.
            using (var writer = new SshKnownHosts())
            {
                writer.ReadLine(knownHostsLine, SshKnownHostFileType.OpenSsh);
                await writer.WriteFileAsync(tmpFile, cancellationToken: cancellationToken);
            }

            // Reader / verify instance: reads the file back, used by the callback.
            int added = await knownHosts.ReadFileAsync(tmpFile, cancellationToken: cancellationToken);
            Assert.Equal(1, added);

            // ── Verify connection: verifyHostKeyAsync delegates to Check ────
            var tcp = new TcpClient();
            await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
            await using var session = new SshSession();
            await session.HandshakeAsync(
                tcp.GetStream(),
                verifyHostKeyAsync: (serverHostKey, _, _) =>
                {
                    SshKnownHostCheckResult result = knownHosts.Check(
                        SshDockerFixture.Host, port: -1, serverHostKey, knownType);
                    return Task.FromResult(result.Status == SshKnownHostCheckStatus.Match);
                },
                cancellationToken);

            Assert.False(session.HostKey.IsEmpty);
            Assert.Equal(hostKeyWireName, session.HostKeyAlgorithm);
        }
        finally
        {
            try
            {
                File.Delete(tmpFile);
            }
            catch
            {
                /* best-effort */
            }
        }
    }

    /// <summary>
    /// The stored entry has the right hostname + key type but a tampered key
    /// body (one byte flipped). The verify callback's
    /// <see cref="SshKnownHosts.Check"/> returns
    /// <see cref="SshKnownHostCheckStatus.Mismatch"/> (the badkey branch at
    /// <c>knownhost.c:474-477</c>), the callback returns false, and
    /// <see cref="SshSession.HandshakeAsync(Stream, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/>
    /// throws <see cref="SshException"/> with
    /// <see cref="SshErrorCode.KeyExchangeFailure"/>.
    /// </summary>
    /// <remarks>
    /// The tampered byte is the LAST byte of the blob, well past the key-type
    /// length-prefix + name string. This ensures the key TYPE still matches
    /// (driving Check into the badkey branch → Mismatch), not the earlier
    /// key-type-mismatch branch which does NOT register as badkey.
    /// </remarks>
    [Fact]
    public async Task KnownHosts_MismatchedKey_ThrowsKeyExchangeFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        byte[] hostKey;
        SshKnownHostKeyType knownType;
        await using (SshSession probe = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken))
        {
            hostKey = probe.HostKey.ToArray();
            (_, knownType) = ReadHostKeyType(hostKey);
        }

        // Tamper: clone + flip the last byte. The key-type prefix is preserved,
        // so Check's key-type gate passes and the comparison falls through to
        // the key-body mismatch (badkey) branch.
        byte[] tampered = (byte[])hostKey.Clone();
        tampered[^1] ^= 0xFF;

        using var knownHosts = new SshKnownHosts();
        knownHosts.Add(SshDockerFixture.Host, salt: null, tampered, knownType, SshKnownHostFormat.Plain);

        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await using var session = new SshSession();

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.HandshakeAsync(
                tcp.GetStream(),
                verifyHostKeyAsync: (serverHostKey, _, _) =>
                {
                    SshKnownHostCheckResult result = knownHosts.Check(
                        SshDockerFixture.Host, port: -1, serverHostKey, knownType);
                    return Task.FromResult(result.Status == SshKnownHostCheckStatus.Match);
                },
                cancellationToken));

        Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
    }

    /// <summary>
    /// An empty <see cref="SshKnownHosts"/> collection yields
    /// <see cref="SshKnownHostCheckStatus.NotFound"/> for any host. The verify
    /// callback returns false and <see cref="SshSession.HandshakeAsync"/> throws
    /// <see cref="SshException"/> with <see cref="SshErrorCode.KeyExchangeFailure"/>.
    /// </summary>
    /// <remarks>
    /// Exercises the third Check branch (no entry matches the hostname at all),
    /// rounding out the <see cref="SshKnownHostCheckStatus"/> coverage alongside
    /// the Match (positive) and Mismatch (badkey) tests.
    /// </remarks>
    [Fact]
    public async Task KnownHosts_EmptyCollection_ThrowsKeyExchangeFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        using var knownHosts = new SshKnownHosts();

        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await using var session = new SshSession();

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.HandshakeAsync(
                tcp.GetStream(),
                verifyHostKeyAsync: (serverHostKey, _, _) =>
                {
                    SshKnownHostCheckResult result = knownHosts.Check(
                        SshDockerFixture.Host, port: -1, serverHostKey, SshKnownHostKeyType.Ed25519);
                    return Task.FromResult(result.Status == SshKnownHostCheckStatus.Match);
                },
                cancellationToken));

        Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
    }

    /// <summary>
    /// Adds a SHA1-hashed (HMAC-SHA1) known_hosts entry for the live server's
    /// host key, then checks it against the plaintext hostname — exercising
    /// the <see cref="SshKnownHosts.HostHashMatches"/> path
    /// (<c>knownhost.c:416-446</c>) that the Plain/Match test above does NOT
    /// reach (the existing tests store the hostname in plaintext). Also
    /// round-trips the hashed entry through <see cref="SshKnownHosts.WriteLine"/>
    /// + <see cref="SshKnownHosts.ReadLine"/> (exercising
    /// <see cref="SshKnownHosts.ParseHashedHostLine"/>), and exercises
    /// <see cref="SshKnownHosts.Delete"/> + <see cref="SshKnownHosts.GetFirst"/>
    /// + <see cref="SshKnownHosts.GetNext"/> (all 0% under integration
    /// coverage before this test).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why a hashed entry.</b> OpenSSH's <c>HashKnownHosts yes</c> option
    /// stores hostnames as <c>|1|&lt;base64-salt&gt;|&lt;base64-hmac&gt;</c> so
    /// a leaked <c>known_hosts</c> file does not reveal which hosts were
    /// visited. The library's <c>Check</c> must recompute
    /// <c>HMAC-SHA1(salt, hostname)</c> and compare to the stored digest. This
    /// test verifies that round-trip end-to-end against a real server host key.
    /// </para>
    /// <para>
    /// <b>No new container needed.</b> The hashed-entry logic is pure
    /// client-side; the live server is only probed to capture a real host-key
    /// blob (so the test also validates a <c>Check</c> match against the real
    /// key, not a synthetic one). The verify handshake itself is NOT re-run
    /// (the Match/Mismatch/NotFound handshake tests above cover that path);
    /// this test focuses on the <c>Add</c> → <c>Check</c> → <c>WriteLine</c>
    /// → <c>ReadLine</c> → <c>Check</c> loop for hashed entries.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task KnownHosts_HashedEntry_CheckAndRoundTripSucceed()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        // Probe the live server to capture a real host-key blob + its wire
        // key type. The hashed-entry logic is client-side, but using a real
        // key exercises the full Check → HostHashMatches → FixedTimeEquals
        // path against a genuine key body.
        byte[] hostKey;
        SshKnownHostKeyType knownType;
        await using (SshSession probe = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken))
        {
            hostKey = probe.HostKey.ToArray();
            (_, knownType) = ReadHostKeyType(hostKey);
        }

        // A non-secret salt for the HMAC-SHA1 hash (any 20-byte value works;
        // OpenSSH uses a random salt, but the library does not require
        // randomness — only that the same salt accompanies the hash on disk).
        byte[] salt = new byte[20];
        RandomNumberGenerator.Fill(salt);

        using var knownHosts = new SshKnownHosts();

        // Add the entry in SHA1 (hashed) format. Add base64-encodes the key
        // internally; the host argument is the plaintext hostname that Add
        // will HMAC with the supplied salt. Wait — Add's Sha1 branch stores
        // the host as the pre-base64 hash TEXT, so we must compute the hash
        // ourselves to match the on-disk form. Actually, per the Add doc,
        // for Sha1 format the `host` parameter IS the base64-encoded HMAC
        // digest (the on-disk form after |1|salt|). So compute the hash now.
        string hashBase64 = ComputeHostHashBase64(SshDockerFixture.Host, salt);

        SshKnownHostEntry entry = knownHosts.Add(
            host: hashBase64,
            salt: salt,
            key: hostKey,
            keyType: knownType,
            format: SshKnownHostFormat.Sha1);

        // ── Check: plaintext host against the hashed entry must Match ──
        // This is the path that was 0% before: HostHashMatches recomputes
        // HMAC-SHA1(salt, "127.0.0.1") and compares to the stored digest.
        SshKnownHostCheckResult result = knownHosts.Check(
            SshDockerFixture.Host, port: -1, hostKey, knownType);
        Assert.Equal(SshKnownHostCheckStatus.Match, result.Status);
        Assert.NotNull(result.Matched);
        Assert.Same(entry, result.Matched);

        // ── WriteLine → ReadLine round-trip for the hashed entry ──
        // WriteLine must emit "|1|<base64-salt>|<base64-hash>" and ReadLine
        // must parse it back into a matching entry (exercising
        // ParseHashedHostLine, 0% before this test).
        string line = knownHosts.WriteLine(entry, SshKnownHostFileType.OpenSsh);
        Assert.StartsWith("|1|", line);

        using var reader = new SshKnownHosts();
        reader.ReadLine(line, SshKnownHostFileType.OpenSsh);

        SshKnownHostCheckResult roundTripped = reader.Check(
            SshDockerFixture.Host, port: -1, hostKey, knownType);
        Assert.Equal(SshKnownHostCheckStatus.Match, roundTripped.Status);

        // ── Iterate via GetFirst/GetNext (0% before this test) ──
        SshKnownHostEntry? first = reader.GetFirst();
        Assert.NotNull(first);
        Assert.Null(reader.GetNext(first));   // single entry → next is null

        // ── Delete the entry (0% before this test) ──
        Assert.True(reader.Delete(first));
        Assert.Null(reader.GetFirst());        // collection now empty
        Assert.False(reader.Delete(first));    // already removed → false
    }

    /// <summary>
    /// Computes <c>HMAC-SHA1(salt, host)</c> and returns the base64-encoded
    /// digest — the on-disk form that follows <c>|1|&lt;base64-salt&gt;|</c>
    /// in a hashed known_hosts line. Mirrors what
    /// <see cref="SshKnownHosts.HostHashMatches"/> expects to find stored in
    /// <see cref="SshKnownHostEntry.Name"/> for SHA1 entries.
    /// </summary>
    private static string ComputeHostHashBase64(string host, byte[] salt)
    {
        byte[] hostBytes = Encoding.UTF8.GetBytes(host);
        byte[] hash;
        using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, salt))
        {
            hmac.AppendData(hostBytes);
            hash = hmac.GetHashAndReset();
        }

        return Convert.ToBase64String(hash);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the first SSH string from the server host-key blob (the key-type
    /// wire name, e.g. <c>"ecdsa-sha2-nistp256"</c>) and maps it to its
    /// <see cref="SshKnownHostKeyType"/>. Used to build a known_hosts line
    /// without hardcoding the negotiated algorithm — the server's host-key blob
    /// type is whatever <c>ssh-keygen -A</c> produced and the client
    /// negotiated.
    /// </summary>
    /// <remarks>
    /// The blob's first string is the CANONICAL key type (<c>"ssh-rsa"</c>
    /// even when negotiated as <c>rsa-sha2-256</c>), which is exactly what
    /// known_hosts stores (parity with RFC 8332 §3.1).
    /// </remarks>
    private static (string WireName, SshKnownHostKeyType KeyType) ReadHostKeyType(byte[] hostKey)
    {
        if (hostKey.Length < 4)
        {
            throw new InvalidOperationException("Host key blob too short.");
        }

        // Blob layout: [u32 len][bytes name][rest of key...].
        int len = (int)BinaryPrimitives.ReadUInt32BigEndian(hostKey.AsSpan(0, 4));
        if (hostKey.Length < 4 + len)
        {
            throw new InvalidOperationException("Host key blob truncated.");
        }

        string wireName = Encoding.ASCII.GetString(hostKey, 4, len);
        return (wireName, WireNameToKnownHostKeyType(wireName));
    }

    /// <summary>
    /// Maps an SSH host-key wire name to its <see cref="SshKnownHostKeyType"/>.
    /// Mirrors the internal <c>SshHostKeyTypeRegistry.LookupByWireName</c> for
    /// the in-scope set the Docker fixture's sshd offers.
    /// </summary>
    private static SshKnownHostKeyType WireNameToKnownHostKeyType(string name) => name switch
    {
        "ssh-rsa" => SshKnownHostKeyType.SshRsa,
        "ssh-ed25519" => SshKnownHostKeyType.Ed25519,
        "ecdsa-sha2-nistp256" => SshKnownHostKeyType.Ecdsa256,
        "ecdsa-sha2-nistp384" => SshKnownHostKeyType.Ecdsa384,
        "ecdsa-sha2-nistp521" => SshKnownHostKeyType.Ecdsa521,
        "ssh-dss" => SshKnownHostKeyType.SshDss,
        _ => SshKnownHostKeyType.Unknown,
    };
}
