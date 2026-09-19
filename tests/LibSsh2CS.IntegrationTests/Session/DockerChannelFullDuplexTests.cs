using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration tests for channel concurrency: the per-channel
/// window / read-avail counters and the stdout/stderr FIFOs are mutated by the
/// cooperative pumper and by the channel's own read/write continuations on
/// different tasks. These tests drive the racing configurations against a REAL
/// OpenSSH server with multi-window data transfers, where both flow-control
/// directions (inbound <c>WINDOW_ADJUST</c>s from <c>EnsureInboundWindowAsync</c>,
/// outbound adjusts routed by the pumper while a <see cref="SshChannel.WriteAsync"/>
/// chunks a transfer larger than the peer's initial window) are exercised.
/// </summary>
/// <remarks>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/> calls
/// <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> internally, so tests
/// skip (not fail) when Docker is not reachable.
/// </remarks>
public sealed class DockerChannelFullDuplexTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerChannelFullDuplexTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Full-duplex stress against a real server: <c>exec cat</c> with a
    /// concurrent 4 MiB write (stdin) and read (echoed stdout) on the SAME
    /// channel. The write far exceeds the server's initial receive window, so
    /// it blocks on the pumper-routed <c>WINDOW_ADJUST</c>s while the read is
    /// concurrently draining inbound DATA and sending its own adjusts — the
    /// exact interleaving the C reference never sees. Verifies the echoed
    /// stream is byte-exact, the write completes, and the exit status is 0.
    /// </summary>
    [Fact]
    public async Task FullDuplex_ExecCat_FourMegabyteEcho_ByteExact()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);
        await channel.ExecAsync("cat", ct);

        const int TotalBytes = 4 * 1024 * 1024;
        byte[] payload = new byte[TotalBytes];
        for (int i = 0; i < TotalBytes; i++)
        {
            payload[i] = (byte)(i % 251);
        }

        // Writer: 16 KiB slices through the peer's window (chunked + adjusted).
        var writeTask = Task.Run(async () =>
        {
            const int SliceSize = 16 * 1024;
            for (int offset = 0; offset < TotalBytes; offset += SliceSize)
            {
                await channel.WriteAsync(
                    payload.AsMemory(offset, Math.Min(SliceSize, TotalBytes - offset)), ct);
            }

            // Tell cat no more input is coming so it flushes + exits.
            await channel.SendEofAsync(ct);
        }, ct);

        // Reader: drains the echo concurrently on a different task.
        byte[] received = await Task.Run(async () =>
        {
            using var ms = new MemoryStream();
            byte[] buf = new byte[32 * 1024];
            int got;
            while ((got = await channel.ReadAsync(buf, ct)) > 0)
            {
                await ms.WriteAsync(buf.AsMemory(0, got), ct);
            }

            return ms.ToArray();
        }, ct);

        await writeTask;
        Assert.Equal(TotalBytes, received.Length);
        Assert.Equal(payload, received);
        Assert.Equal(0, await channel.GetExitStatusAsync(ct));
    }

    /// <summary>
    /// Two concurrent readers on ONE channel (stdout + stderr), the
    /// "multiple waiters, shared window accounting" configuration: both
    /// readers drain concurrently, each read decrementing
    /// <c>_readAvail</c>/<c>_inboundWindow</c> while the pumper delivers
    /// interleaved DATA + EXTENDED_DATA. Verifies both streams complete
    /// byte-exact and the exit status is 0.
    /// </summary>
    [Fact]
    public async Task ConcurrentStdoutAndStderrReaders_BothStreamsComplete()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // ~9.7 KB per stream (seq 1 4000 = 4 digits + newline avg ≈ 2.43 B/line).
        await channel.ExecAsync("sh -c 'seq 1 4000; seq 1 4000 >&2'", ct);

        Task<string> stdoutTask = Task.Run(
            () => DrainStreamAsync((buf, token) => channel.ReadAsync(buf, token), ct), ct);
        Task<string> stderrTask = Task.Run(
            () => DrainStreamAsync((buf, token) => channel.ReadStderrAsync(buf, token), ct), ct);

        string stdout = await stdoutTask;
        string stderr = await stderrTask;

        Assert.Equal(ExpectedSeqOutput(4000), stdout);
        Assert.Equal(ExpectedSeqOutput(4000), stderr);
        Assert.Equal(0, await channel.GetExitStatusAsync(ct));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Drains a stream via repeated <paramref name="read"/> calls until one
    /// returns 0 (peer EOF with an empty buffer), returning the decoded UTF-8
    /// text.
    /// </summary>
    private static async Task<string> DrainStreamAsync(
        Func<byte[], CancellationToken, Task<int>> read, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[1024];
        int got;
        while ((got = await read(buf, ct)) > 0)
        {
            await ms.WriteAsync(buf.AsMemory(0, got), ct);
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>The exact output of <c>seq 1 count</c> (LF line endings).</summary>
    private static string ExpectedSeqOutput(int count)
    {
        var sb = new StringBuilder();
        for (int i = 1; i <= count; i++)
        {
            sb.Append(i).Append('\n');
        }

        return sb.ToString();
    }
}
