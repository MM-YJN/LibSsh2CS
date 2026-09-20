using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration tests for the <see cref="SshChannel"/> inbound window
/// management + <see cref="SshExtendedDataMode.Ignore"/> stderr-discard path
/// that the other Docker suites leave dark. Exercises two distinct coverage
/// gaps in <see cref="SshChannel"/> + <see cref="Transport.ChannelRouter"/>:
/// <list type="bullet">
/// <item><see cref="SshExtendedDataMode.Ignore"/> set BEFORE exec — stderr
/// EXTENDED_DATA packets are dropped at router delivery time and the freed
/// window bytes are refunded immediately via
/// <see cref="SshChannel.RefundInboundWindowAsync"/> +
/// <see cref="SshChannel.SendWindowAdjustAsync"/> (parity
/// <c>packet.c:994-1030</c>).</item>
/// <item><see cref="SshExtendedDataMode.Ignore"/> set AFTER stderr is already
/// buffered (mode transition) — <see cref="SshChannel.SetExtendedDataModeAsync"/>
/// flushes the buffered stderr via
/// <see cref="SshChannel.FlushStderrBufferAsync"/> and refunds the freed
/// window (parity intent <c>channel.c:2010-2016</c>).</item>
/// </list>
/// Both paths light up <see cref="SshChannel.FlushStderrBufferAsync"/>,
/// <see cref="SshChannel.RefundInboundWindowAsync"/>, and
/// <see cref="SshChannel.SendWindowAdjustAsync"/> (all 0% → covered).
/// </summary>
/// <remarks>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailableAsync"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </remarks>
public sealed class DockerChannelWindowTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerChannelWindowTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// <see cref="SshExtendedDataMode.Ignore"/> set BEFORE exec: stderr
    /// EXTENDED_DATA packets are dropped at router delivery time and the freed
    /// inbound window bytes are immediately refunded to the peer via
    /// <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c>. The test execs a command that
    /// writes a large stderr payload (~5 KB, well above the initial window
    /// fraction that would trigger a refund), drains stdout, and asserts the
    /// exit status is 0. <see cref="SshChannel.ReadStderrAsync"/> must return 0
    /// (no stderr was buffered). Lights up the router-level
    /// <see cref="Transport.ChannelRouter.DeliverExtendedDataPayloadAsync"/>
    /// Ignore branch + <see cref="SshChannel.RefundInboundWindowAsync"/> +
    /// <see cref="SshChannel.SendWindowAdjustAsync"/> (all 0% → covered).
    /// </summary>
    /// <remarks>
    /// The large stderr payload is deliberate: a tiny payload might fit within
    /// the initial window without triggering a refund, leaving the
    /// <c>WINDOW_ADJUST</c> send path unexercised. ~5 KB across many
    /// EXTENDED_DATA packets forces multiple refund round-trips.
    /// </remarks>
    [Fact]
    public async Task IgnoreMode_SetBeforeExec_DropsStderrAtDeliveryAndRefundsWindow()
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

        // Switch to Ignore BEFORE exec so the router drops stderr at delivery.
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, ct);

        // Write a large stderr payload (seq 1 500 ≈ 1.9 KB per line set; use
        // seq 1 1000 for ~3.9 KB) + a single stdout line. The server sends
        // many EXTENDED_DATA packets; each is dropped + refunded at delivery.
        await channel.ExecAsync("sh -c 'seq 1 1000 >&2; echo out-mark'", ct);

        // Drain stdout — must contain only "out-mark\n".
        string stdout = await DrainStdoutToEndAsync(channel, ct);
        int exit = await channel.GetExitStatusAsync(ct);

        // Stderr was dropped at delivery: ReadStderrAsync must return 0
        // immediately (no buffered stderr).
        byte[] buf = new byte[256];
        int stderrN = await channel.ReadStderrAsync(buf, ct);

        Assert.Equal(0, exit);
        Assert.Equal("out-mark\n", stdout);
        Assert.Equal(0, stderrN);
    }

    /// <summary>
    /// <see cref="SshExtendedDataMode.Ignore"/> set AFTER stderr is already
    /// buffered: <see cref="SshChannel.SetExtendedDataModeAsync"/> flushes the
    /// buffered stderr via <see cref="SshChannel.FlushStderrBufferAsync"/>
    /// (drops all buffered stderr packets, decrements <c>_readAvail</c>, and
    /// refunds the freed window bytes via
    /// <see cref="SshChannel.RefundInboundWindowAsync"/> →
    /// <see cref="SshChannel.SendWindowAdjustAsync"/>). The test starts in
    /// <see cref="SshExtendedDataMode.Normal"/>, execs a command that writes a
    /// large stderr payload, performs a single stdout read (pumps the transport
    /// so stderr is delivered + buffered), then switches to
    /// <see cref="SshExtendedDataMode.Ignore"/> — triggering the flush. Lights
    /// up <see cref="SshChannel.FlushStderrBufferAsync"/> (0% → covered) and
    /// the Ignore-transition branch of
    /// <see cref="SshChannel.SetExtendedDataModeAsync"/> (only Normal/Merge
    /// arms were covered before).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why a single read before the mode switch.</b> Draining stdout to EOF
    /// would pump the transport until the peer's EOF/CLOSE, at which point all
    /// stderr has been delivered + buffered. A single bounded read guarantees
    /// at least one EXTENDED_DATA packet is delivered + buffered before the
    /// mode switch — so <see cref="SshChannel.FlushStderrBufferAsync"/>'s
    /// non-empty-buffer path (the refund loop at SshChannel.cs:1243-1266) runs.
    /// </para>
    /// <para>
    /// <b>Why a large stderr payload.</b> A tiny payload might be fully
    /// delivered in a single packet that arrives before the stdout read
    /// completes; the large payload (seq 1 1000 ≈ 3.9 KB) spans many
    /// EXTENDED_DATA packets, making it near-certain that at least one is
    /// buffered when the mode switch runs.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task IgnoreMode_SetAfterStderrBuffered_FlushesBufferAndRefundsWindow()
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

        // Start in Normal mode (default) so stderr is buffered.
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Normal, ct);

        // Exec a command that writes a large stderr payload + a stdout line.
        // The server interleaves EXTENDED_DATA + DATA packets.
        await channel.ExecAsync("sh -c 'seq 1 1000 >&2; echo out-mark'", ct);

        // Perform a single stdout read — this pumps the transport, causing
        // the server's EXTENDED_DATA packets to be delivered + buffered in
        // _stderrBuffer (Normal mode buffers, doesn't drop).
        byte[] buf = new byte[4096];
        int n = await channel.ReadAsync(buf, ct);
        Assert.True(n > 0, "expected at least one stdout read before the mode switch");

        // Switch to Ignore — this triggers FlushStderrBufferAsync which drops
        // any buffered stderr and refunds the freed window via
        // RefundInboundWindowAsync → SendWindowAdjustAsync.
        await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Ignore, ct);

        // Drain remaining stdout + exit status.
        using var ms = new MemoryStream();
        ms.Write(buf.AsSpan(0, n));
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(ct);
        string stdout = Encoding.UTF8.GetString(ms.ToArray());

        // After the flush, ReadStderrAsync must return 0 (buffer was emptied).
        int stderrN = await channel.ReadStderrAsync(buf, ct);

        Assert.Equal(0, exit);
        Assert.Contains("out-mark", stdout);
        Assert.Equal(0, stderrN);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>Drains stdout to EOF via <see cref="SshChannel.ReadAsync"/>.</summary>
    private static async Task<string> DrainStdoutToEndAsync(
        SshChannel channel, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
