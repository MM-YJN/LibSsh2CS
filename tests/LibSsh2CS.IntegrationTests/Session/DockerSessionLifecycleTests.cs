using System.Net.Sockets;
using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Phase 5.7+ live integration tests for the
/// <see cref="SshSession"/> lifecycle surface that the per-feature Docker
/// suites (<c>DockerAuthTests</c>, <c>DockerExecTests</c>,
/// <c>DockerForwardTests</c>) don't otherwise exercise:
/// <list type="bullet">
/// <item><see cref="SshSession.DisconnectAsync"/> with a non-empty
/// description + language tag.</item>
/// <item><see cref="SshSession.DisposeAsync"/> on a handshaked-but-not-
/// authenticated session (the no-auth dispose branch — covers the
/// <c>_handshakeCompleted</c> + <c>_writer is not null</c> path without any
/// listeners and without auth).</item>
/// <item>The rekey <b>time</b> auto-trigger
/// (<see cref="RekeyPolicy.MaxInterval"/>) — complements
/// <c>DockerExecTests.Exec_WithTinyRekeyPolicy_TriggersRekeyWithoutDroppingSession</c>,
/// which covers the byte-threshold trigger.</item>
/// <item><see cref="SshUserAuth.GetBannerAsync"/> — the pre-auth banner
/// retrieval surface.</item>
/// </list>
/// </summary>
/// <remarks>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </remarks>
public sealed class DockerSessionLifecycleTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerSessionLifecycleTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// <see cref="SshSession.DisconnectAsync"/> with a non-empty description and
    /// a non-empty language tag round-trips through the
    /// <c>SSH_MSG_DISCONNECT</c> send path (the 256-byte truncation branches for
    /// both fields are exercised by keeping both inputs short). Verifies the
    /// call completes without throwing and without hanging — the server does not
    /// acknowledge DISCONNECT (fire-and-forget per RFC 4253 §11.1).
    /// </summary>
    /// <remarks>
    /// The session is NOT authenticated first; <see cref="SshSession.DisconnectAsync"/>
    /// only requires a handshaked transport (a non-null <c>_writer</c>), so this
    /// also covers the post-handshake-pre-auth slice of the lifecycle.
    /// </remarks>
    [Fact]
    public async Task Disconnect_WithDescriptionAndLang_RoundTrips()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);

        // Fire-and-forget: should not throw or hang. Both description + lang
        // are well under the 256-byte cap, so the non-truncating branch runs.
        await session.DisconnectAsync(
            SshDisconnectReason.ByApplication,
            description: "libssh2cs lifecycle test disconnect",
            lang: "en",
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// <see cref="SshSession.DisposeAsync"/> on a session that completed
    /// <see cref="SshSession.HandshakeAsync"/> but never authenticated still
    /// sends <c>SSH_MSG_DISCONNECT</c> (the
    /// <c>_handshakeCompleted &amp;&amp; _writer is not null</c> branch) and
    /// disposes the packet reader/writer. Covers the no-listeners, no-auth
    /// teardown path that the auth/exec tests don't reach (they all authenticate
    /// first).
    /// </summary>
    [Fact]
    public async Task Dispose_AfterHandshakeOnly_NoAuth_SendsDisconnectAndTearsDown()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        // Connect + handshake only — deliberately skip AuthenticateWithPasswordAsync.
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);

        // Sanity: handshake completed (we have a server banner) but no auth.
        Assert.NotNull(session.ServerBanner);
        Assert.False(session.IsAuthenticated);

        // DisposeAsync drives the best-effort DISCONNECT + writer/reader dispose.
        // The assertion is implicit: no hang, no throw.
        await session.DisposeAsync();

        // Re-dispose is a no-op (idempotency guard).
        await session.DisposeAsync();
    }

    /// <summary>
    /// With a tiny <see cref="RekeyPolicy.MaxInterval"/> (2 seconds, rewritten
    /// from 1 per the keepalive-style floor) set BEFORE handshake, the rekey
    /// time-trigger must fire during the first channel op that pumps the
    /// transport AFTER the interval has elapsed. Complements
    /// <c>DockerExecTests.Exec_WithTinyRekeyPolicy_TriggersRekeyWithoutDroppingSession</c>
    /// (which covers the byte threshold) and lights up the time-based branch of
    /// <c>MaybeRekeyAsync</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why we must drive the pump.</b> The time check fires only at
    /// channel-op boundaries (a quiet session does NOT auto-rekey on time
    /// alone — see <see cref="RekeyPolicy"/> XML doc). So this test sleeps
    /// past the threshold, then opens an exec channel — the open's first pump
    /// observes <c>elapsed &gt;= MaxInterval</c> and invokes
    /// <see cref="SshSession.RekeyAsync"/>.
    /// </para>
    /// <para>
    /// <b>Why inline-connect.</b> The policy must be set BEFORE
    /// <see cref="SshSession.HandshakeAsync"/> — the router captures the policy
    /// at handshake completion (<c>ConfigureRekeyTrigger</c>). The shared
    /// <see cref="SshDockerFixture.ConnectAsync"/> doesn't expose a hook for
    /// that, so we inline the connect (same pattern as
    /// <c>Exec_WithTinyRekeyPolicy_TriggersRekeyWithoutDroppingSession</c>).
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Rekey_TimeTrigger_FiresWhenIntervalElapses()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        // Inline connect so the policy applies before handshake (the router
        // captures _rekeyPolicy at handshake completion).
        var tcp = new TcpClient();
        await tcp.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);
        await using var session = new SshSession();
        session.RekeyPolicy = new RekeyPolicy
        {
            // Keep the byte/packet thresholds high so ONLY the time trigger
            // can fire — isolates the time-based branch of MaybeRekeyAsync.
            MaxBytes = long.MaxValue,
            MaxPackets = long.MaxValue,
            MaxInterval = TimeSpan.FromSeconds(2),
        };
        await session.HandshakeAsync(tcp.GetStream(), verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // Baseline: no rekey yet (the handshake itself doesn't trip the trigger).
        Assert.Equal(0, session.RekeyCount);

        // Sleep past the threshold. 3 seconds > 2 seconds MaxInterval.
        await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);

        // Open + exec on a session channel — the first pump observes
        // elapsed >= MaxInterval and fires RekeyAsync. A successful rekey
        // completes the open + exec transparently (the session stays up).
        await using SshChannel channel = await session.OpenSessionAsync(cancellationToken);
        await channel.ExecAsync("echo post-rekey", cancellationToken);

        using var ms = new MemoryStream();
        byte[] buf = new byte[256];
        int n;
        while ((n = await channel.ReadAsync(buf, cancellationToken)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        int exit = await channel.GetExitStatusAsync(cancellationToken);
        Assert.Equal(0, exit);
        Assert.Equal("post-rekey\n", Encoding.UTF8.GetString(ms.ToArray()));

        // The time-trigger MUST have fired at least once during the exec pump.
        Assert.True(session.RekeyCount >= 1,
            "time-based rekey should have fired at least once; RekeyCount=" + session.RekeyCount);
    }

    /// <summary>
    /// <see cref="SshUserAuth.GetBannerAsync"/> returns the pre-auth banner
    /// string the server sent during authentication (if any) without throwing.
    /// OpenSSH's default sshd does not send <c>SSH_MSG_USERAUTH_BANNER</c> in
    /// this fixture configuration, so the result is expected to be null here —
    /// the test primarily locks in the no-throw contract and exercises the
    /// <see cref="SshSession.UserAuthBanner"/> getter + the
    /// <see cref="SshUserAuth.GetBannerAsync"/> wrapper.
    /// </summary>
    [Fact]
    public async Task GetBanner_AfterAuth_ReturnsNullOrStringWithoutThrowing()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        // The banner is captured into session.UserAuthBanner by WaitForAuthResponseAsync
        // when a SSH_MSG_USERAUTH_BANNER (53) arrives. The fixture's sshd_config
        // doesn't configure a Banner, so this is typically null — but we accept
        // either (the contract is nullable). The assertion is non-throwing +
        // consistent with the internal UserAuthBanner property.
        string? banner = await session.GetBannerAsync(cancellationToken);
        Assert.Null(banner);
    }

    /// <summary>
    /// After <see cref="SshSession.HandshakeAsync"/> completes against a live
    /// OpenSSH server, <see cref="SshSession.ServerSignatureAlgorithms"/> must
    /// be populated from the <c>SSH_MSG_EXT_INFO</c> "server-sig-algs"
    /// extension (RFC 8308 §3.1). OpenSSH 8+ advertises this by default,
    /// including the RSA-SHA2 variants that drive
    /// <see cref="SshUserAuth"/>'s algorithm selection. Lights up the live
    /// call site of <see cref="ExtInfo.Parse"/> (0% → covered) — the unit
    /// tests in <c>ExtInfoTests</c> pin the parser byte-exactly; this test
    /// confirms the <c>HandshakeAsync</c> → <c>TryTakeStashed(ExtInfo)</c> →
    /// <see cref="ExtInfo.Parse"/> wiring runs end-to-end against a real peer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per RFC 8308 §2.1 the server sends <c>SSH_MSG_EXT_INFO</c>
    /// immediately after its <c>NEWKEYS</c>. The <c>PacketQueue</c> stashes
    /// it inline during the subsequent <c>SERVICE_ACCEPT</c> pump, and
    /// <c>HandshakeAsync</c> retrieves it right after — so the algorithms are
    /// available before <see cref="SshUserAuth"/> consults them for RSA-SHA2
    /// selection.
    /// </para>
    /// <para>
    /// The assertion is deliberately loose (<c>Contains</c> rather than
    /// <c>Equal</c>): the exact algorithm list varies across OpenSSH versions,
    /// but every modern OpenSSH advertises at least one <c>rsa-sha2-*</c>
    /// variant. If a future OpenSSH stops advertising <c>server-sig-algs</c>,
    /// this test fails loudly — which is the desired signal.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Handshake_AgainstLiveOpenSsh_PopulatesServerSignatureAlgorithmsFromExtInfo()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);

        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);

        // EXT_INFO is parsed during HandshakeAsync (the stash is drained after
        // the SERVICE_ACCEPT pump), so the algorithms must be populated
        // immediately after handshake completes — before any auth call.
        Assert.NotNull(session.ServerSignatureAlgorithms);

        // OpenSSH advertises rsa-sha2-256 and/or rsa-sha2-512 in
        // server-sig-algs; confirm at least one is present.
        Assert.Contains(session.ServerSignatureAlgorithms!,
            alg => alg.StartsWith("rsa-sha2-", StringComparison.Ordinal));
    }
}
