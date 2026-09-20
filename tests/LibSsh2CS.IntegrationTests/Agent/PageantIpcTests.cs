using System.Diagnostics;
using System.Runtime.Versioning;

using LibSsh2CS.Agent;

namespace LibSsh2CS.IntegrationTests.Agent;

/// <summary>
/// End-to-end tests for the Windows Pageant backend over real cross-process
/// window messages and file mappings, driven through
/// <see cref="PageantWindowChannel"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a separate process.</b> A window on the calling thread's own message
/// queue is called directly, so an in-process fake window would not exercise
/// cross-process marshalling, cancellation while the receiver is still working,
/// or the mapping hand-off. The fixture therefore runs <c>PageantTestHost</c>
/// as its own process and lets it serve requests the way Pageant does.
/// </para>
/// <para>
/// <b>Isolation from a real Pageant.</b> Every fixture registers a window class
/// named after a GUID, and the client under test is pointed at exactly that
/// class. Nothing here looks up, reads, or closes the <c>Pageant</c> window a
/// developer may have running, and the "no window" test asserts that a client
/// scoped to a missing class fails instead of falling back to it.
/// </para>
/// <para>
/// These tests need only Windows and a built test project — no PuTTY
/// installation, no Docker, no SSH server, and no user keys. The helper
/// program is an executable the integration test project builds and stages
/// next to the test assembly, so a focused <c>dotnet test --project …</c> run
/// works without a solution-wide build.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public class PageantIpcTests
{
    private const string IdentityComment = "pageant-test-host";

    [Fact]
    public async Task Pageant_ListIdentitiesAndSign_RoundTripOverRealIpc()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        await using PageantTestHost host = await PageantTestHost.StartAsync("normal", cancellationToken);

        await using var transport = new PageantAgentTransport(host.CreateChannel());
        await using var agent = new SshAgent(transport);

        await agent.ConnectAsync(cancellationToken);

        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);

        // Byte-exact comparison against the blobs the host reported at startup:
        // the request and the response both crossed a process boundary through
        // the shared mapping, and the host's encoding is independent of the
        // library's parser.
        SshAgentIdentity identity = Assert.Single(identities);
        Assert.Equal(host.ExpectedIdentityBlob, identity.Blob);
        Assert.Equal(IdentityComment, identity.Comment);

        byte[] signature = await agent.SignAsync(
            identity, new byte[] { 0x01, 0x02, 0x03 }, SshAgentSignFlags.None, cancellationToken);

        Assert.Equal(host.ExpectedSignatureBlob, signature);
    }

    /// <summary>
    /// A client scoped to a window class that does not exist must fail rather
    /// than silently connecting to some other agent — that is what keeps these
    /// tests off a developer's real Pageant, and what makes the backend's
    /// "failed connecting agent" error meaningful.
    /// </summary>
    [Fact]
    public async Task Pageant_NoMatchingWindow_FailsInsteadOfFindingAnotherAgent()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        string missingClass = $"LibSsh2CS-NoSuchPageant-{Guid.NewGuid():N}";
        await using var transport = new PageantAgentTransport(
            new PageantWindowChannel(missingClass, missingClass));

        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => transport.ConnectAsync(cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("failed connecting agent", ex.Message);
    }

    [Fact]
    public async Task Pageant_RejectedRequest_SurfacesAsAgentProtocolError()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        await using PageantTestHost host = await PageantTestHost.StartAsync("reject", cancellationToken);
        await using SshAgent agent = await ConnectAsync(host, cancellationToken);

        // Pageant answers a refused request by returning 0 without writing to
        // the mapping; the client must report that instead of parsing an
        // untouched buffer.
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => agent.ListIdentitiesAsync(cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("pageant rejected the request", ex.Message);
    }

    [Theory]
    [InlineData("overlong")]
    [InlineData("zero")]
    public async Task Pageant_UnusableResponseLength_IsRejected(string behavior)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        await using PageantTestHost host = await PageantTestHost.StartAsync(behavior, cancellationToken);
        await using SshAgent agent = await ConnectAsync(host, cancellationToken);

        // libssh2 would accept a response of up to PAGEANT_MAX_MSGLEN bytes
        // after the prefix (reading past the mapping) and would treat a
        // zero-length response as success (agent.c:394-410). Both are rejected.
        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => agent.ListIdentitiesAsync(cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("invalid response length", ex.Message);
    }

    /// <summary>
    /// Cancellation releases the waiting caller while the receiver is still
    /// inside its window procedure, and the shared mapping stays valid for that
    /// receiver afterwards: cleanup belongs to the worker that owns the send,
    /// not to the caller that stopped waiting.
    /// </summary>
    [Fact]
    public async Task Pageant_Cancellation_DoesNotInvalidateTheInFlightMapping()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        // The host blocks inside its window procedure for ten seconds before it
        // opens the mapping, so the cancel always lands while the request is in
        // flight.
        await using PageantTestHost host = await PageantTestHost.StartAsync(
            "hang", cancellationToken, hangMilliseconds: 10_000);
        await using SshAgent agent = await ConnectAsync(host, cancellationToken);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<IReadOnlyList<SshAgentIdentity>> transaction = agent.ListIdentitiesAsync(cts.Token);

        // Wait until Pageant is inside the handler: the message is delivered and
        // the mapping is what it will still reach for when the delay is over.
        await host.WaitForOutputLineAsync("HANGING", TimeSpan.FromSeconds(30), cancellationToken);

        long startedAt = Stopwatch.GetTimestamp();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transaction);
        TimeSpan elapsed = Stopwatch.GetElapsedTime(startedAt);

        // Generous ceiling: the point is that the caller is released by the
        // token, not by Pageant answering.
        Assert.True(elapsed < TimeSpan.FromSeconds(5), $"Cancellation took {elapsed}.");

        // The receiver is still inside its handler; its later access to the
        // shared mapping must succeed, which is what worker-owned cleanup buys.
        await host.WaitForOutputLineAsync("SERVED", TimeSpan.FromSeconds(30), cancellationToken);
    }

    /// <summary>
    /// A peer that never answers must not pin the caller forever: the bounded
    /// wait elapses and the transaction fails instead of blocking until the
    /// fixture exits. The receiver still holds the request at that point, so
    /// the shared mapping must stay valid until it finishes — the host's later
    /// access must succeed even though the caller has already given up. The
    /// client uses a short timeout so the test does not wait minutes;
    /// production uses
    /// <see cref="PageantAgentTransport.DefaultTransactionTimeout"/>.
    /// </summary>
    [Fact]
    public async Task Pageant_RequestTimesOut_ReportsAgentProtocolError()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        // The host stays inside its window procedure longer than the client is
        // willing to wait, so the request is in the receiver's hands when the
        // client gives up on it — and short enough that the test can wait for
        // the receiver to finish afterwards.
        await using PageantTestHost host = await PageantTestHost.StartAsync(
            "hang", cancellationToken, hangMilliseconds: 8_000);

        await using var transport = new PageantAgentTransport(
            host.CreateChannel(), TimeSpan.FromSeconds(1));
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        long startedAt = Stopwatch.GetTimestamp();
        Task<IReadOnlyList<SshAgentIdentity>> transaction = agent.ListIdentitiesAsync(cancellationToken);
        SshException ex = await Assert.ThrowsAsync<SshException>(() => transaction);
        TimeSpan elapsed = Stopwatch.GetElapsedTime(startedAt);

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("did not answer within 1000 ms", ex.Message);

        // Generous ceiling: the point is that the bounded wait ends the call on
        // its own, not that it elapses at an exact millisecond. The host is
        // still inside its handler (the message was delivered — it printed its
        // marker), so only the client-side bound can have released the caller.
        Assert.True(elapsed < TimeSpan.FromSeconds(30), $"The bounded wait took {elapsed}.");
        await host.WaitForOutputLineAsync("HANGING", TimeSpan.FromSeconds(30), cancellationToken);

        // The receiver is still inside its handler; its later access to the
        // shared mapping must succeed, which is what non-invalidating cleanup
        // buys. Pre-fix, the client had already released the mapping and this
        // line never arrives.
        await host.WaitForOutputLineAsync("SERVED", TimeSpan.FromSeconds(30), cancellationToken);
    }

    /// <summary>
    /// The window is looked up again for every transaction
    /// (<c>agent.c:362-364</c>), so a Pageant that is restarted mid-session is
    /// picked up without the caller reconnecting.
    /// </summary>
    [Fact]
    public async Task Pageant_RestartedMidSession_IsDiscoveredAgain()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfNotWindows();

        string windowClass = $"LibSsh2CS-Pageant-{Guid.NewGuid():N}";
        await using PageantTestHost first = await PageantTestHost.StartAsync(
            "normal", cancellationToken, windowClass);
        await using SshAgent agent = await ConnectAsync(first, cancellationToken);

        Assert.Single(await agent.ListIdentitiesAsync(cancellationToken));

        // Replace the agent behind the client's back: same window class, new
        // process.
        first.Kill();
        await using PageantTestHost second = await PageantTestHost.StartAsync(
            "normal", cancellationToken, windowClass);

        // No reconnect: the transport re-resolves the window per transaction.
        Assert.Single(await agent.ListIdentitiesAsync(cancellationToken));

        byte[] signature = await agent.SignAsync(
            (await agent.ListIdentitiesAsync(cancellationToken))[0],
            new byte[] { 0x09 },
            SshAgentSignFlags.None,
            cancellationToken);
        Assert.Equal(second.ExpectedSignatureBlob, signature);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    private static void SkipIfNotWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Pageant IPC tests require Windows.");
        }
    }

    private static async Task<SshAgent> ConnectAsync(
        PageantTestHost host, CancellationToken cancellationToken)
    {
        var transport = new PageantAgentTransport(host.CreateChannel());
        var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);
        return agent;
    }

    /// <summary>
    /// A running <c>PageantTestHost</c> fixture process: it owns a window whose
    /// class name is unique to this test, so the client under test can only ever
    /// reach this fixture.
    /// </summary>
    private sealed class PageantTestHost : IAsyncDisposable
    {
        private readonly Process _process;

        private PageantTestHost(
            Process process, string windowClass, byte[] expectedIdentityBlob, byte[] expectedSignatureBlob)
        {
            _process = process;
            WindowClass = windowClass;
            ExpectedIdentityBlob = expectedIdentityBlob;
            ExpectedSignatureBlob = expectedSignatureBlob;
        }

        public string WindowClass { get; }

        /// <summary>The key blob the host returns for <c>REQUEST_IDENTITIES</c>.</summary>
        public byte[] ExpectedIdentityBlob { get; }

        /// <summary>The signature blob the host returns for <c>SIGN_REQUEST</c>.</summary>
        public byte[] ExpectedSignatureBlob { get; }

        public static async Task<PageantTestHost> StartAsync(
            string behavior,
            CancellationToken cancellationToken,
            string? windowClass = null,
            int hangMilliseconds = 30_000)
        {
            string className = windowClass ?? $"LibSsh2CS-Pageant-{Guid.NewGuid():N}";
            string executable = ResolveHostExecutablePath();

            var startInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add("--class");
            startInfo.ArgumentList.Add(className);
            startInfo.ArgumentList.Add("--behavior");
            startInfo.ArgumentList.Add(behavior);
            startInfo.ArgumentList.Add("--hang-ms");
            startInfo.ArgumentList.Add(hangMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture));

            Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException($"Could not start {executable}.");

            try
            {
                string? ready = await process.StandardOutput.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (ready is null)
                {
                    // The host exits after reporting the reason on stderr.
                    await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                    string error = await process.StandardError.ReadToEndAsync(CancellationToken.None)
                        .ConfigureAwait(false);
                    throw new InvalidOperationException(
                        $"Pageant test host did not start (exit {process.ExitCode}): {error}");
                }

                // READY <class> <identityBlobB64> <signatureBlobB64>
                string[] fields = ready.Split(' ');
                if (fields.Length != 4 || fields[0] != "READY")
                {
                    throw new InvalidOperationException($"Unexpected host handshake: '{ready}'.");
                }

                Assert.Equal(className, fields[1]);

                return new PageantTestHost(
                    process,
                    className,
                    Convert.FromBase64String(fields[2]),
                    Convert.FromBase64String(fields[3]));
            }
            catch
            {
                KillProcess(process);
                throw;
            }
        }

        public PageantWindowChannel CreateChannel()
            => new(WindowClass, WindowClass);

        /// <summary>
        /// Reads the next standard-output line the host prints and asserts it
        /// starts with <paramref name="expectedPrefix"/>. Used to observe the
        /// hang behavior's handler progress.
        /// </summary>
        public async Task WaitForOutputLineAsync(
            string expectedPrefix, TimeSpan timeout, CancellationToken cancellationToken)
        {
            string? line = await _process.StandardOutput
                .ReadLineAsync(cancellationToken)
                .AsTask()
                .WaitAsync(timeout, cancellationToken)
                .ConfigureAwait(false);

            Assert.True(
                line is not null && line.StartsWith(expectedPrefix, StringComparison.Ordinal),
                $"Expected a host output line starting with '{expectedPrefix}', got '{line ?? "<end of stream>"}'.");
        }

        /// <summary>Stops the fixture process so its window disappears.</summary>
        public void Kill() => KillProcess(_process);

        public ValueTask DisposeAsync()
        {
            KillProcess(_process);
            _process.Dispose();
            return ValueTask.CompletedTask;
        }

        private static void KillProcess(Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(5_000);
                }
            }
            catch (InvalidOperationException)
            {
                // Already gone — the process object outlived the process.
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Already reaped by the OS.
            }
        }

        /// <summary>
        /// Locates the staged host executable. The integration test project
        /// declares the helper project as a build dependency and copies its app
        /// bundle into a <c>PageantTestHost</c> subdirectory of the test output,
        /// so the path is stable and a focused <c>dotnet test --project …</c>
        /// run stages it without a solution-wide build first.
        /// </summary>
        private static string ResolveHostExecutablePath()
        {
            string executable = Path.Combine(
                AppContext.BaseDirectory, "PageantTestHost", "PageantTestHost.exe");

            if (!File.Exists(executable))
            {
                throw new InvalidOperationException(
                    $"Pageant test host not staged at '{executable}'. " +
                    "Rebuild the integration test project (its StagePageantTestHost target copies the helper there).");
            }

            return executable;
        }
    }
}
