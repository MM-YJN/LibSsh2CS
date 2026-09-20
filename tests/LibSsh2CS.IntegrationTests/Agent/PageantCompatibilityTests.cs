using System.Diagnostics;
using System.Runtime.Versioning;

using LibSsh2CS.Agent;

using Windows.Win32;
using Windows.Win32.Foundation;

namespace LibSsh2CS.IntegrationTests.Agent;

/// <summary>
/// Compatibility tests against a <b>real</b> Pageant executable, enabled only
/// when the environment explicitly opts in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Enablement.</b> Set <c>LIBSSH2CS_TEST_PAGEANT=1</c> to run these tests,
/// and optionally <c>LIBSSH2CS_PAGEANT_PATH</c> to point at a specific
/// <c>pageant.exe</c> (otherwise the default install location is used). With
/// the variable unset the tests skip; with it set they run and <b>fail</b> —
/// never silently skip — when a prerequisite is missing, so a CI job cannot go
/// green by accident.
/// </para>
/// <para>
/// <b>Why they need a dedicated machine or session.</b> Pageant decides whether
/// it is "already running" with <c>agent_exists()</c>, which on Windows is
/// <c>named_pipe_agent_exists() || wm_copydata_agent_exists()</c>
/// (<c>winpgntc.c</c>). The named-pipe probe looks at
/// <c>\\.\pipe\pageant.&lt;user&gt;.&lt;obfuscated&gt;</c>, which is
/// <b>session-wide rather than desktop-wide</b>, and a second launch with keys
/// on its command line forwards those keys to the instance that already
/// exists. A private desktop therefore does <i>not</i> isolate a test Pageant
/// from a real one. These tests handle that by refusing to start — with an
/// actionable message — whenever any agent is already present, which is why
/// they belong on a CI machine (or a freshly logged-on session) rather than a
/// developer desktop that has Pageant running.
/// </para>
/// <para>
/// <b>What they cover.</b> The real client path end to end: unmodified
/// <see cref="SshAgent"/> auto-discovery finds the real <c>Pageant</c> window,
/// and a <c>REQUEST_IDENTITIES</c> round trip crosses real cross-process
/// <c>WM_COPYDATA</c> marshalling and a real shared-mapping hand-off. No key
/// material is involved: the fixture Pageant starts with an empty key list, so
/// nothing here can leak a key into anything. Sign coverage needs an
/// unencrypted <c>.ppk</c> fixture loaded on the command line; see the note in
/// the repository's development docs before adding one.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public class PageantCompatibilityTests
{
    private const string EnableVariable = "LIBSSH2CS_TEST_PAGEANT";
    private const string PathVariable = "LIBSSH2CS_PAGEANT_PATH";

    [Fact]
    public async Task RealPageant_FreshInstance_IsDiscoveredAndServesRequests()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Real Pageant requires Windows.");
        }

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        if (!IsEnabled())
        {
            Assert.Skip($"Set {EnableVariable}=1 to run the real-Pageant compatibility tests.");
        }

        // Enabled: every prerequisite problem below is a hard failure.

        string executable = ResolvePageantExecutable();
        AssertAgentNotAlreadyRunning();

        using Process pageant = Process.Start(new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException($"Could not start '{executable}'.");

        try
        {
            nint window = await WaitForPageantWindowAsync(pageant, cancellationToken);

            // The window the client will find must belong to the instance we
            // started; otherwise the assertions below would be describing
            // somebody else's agent.
            Assert.Equal((uint)pageant.Id, PageantNative.GetWindowProcessId(window));

            // Unmodified auto-discovery: no socket path, no injected transport.
            await using var agent = new SshAgent();
            Assert.Null(agent.IdentityPath);

            await agent.ConnectAsync(cancellationToken);
            Assert.True(agent.IsConnected);

            // A fresh Pageant holds no keys, so the identities answer must be
            // empty — which also demonstrates the response crossed the mapping
            // intact rather than being a leftover buffer.
            IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);
            Assert.Empty(identities);

            // Several transactions on one connection: the mapping is created
            // and released per request, and the client must remain usable.
            Assert.Empty(await agent.ListIdentitiesAsync(cancellationToken));
        }
        finally
        {
            KillProcess(pageant);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Prerequisites
    // ════════════════════════════════════════════════════════════════════════

    private static bool IsEnabled()
        => string.Equals(
            Environment.GetEnvironmentVariable(EnableVariable), "1", StringComparison.Ordinal);

    private static string ResolvePageantExecutable()
    {
        string? configured = Environment.GetEnvironmentVariable(PathVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return File.Exists(configured)
                ? configured
                : throw new FileNotFoundException(
                    $"{PathVariable} points at '{configured}', which does not exist.", configured);
        }

        string fallback = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PuTTY", "pageant.exe");

        return File.Exists(fallback)
            ? fallback
            : throw new FileNotFoundException(
                $"No pageant.exe found at '{fallback}'. Install PuTTY or set {PathVariable}.");
    }

    /// <summary>
    /// Fails unless no agent is present, because starting a second Pageant
    /// while one exists would hand our fixture's keys (and our command line) to
    /// the existing instance instead of creating an isolated one.
    /// </summary>
    private static void AssertAgentNotAlreadyRunning()
    {
        nint existing = PageantNative.FindWindow("Pageant", "Pageant");
        Assert.True(existing == 0,
            "A 'Pageant' window already exists on this desktop. Close it (or run these tests in a " +
            "dedicated session) before enabling the real-Pageant compatibility tests.");

        string userName = Environment.UserName;
        var pipes = new List<string>();
        try
        {
            foreach (string pipe in Directory.EnumerateFiles(@"\\.\pipe\"))
            {
                string name = Path.GetFileName(pipe);
                if (name.StartsWith($"pageant.{userName}.", StringComparison.OrdinalIgnoreCase))
                {
                    pipes.Add(name);
                }
            }
        }
        catch (Exception ex)
        {
            Assert.Fail(
                $"Could not enumerate the named-pipe namespace to confirm no agent is running ({ex.Message}). " +
                "Refusing to start a real Pageant, because Pageant's own already-running check is " +
                "session-wide and could route fixture keys into an existing agent.");
        }

        Assert.True(pipes.Count == 0,
            "An SSH agent named pipe is already present for this user (" + string.Join(", ", pipes) + "). " +
            "Pageant treats that as 'already running' and would forward keys to it, so these tests refuse to run.");
    }

    private static async Task<nint> WaitForPageantWindowAsync(Process pageant, CancellationToken cancellationToken)
    {
        // Waits for the fixture's IPC window to appear, so a slow start is not
        // reported as a protocol failure.
        DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);

        while (true)
        {
            nint window = PageantNative.FindWindow("Pageant", "Pageant");
            if (window != 0)
            {
                return window;
            }

            if (pageant.HasExited)
            {
                Assert.Fail($"pageant.exe exited with code {pageant.ExitCode} before creating its IPC window.");
            }

            if (DateTime.UtcNow >= deadline)
            {
                Assert.Fail("pageant.exe did not create its IPC window within 30 seconds.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void KillProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(10_000);
            }
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Already reaped.
        }
    }

    /// <summary>
    /// The two lookups these tests need that the library deliberately keeps
    /// internal. Kept minimal on purpose: this is fixture plumbing, not a
    /// second implementation of the transport under test, so it calls the
    /// CsWin32-generated entry points rather than declaring any of its own.
    /// </summary>
    [SupportedOSPlatform("windows")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Platform Compatibility", "CA1416:Validate platform compatibility", Justification = "The generated entry points name the Windows version they first appeared in (5.0 for FindWindow, 5.1.2600 for GetWindowThreadProcessId). These tests only run on Windows and fail outright anywhere else, so those distinctions carry no information for fixture plumbing.")]
    private static class PageantNative
    {
        public static nint FindWindow(string className, string windowName)
            => PageantInterop.FindWindow(className, windowName);

        public static uint GetWindowProcessId(nint window)
        {
            _ = PageantInterop.GetWindowThreadProcessId((HWND)window, out uint processId);
            return processId;
        }
    }
}
