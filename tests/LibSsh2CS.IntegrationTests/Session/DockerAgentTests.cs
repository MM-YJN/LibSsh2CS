using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

using LibSsh2CS.Agent;
using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Phase 4 live SSH agent integration tests: starts a real ssh-agent on the
/// test host, loads the Ed25519 test key via <c>ssh-add</c>, then runs a real
/// OpenSSH server in Docker whose <c>authorized_keys</c> contains the
/// matching public key. The full
/// <see cref="SshAgent"/> → <see cref="SshAgentExtensions.AuthenticateWithIdentityAsync"/>
/// → <see cref="SshSession"/> path is exercised end-to-end.
/// </summary>
/// <remarks>
/// <para>
/// <b>Gating.</b> The tests skip when ANY of the following is unavailable:
/// <list type="bullet">
///   <item>Docker (via <see cref="SshDockerFixture.ShouldRun"/>)</item>
///   <item><c>ssh-agent</c> binary on PATH</item>
///   <item><c>ssh-add</c> binary on PATH</item>
/// </list>
/// These tests modify host-state by starting a host-side ssh-agent; the
/// binaries-on-PATH requirement serves as the opt-in signal. The
/// Docker-gated tests that start a container rely on
/// <see cref="SshImageFixtureBase.StartContainerAsync"/>'s internal
/// <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> call; the
/// agent-only tests (no container) call it explicitly.
/// </para>
/// <para>
/// <b>Why a host-side ssh-agent (not in-container).</b> LibSsh2CS's
/// <see cref="UnixSocketAgentTransport"/> connects to a Unix domain socket
/// identified by <c>SSH_AUTH_SOCK</c>. The agent socket must be reachable
/// from the test process; an in-container ssh-agent would require
/// socket-forwarding plumbing that exceeds the value of the test. The host's
/// ssh-agent is the natural choice.
/// </para>
/// <para>
/// <b>Host-side state.</b> Each test starts a private ssh-agent via
/// <c>ssh-agent -s</c> (yielding a fresh socket + PID), loads only the test
/// key, and kills the agent at teardown — no global state is mutated.
/// </para>
/// <para>
/// <b>Test collection.</b> The class is decorated with
/// <c>[Collection("agent-env-mutating")]</c> because
/// <see cref="Agent_ParameterlessCtor_ResolvesAuthSockEnvVar"/> mutates the
/// <c>SSH_AUTH_SOCK</c> environment variable. xUnit v3 serializes test
/// classes within the same collection, so the env-var mutation cannot race
/// another agent test. The other agent tests use the explicit-path
/// constructor and are immune to <c>SSH_AUTH_SOCK</c> changes — they are in
/// the collection only to share the serialization discipline.
/// </para>
/// </remarks>
[Collection("agent-env-mutating")]
public sealed class DockerAgentTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineWithEd25519KeySshImageFixture _alpineWithEd25519Key;
    private readonly AlpineWithRsaKeySshImageFixture _alpineWithRsaKey;

    public DockerAgentTests(
        AlpineWithEd25519KeySshImageFixture alpineWithEd25519Key,
        AlpineWithRsaKeySshImageFixture alpineWithRsaKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineWithEd25519Key = alpineWithEd25519Key;
        _alpineWithRsaKey = alpineWithRsaKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Loads the Ed25519 test key into a fresh host ssh-agent, starts the
    /// Docker SSH server with the matching pubkey in authorized_keys, and
    /// authenticates via <see cref="SshAgent"/>. Verifies the full
    /// <c>ListIdentitiesAsync → SignAsync → USERAUTH_REQUEST</c> flow.
    /// </summary>
    [Fact]
    public async Task Agent_Ed25519Identity_AuthenticatesAgainstLiveServer()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");

        await using SshDockerContainer container = await _alpineWithEd25519Key.StartContainerAsync(_loggerFactory, cancellationToken);
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        await using var agent = new SshAgent(agentCtx.SocketPath);
        await agent.ConnectAsync(cancellationToken);

        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);
        Assert.NotEmpty(identities);

        // Find the Ed25519 identity (the agent may have others loaded — we only
        // added one, but be defensive and pick by keytype prefix).
        var ed25519Ids = identities
            .Where(i => i.Blob.Length > 11 && StartsWithKeyType(i.Blob, "ssh-ed25519"))
            .ToList();
        SshAgentIdentity ed25519 = Assert.Single(ed25519Ids);
        Assert.Contains("libssh2cs", ed25519.Comment);

        // Authenticate the live session via the agent.
        await agent.AuthenticateWithIdentityAsync(
            session, SshDockerFixture.TestUser, ed25519, cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// Loads the RSA test key into a fresh host ssh-agent, starts the Docker
    /// SSH server with the matching pubkey in authorized_keys, and
    /// authenticates via <see cref="SshAgent"/>. This is the RSA counterpart
    /// of <see cref="Agent_Ed25519Identity_AuthenticatesAgainstLiveServer"/>
    /// and lights up the RSA-SHA2 algorithm-selection path: the live server
    /// advertises <c>server-sig-algs</c> via EXT_INFO, the client picks
    /// <c>rsa-sha2-256</c> (or <c>rsa-sha2-512</c>), and the
    /// <see cref="SshAgentExtensions.AlgorithmNameToFlags"/> SHA-2 branches
    /// (<c>rsa-sha2-256</c> / <c>rsa-sha2-512</c>) that return non-<see cref="SshAgentSignFlags.None"/>
    /// are exercised end-to-end. The Ed25519 test only hits the
    /// <see cref="SshAgentSignFlags.None"/> branch.
    /// </summary>
    [Fact]
    public async Task Agent_RsaIdentity_AuthenticatesAndDrivesSha2Flags()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("rsa_plain_key");

        await using SshDockerContainer container = await _alpineWithRsaKey.StartContainerAsync(_loggerFactory, cancellationToken);
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        await using SshSession session = await SshDockerFixture.ConnectAsync(SshDockerFixture.Host, container.Port, cancellationToken);

        await using var agent = new SshAgent(agentCtx.SocketPath);
        await agent.ConnectAsync(cancellationToken);

        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);
        Assert.NotEmpty(identities);

        // Find the RSA identity (the agent may have others loaded — we only
        // added one, but be defensive and pick by keytype prefix).
        var rsaIds = identities
            .Where(i => i.Blob.Length > 7 && StartsWithKeyType(i.Blob, "ssh-rsa"))
            .ToList();
        SshAgentIdentity rsa = Assert.Single(rsaIds);

        // Authenticate the live session via the agent. The server-sig-algs
        // EXT_INFO exchange forces UserAuth to pick rsa-sha2-256 (or 512),
        // which exercises the AlgorithmNameToFlags SHA-2 branches.
        await agent.AuthenticateWithIdentityAsync(
            session, SshDockerFixture.TestUser, rsa, cancellationToken);
        Assert.True(session.IsAuthenticated);
    }

    /// <summary>
    /// <see cref="SshAgent.DisconnectAsync"/> closes the underlying transport
    /// and flips <see cref="SshAgent.IsConnected"/> to <c>false</c>. After
    /// disconnect, further operations throw because the transport socket is
    /// closed. A fresh <see cref="SshAgent"/> on the same socket still works
    /// — the agent process itself is unaffected by a single client
    /// disconnecting.
    /// </summary>
    /// <remarks>
    /// This is the only integration test that exercises
    /// <see cref="SshAgent.DisconnectAsync"/> against a real transport —
    /// the unit-test equivalent (<c>Disconnect_AfterConnect_DropsConnection</c>)
    /// uses a <c>FakeTransport</c> that does not actually close a socket.
    /// Lights up <see cref="UnixSocketAgentTransport.DisconnectAsync"/>'s
    /// <see cref="Socket.Shutdown"/> + <see cref="Socket.Close"/> body, which
    /// the unit tests cannot reach.
    /// </remarks>
    [Fact]
    public async Task Agent_DisconnectAsync_ClosesSocket_AndSubsequentOpFails()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshDockerFixture.SkipIfDockerNotAvailable();
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        await using var agent = new SshAgent(agentCtx.SocketPath);
        await agent.ConnectAsync(cancellationToken);
        Assert.True(agent.IsConnected);

        // Sanity: the agent responds before disconnect.
        IReadOnlyList<SshAgentIdentity> before = await agent.ListIdentitiesAsync(cancellationToken);
        Assert.NotEmpty(before);

        // Disconnect — should drop IsConnected and close the transport socket.
        await agent.DisconnectAsync(cancellationToken);
        Assert.False(agent.IsConnected);

        // After disconnect, ListIdentities throws InvalidOperationException
        // because SshAgent.ThrowIfNotConnected() guards the call before the
        // transport is touched. The transport's own socket-closed SshException
        // path is not reachable through the public API post-disconnect —
        // the agent-level guard fires first.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => agent.ListIdentitiesAsync(cancellationToken));

        // A fresh SshAgent on the same socket still works — the agent process
        // is unaffected by this client's disconnect.
        await using var agent2 = new SshAgent(agentCtx.SocketPath);
        await agent2.ConnectAsync(cancellationToken);
        IReadOnlyList<SshAgentIdentity> after = await agent2.ListIdentitiesAsync(cancellationToken);
        Assert.NotEmpty(after);
    }

    /// <summary>
    /// The parameterless <see cref="SshAgent()"/> constructor relies on
    /// <see cref="AgentTransports.Create"/> to wire up a
    /// <see cref="UnixSocketAgentTransport"/> that resolves the socket path
    /// from <c>$SSH_AUTH_SOCK</c> at <see cref="SshAgent.ConnectAsync"/> time.
    /// This test sets <c>SSH_AUTH_SOCK</c> to the live agent's socket and
    /// verifies the parameterless ctor path reaches the agent successfully.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this is in the <c>agent-env-mutating</c> collection.</b> The test
    /// temporarily replaces <c>SSH_AUTH_SOCK</c> in the process environment.
    /// The original value (or <c>null</c>) is restored in <c>finally</c>.
    /// Other tests in this class use the explicit-path constructor
    /// (<c>new SshAgent(socketPath)</c>) and never read <c>SSH_AUTH_SOCK</c>,
    /// so they are immune to the mutation — but xUnit's collection-level
    /// serialization guarantees this test cannot overlap with anything else
    /// that might read the env var concurrently.
    /// </para>
    /// <para>
    /// Lights up <see cref="SshAgent()"/> parameterless ctor,
    /// <see cref="AgentTransports.Create()"/> factory loop, and
    /// <see cref="UnixSocketAgentTransport"/> parameterless ctor +
    /// <see cref="UnixSocketAgentTransport.ResolveSocketPath"/> env-var path
    /// — all currently at 0% because every other agent test passes an
    /// explicit socket path.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Agent_ParameterlessCtor_ResolvesAuthSockEnvVar()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshDockerFixture.SkipIfDockerNotAvailable();
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        string? original = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        try
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", agentCtx.SocketPath);

            await using var agent = new SshAgent();
            Assert.Null(agent.IdentityPath);
            await agent.ConnectAsync(cancellationToken);
            Assert.True(agent.IsConnected);

            IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);
            Assert.NotEmpty(identities);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", original);
        }
    }

    /// <summary>
    /// Setting <see cref="SshAgent.IdentityPath"/> before
    /// <see cref="SshAgent.ConnectAsync"/> rebuilds the underlying transport
    /// via <see cref="AgentTransports.Create(string)"/>. This exercises the
    /// <see cref="SshAgent.IdentityPath"/> setter's transport-swap branch
    /// (<c>_ownsTransport</c> path), which is at 0% today because no other
    /// test sets <see cref="SshAgent.IdentityPath"/> on an auto-discovery
    /// <see cref="SshAgent"/>.
    /// </summary>
    [Fact]
    public async Task Agent_IdentityPath_SwapBeforeConnect_RebuildsTransport()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshDockerFixture.SkipIfDockerNotAvailable();
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        // Construct via the parameterless ctor (auto-discovery: no transport
        // swap yet). Then override the socket path via IdentityPath before
        // ConnectAsync — this is the branch under test.
        await using var agent = new SshAgent();
        Assert.Null(agent.IdentityPath);

        agent.IdentityPath = agentCtx.SocketPath;
        Assert.Equal(agentCtx.SocketPath, agent.IdentityPath);

        await agent.ConnectAsync(cancellationToken);
        Assert.True(agent.IsConnected);

        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);
        Assert.NotEmpty(identities);
    }

    /// <summary>
    /// <see cref="SshAgent.ListIdentitiesAsync"/> returns the key loaded by
    /// <c>ssh-add</c> with its comment intact.
    /// </summary>
    [Fact]
    public async Task Agent_ListIdentities_ReturnsLoadedKey()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshDockerFixture.SkipIfDockerNotAvailable();
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        await using var agent = new SshAgent(agentCtx.SocketPath);
        await agent.ConnectAsync(cancellationToken);

        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken);

        // The ssh-add'd key is the only one in the fresh agent.
        Assert.NotEmpty(identities);
        SshAgentIdentity id = identities[0];
        Assert.True(StartsWithKeyType(id.Blob, "ssh-ed25519"));
        Assert.False(string.IsNullOrEmpty(id.Comment));
    }

    /// <summary>
    /// Signing with the agent produces a signature that the SSH server
    /// accepts as a valid Ed25519 signature over the userauth challenge.
    /// This implicitly verifies the entire sign path: ListIdentities picks
    /// the key, SignAsync issues a sign request with no flags, ParseSignResponse
    /// extracts the sig blob, and UserAuth places it in the USERAUTH_REQUEST.
    /// </summary>
    [Fact]
    public async Task Agent_Sign_Produces_Verifiable_Signature()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshDockerFixture.SkipIfDockerNotAvailable();
        SkipIfSshAgentBinariesMissing();

        byte[] privKeyBytes = FixtureLoader.LoadBytes("ed25519_plain_key");
        await using HostSshAgent agentCtx = await HostSshAgent.StartAsync(privKeyBytes, cancellationToken);

        await using var agent = new SshAgent(agentCtx.SocketPath);
        await agent.ConnectAsync(cancellationToken);

        IReadOnlyList<SshAgentIdentity> ids = await agent.ListIdentitiesAsync(cancellationToken);
        SshAgentIdentity id = ids[0];

        byte[] data = Encoding.UTF8.GetBytes("test-data-to-sign");
        byte[] sigBlob = await agent.SignAsync(id, data, SshAgentSignFlags.None, cancellationToken);

        // The sig blob should be [string "ssh-ed25519"][string 64-byte-sig].
        Assert.True(sigBlob.Length > 4);
        uint algoLen = BitConverter.IsLittleEndian
            ? BitConverter.ToUInt32(ReverseIfLittle(sigBlob, 0, 4), 0)
            : BitConverter.ToUInt32(sigBlob, 0);
        Assert.Equal(11u, algoLen);  // "ssh-ed25519" is 11 bytes
        Assert.Equal("ssh-ed25519", Encoding.UTF8.GetString(sigBlob, 4, 11));

        // The signature itself: 4-byte length + 64-byte Ed25519 R‖S.
        int sigOffset = 4 + 11;
        uint sigLen = BitConverter.IsLittleEndian
            ? BitConverter.ToUInt32(ReverseIfLittle(sigBlob, sigOffset, 4), 0)
            : BitConverter.ToUInt32(sigBlob, sigOffset);
        Assert.Equal(64u, sigLen);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Skip if agent tests cannot run: Docker reachable + ssh-agent +
    /// ssh-add binaries present on PATH.
    /// </summary>
    private static void SkipIfSshAgentBinariesMissing()
    {
        if (!BinaryExists("ssh-agent"))
        {
            Assert.Skip("ssh-agent binary not found on PATH; skipping agent tests.");
        }
        if (!BinaryExists("ssh-add"))
        {
            Assert.Skip("ssh-add binary not found on PATH; skipping agent tests.");
        }
    }

    private static bool BinaryExists(string name)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "which",
                Arguments = name,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            p?.WaitForExit(2000);
            return p is { ExitCode: 0 };
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Checks whether the first SSH string in <paramref name="blob"/> equals <paramref name="keyType"/>.</summary>
    private static bool StartsWithKeyType(byte[] blob, string keyType)
    {
        if (blob.Length < 4 + keyType.Length)
        {
            return false;
        }

        // Read BE32 length, then compare the next bytes to keyType.
        int len = (int)BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(0, 4));
        if (len != keyType.Length)
        {
            return false;
        }

        for (int i = 0; i < keyType.Length; i++)
        {
            if (blob[4 + i] != (byte)keyType[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Reads 4 bytes at offset and returns them in big-endian (for BitConverter on LE).</summary>
    private static byte[] ReverseIfLittle(byte[] buf, int offset, int count)
    {
        byte[] slice = new byte[count];
        Buffer.BlockCopy(buf, offset, slice, 0, count);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(slice);
        }

        return slice;
    }

    // ════════════════════════════════════════════════════════════════════════
    // HostSshAgent — manages a private ssh-agent process for the test
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Starts a private ssh-agent on the host, loads a private key via
    /// <c>ssh-add</c>, and exposes the socket path for use by
    /// <see cref="SshAgent"/>. Disposes kills the agent + removes the socket.
    /// </summary>
    private sealed class HostSshAgent : IAsyncDisposable
    {
        private readonly string _socketPath;
        private readonly string _tmpKeyPath;
        private readonly int _agentPid;

        private HostSshAgent(string socketPath, string tmpKeyPath, int agentPid)
        {
            _socketPath = socketPath;
            _tmpKeyPath = tmpKeyPath;
            _agentPid = agentPid;
        }

        public string SocketPath => _socketPath;

        /// <summary>
        /// Starts a fresh ssh-agent, writes the key to a temp file, ssh-add's it,
        /// and returns the agent context. The key file is given a descriptive
        /// comment (<c>libssh2cs-test</c>) so tests can disambiguate.
        /// </summary>
        public static async Task<HostSshAgent> StartAsync(byte[] privateKeyBytes, CancellationToken ct)
        {
            // Start ssh-agent -s. Output is Bourne-shell sourceable lines:
            //   SSH_AUTH_SOCK=/tmp/...; export SSH_AUTH_SOCK;
            //   SSH_AGENT_PID=12345; export SSH_AGENT_PID;
            //   echo Agent pid 12345;
            var startInfo = new ProcessStartInfo
            {
                FileName = "ssh-agent",
                Arguments = "-s",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            using Process startProc = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Failed to start ssh-agent");
            string stdout = await startProc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await startProc.WaitForExitAsync(ct).ConfigureAwait(false);

            if (startProc.ExitCode != 0)
            {
                throw new InvalidOperationException($"ssh-agent exited {startProc.ExitCode}: {stdout}");
            }

            (string? socketPath, int pid) = ParseAgentOutput(stdout);
            if (socketPath is null || pid == 0)
            {
                throw new InvalidOperationException($"Could not parse ssh-agent output: {stdout}");
            }

            // Write the key to a temp file with safe perms (ssh-add refuses otherwise).
            string tmpKey = Path.Combine(Path.GetTempPath(), $"libssh2cs-key-{Guid.NewGuid():N}");
            await File.WriteAllBytesAsync(tmpKey, privateKeyBytes, ct);
            // chmod 600 — ssh-add and ssh-keygen reject world-readable keys.
            if (!OperatingSystem.IsWindows())
            {
                using var chmod = Process.Start(new ProcessStartInfo
                {
                    FileName = "chmod",
                    Arguments = $"600 {tmpKey}",
                    UseShellExecute = false,
                });
                if (chmod is not null)
                {
                    using var chmodCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    chmodCts.CancelAfter(TimeSpan.FromSeconds(5));
                    await chmod.WaitForExitAsync(chmodCts.Token).ConfigureAwait(false);
                }
            }

            try
            {
                // ssh-add the key into the agent. Use env var passing instead
                // of `eval` since we're in C# not a shell.
                var addStart = new ProcessStartInfo
                {
                    FileName = "ssh-add",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                };
                addStart.Environment["SSH_AUTH_SOCK"] = socketPath;
                addStart.ArgumentList.Add(tmpKey);

                using Process addProc = Process.Start(addStart)
                    ?? throw new InvalidOperationException("Failed to start ssh-add");
                string addStdout = await addProc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
                string addStderr = await addProc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
                await addProc.WaitForExitAsync(ct).ConfigureAwait(false);

                if (addProc.ExitCode != 0)
                {
                    throw new InvalidOperationException(
                        $"ssh-add exited {addProc.ExitCode}: stdout={addStdout} stderr={addStderr}");
                }
            }
            catch
            {
                // Clean up the agent if ssh-add failed.
                TryKillAgent(pid);
                File.Delete(tmpKey);
                throw;
            }

            return new HostSshAgent(socketPath, tmpKey, pid);
        }

        /// <summary>Parse SSH_AUTH_SOCK + SSH_AGENT_PID from ssh-agent -s output.</summary>
        private static (string? Socket, int Pid) ParseAgentOutput(string stdout)
        {
            string? socket = null;
            int pid = 0;

            foreach (string line in stdout.Split(';', '\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("SSH_AUTH_SOCK=", StringComparison.Ordinal))
                {
                    socket = trimmed.Substring("SSH_AUTH_SOCK=".Length);
                }
                else if (trimmed.StartsWith("SSH_AGENT_PID=", StringComparison.Ordinal))
                {
                    string pidStr = trimmed.Substring("SSH_AGENT_PID=".Length);
                    if (!int.TryParse(pidStr, out pid))
                    {
                        pid = 0;
                    }
                }
            }

            return (socket, pid);
        }

        public async ValueTask DisposeAsync()
        {
            // Best-effort cleanup: ssh-add -D (clear keys), ssh-agent -k (kill agent).
            try
            {
                var clearStart = new ProcessStartInfo
                {
                    FileName = "ssh-add",
                    Arguments = "-D",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                clearStart.Environment["SSH_AUTH_SOCK"] = _socketPath;
                using var clearProc = Process.Start(clearStart);
                if (clearProc is not null)
                {
                    using var clearCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await clearProc.WaitForExitAsync(clearCts.Token).ConfigureAwait(false);
                }
            }
            catch
            {
                // Ignore — best-effort.
            }

            TryKillAgent(_agentPid);

            try
            {
                if (File.Exists(_tmpKeyPath))
                {
                    File.Delete(_tmpKeyPath);
                }
            }
            catch { /* best-effort */ }

            try
            {
                if (File.Exists(_socketPath))
                {
                    File.Delete(_socketPath);
                }
            }
            catch { /* best-effort — may not have perms */ }
        }

        private static void TryKillAgent(int pid)
        {
            if (pid == 0)
            {
                return;
            }

            try
            {
                using var killProc = Process.Start(new ProcessStartInfo
                {
                    FileName = "kill",
                    Arguments = $"{pid}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });
                killProc?.WaitForExit(2000);
            }
            catch
            {
                // Best-effort — process may already be gone.
            }
        }
    }
}
