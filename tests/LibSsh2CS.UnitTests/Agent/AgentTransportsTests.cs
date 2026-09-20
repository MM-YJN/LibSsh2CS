using System.Buffers;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Tests for agent backend discovery: candidate ordering, fallback when a
/// backend is not running, disposal of candidates that fail, cancellation, and
/// how <see cref="SshAgent"/> adopts (and re-runs) discovery. Everything runs
/// against injected factories, so the tests never depend on which agents happen
/// to be installed or running on the machine.
/// </summary>
public class AgentTransportsTests
{
    // ════════════════════════════════════════════════════════════════════════
    // Factory list
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task GetFactories_PutsPageantFirstOnWindowsAndUnixElsewhere()
    {
        IReadOnlyList<Func<IAgentTransport?>> factories = AgentTransports.GetFactories();
        Assert.Equal(2, factories.Count);

        IAgentTransport? pageant = factories[0]();
        IAgentTransport? unix = factories[1]();

        if (OperatingSystem.IsWindows())
        {
            // Parity with supported_backends[] (agent.c:436-440): Pageant first.
            Assert.IsType<PageantAgentTransport>(pageant);
        }
        else
        {
            // The factory reports the backend as unavailable rather than
            // throwing, so discovery just skips it.
            Assert.Null(pageant);
        }

        Assert.IsType<UnixSocketAgentTransport>(unix);

        if (pageant is not null)
        {
            await pageant.DisposeAsync();
        }

        await unix.DisposeAsync();
    }

    [Fact]
    public void Create_NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AgentTransports.Create(null!));
    }

    [Fact]
    public async Task Create_ExplicitPath_ReturnsUnixTransport()
    {
        IAgentTransport transport = AgentTransports.Create("/tmp/explicit.sock");
        Assert.IsType<UnixSocketAgentTransport>(transport);
        await transport.DisposeAsync();
    }

    // ════════════════════════════════════════════════════════════════════════
    // Candidate selection
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ConnectAsync_FirstCandidateThatConnectsWins()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var first = new StubTransport("pageant");
        var second = new StubTransport("unix");

        IAgentTransport connected = await AgentTransports.ConnectAsync(
            [() => first, () => second], cancellationToken);

        Assert.Same(first, connected);
        Assert.True(first.ConnectCalled);
        Assert.False(second.ConnectCalled);
        Assert.False(first.Disposed);
    }

    [Fact]
    public async Task ConnectAsync_UnavailableFactory_IsSkipped()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var unix = new StubTransport("unix");

        IAgentTransport connected = await AgentTransports.ConnectAsync(
            [static () => null, () => unix], cancellationToken);

        Assert.Same(unix, connected);
    }

    [Fact]
    public async Task ConnectAsync_FailedCandidate_IsDisposedBeforeNextIsTried()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var pageant = new StubTransport("pageant")
        {
            ConnectFailure = new SshException(SshErrorCode.AgentProtocol, "failed connecting agent"),
        };
        var unix = new StubTransport("unix");

        IAgentTransport connected = await AgentTransports.ConnectAsync(
            [() => pageant, () => unix], cancellationToken);

        Assert.Same(unix, connected);
        Assert.True(pageant.Disposed);
        Assert.False(unix.Disposed);
    }

    [Fact]
    public async Task ConnectAsync_DisposeFailureOnDiscardedCandidate_DoesNotMaskConnectError()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var pageant = new StubTransport("pageant")
        {
            ConnectFailure = new SshException(SshErrorCode.AgentProtocol, "failed connecting agent"),
            DisposeFailure = new InvalidOperationException("dispose blew up"),
        };

        await Assert.ThrowsAsync<SshException>(
            () => AgentTransports.ConnectAsync([() => pageant], cancellationToken));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Total failure and cancellation
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ConnectAsync_AllCandidatesFail_ThrowsAgentProtocolWithLastFailure()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var pageant = new StubTransport("pageant")
        {
            ConnectFailure = new SshException(SshErrorCode.AgentProtocol, "failed connecting agent"),
        };
        var unix = new StubTransport("unix")
        {
            ConnectFailure = new SshException(SshErrorCode.AgentProtocol, "socket missing"),
        };

        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => AgentTransports.ConnectAsync([() => pageant, () => unix], cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Same(unix.ConnectFailure, ex.InnerException);
        Assert.True(pageant.Disposed);
        Assert.True(unix.Disposed);
    }

    [Fact]
    public async Task ConnectAsync_NoUsableCandidates_ThrowsWithoutInnerException()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        SshException ex = await Assert.ThrowsAsync<SshException>(
            () => AgentTransports.ConnectAsync([static () => null], cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public async Task ConnectAsync_Canceled_StopsSearchInsteadOfFallingBack()
    {
        using var cts = new CancellationTokenSource();
        var pageant = new StubTransport("pageant")
        {
            OnConnect = cts.Cancel,
            ConnectFailure = new OperationCanceledException(),
        };
        var unix = new StubTransport("unix");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AgentTransports.ConnectAsync([() => pageant, () => unix], cts.Token));

        Assert.True(pageant.Disposed);
        Assert.False(unix.ConnectCalled);
    }

    [Fact]
    public async Task ConnectAsync_PreCanceledToken_DoesNotConstructCandidates()
    {
        int factoryCalls = 0;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AgentTransports.ConnectAsync(
                [
                    () =>
                    {
                        factoryCalls++;
                        return new StubTransport("pageant");
                    },
                ],
                new CancellationToken(canceled: true)));

        Assert.Equal(0, factoryCalls);
    }

    // ════════════════════════════════════════════════════════════════════════
    // SshAgent integration
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SshAgent_AutoDiscovery_RunsAtConnectAndAdoptsWinner()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var pageant = new StubTransport("pageant")
        {
            ConnectFailure = new SshException(SshErrorCode.AgentProtocol, "failed connecting agent"),
        };
        var unix = new StubTransport("unix");

        await using var agent = new SshAgent([() => pageant, () => unix]);

        // Constructing the client must not have probed anything yet.
        Assert.False(pageant.ConnectCalled);
        Assert.False(agent.IsConnected);

        await agent.ConnectAsync(cancellationToken);

        Assert.True(agent.IsConnected);
        Assert.True(unix.ConnectCalled);
        Assert.True(pageant.Disposed);
    }

    [Fact]
    public async Task SshAgent_AutoDiscovery_RediscoveryOnReconnect()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        int factoryCalls = 0;

        await using var agent = new SshAgent(
            [
                () =>
                {
                    factoryCalls++;
                    return new StubTransport("unix");
                },
            ]);

        await agent.ConnectAsync(cancellationToken);
        Assert.Equal(1, factoryCalls);

        await agent.DisconnectAsync(cancellationToken);
        Assert.False(agent.IsConnected);

        // Re-discovery is what lets a reconnect pick up an agent that started
        // after the previous connect.
        await agent.ConnectAsync(cancellationToken);
        Assert.Equal(2, factoryCalls);
        Assert.True(agent.IsConnected);
    }

    [Fact]
    public async Task SshAgent_OwnsDiscoveredTransport_AndDisposesIt()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var winner = new StubTransport("unix");

        var agent = new SshAgent([() => winner]);
        await agent.ConnectAsync(cancellationToken);
        await agent.DisposeAsync();

        Assert.True(winner.Disposed);
    }

    [Fact]
    public async Task SshAgent_ExplicitPath_DoesNotRunDiscovery()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        int factoryCalls = 0;
        string missingSocket = Path.Combine(
            Path.GetTempPath(), $"libssh2cs-missing-{Guid.NewGuid():N}.sock");

        await using var agent = new SshAgent(
            [
                () =>
                {
                    factoryCalls++;
                    return new StubTransport("pageant");
                },
            ]);
        agent.IdentityPath = missingSocket;

        await Assert.ThrowsAsync<SshException>(() => agent.ConnectAsync(cancellationToken));
        Assert.Equal(0, factoryCalls);
        Assert.False(agent.IsConnected);
    }

    [Fact]
    public async Task SshAgent_ClearingIdentityPath_RestoresAutoDiscovery()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var winner = new StubTransport("pageant");

        await using var agent = new SshAgent([() => winner]);
        agent.IdentityPath = "/tmp/explicit.sock";
        Assert.Equal("/tmp/explicit.sock", agent.IdentityPath);

        agent.IdentityPath = null;
        Assert.Null(agent.IdentityPath);

        await agent.ConnectAsync(cancellationToken);
        Assert.True(winner.ConnectCalled);
    }

    [Fact]
    public void SshAgent_EmptyIdentityPath_Throws()
    {
        var agent = new SshAgent();
        Assert.Throws<ArgumentException>(() => agent.IdentityPath = string.Empty);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Stub transport
    // ════════════════════════════════════════════════════════════════════════

    private sealed class StubTransport : IAgentTransport
    {
        public StubTransport(string name)
        {
            Name = name;
        }

        public string Name { get; }

        /// <summary>Thrown (as a faulted task) by <see cref="ConnectAsync"/> when set.</summary>
        public Exception? ConnectFailure { get; set; }

        /// <summary>Thrown by <see cref="DisposeAsync"/> when set.</summary>
        public Exception? DisposeFailure { get; set; }

        /// <summary>Runs at the start of <see cref="ConnectAsync"/>; used to cancel mid-connect.</summary>
        public Action? OnConnect { get; set; }

        public bool ConnectCalled { get; private set; }

        public bool Disposed { get; private set; }

        public Task ConnectAsync(CancellationToken cancellationToken)
        {
            ConnectCalled = true;
            OnConnect?.Invoke();
            return ConnectFailure is null ? Task.CompletedTask : Task.FromException(ConnectFailure);
        }

        public Task TransactAsync(
            ReadOnlyMemory<byte> request, IBufferWriter<byte> responseWriter,
            CancellationToken cancellationToken)
            => throw new NotSupportedException($"{nameof(StubTransport)} does not transact");

        public Task DisconnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return DisposeFailure is null
                ? ValueTask.CompletedTask
                : ValueTask.FromException(DisposeFailure);
        }
    }
}
