using System.Buffers;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Tests for <see cref="SshAgentExtensions"/>. Two surfaces:
/// <list type="bullet">
///   <item><see cref="SshAgentExtensions.AlgorithmNameToFlags"/> — pure
///   mapping from algorithm name (<c>"rsa-sha2-256"</c>,
///   <c>"rsa-sha2-512"</c>, etc.) to <see cref="SshAgentSignFlags"/> bit values.
///   Parity with <c>agent_sign</c>'s flag derivation
///   (<c>agent.c:488-503</c>).</item>
///   <item><see cref="SshAgentExtensions.AuthenticateWithIdentityAsync"/> —
///   argument validation. The end-to-end sign path (algorithm name → flags →
///   agent request → response) is verified live by
///   <c>DockerAgentTests</c> (Phase 4 increment 4.5).</item>
/// </list>
/// </summary>
public class SshAgentExtensionsTests
{
    // ════════════════════════════════════════════════════════════════════════
    // AlgorithmNameToFlags
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Flags_RsaSha2_512_ReturnsRsaSha512()
    {
        Assert.Equal(SshAgentSignFlags.RsaSha512, SshAgentExtensions.AlgorithmNameToFlags("rsa-sha2-512"));
    }

    [Fact]
    public void Flags_RsaSha2_256_ReturnsRsaSha256()
    {
        Assert.Equal(SshAgentSignFlags.RsaSha256, SshAgentExtensions.AlgorithmNameToFlags("rsa-sha2-256"));
    }

    [Fact]
    public void Flags_SshRsa_ReturnsNone()
    {
        // SHA-1 fallback (OpenSSH 8.2+ rejects this; agent picks default).
        Assert.Equal(SshAgentSignFlags.None, SshAgentExtensions.AlgorithmNameToFlags("ssh-rsa"));
    }

    [Fact]
    public void Flags_SshEd25519_ReturnsNone()
    {
        Assert.Equal(SshAgentSignFlags.None, SshAgentExtensions.AlgorithmNameToFlags("ssh-ed25519"));
    }

    [Theory]
    [InlineData("ecdsa-sha2-nistp256")]
    [InlineData("ecdsa-sha2-nistp384")]
    [InlineData("ecdsa-sha2-nistp521")]
    public void Flags_Ecdsa_CurveNames_ReturnNone(string algorithm)
    {
        Assert.Equal(SshAgentSignFlags.None, SshAgentExtensions.AlgorithmNameToFlags(algorithm));
    }

    [Fact]
    public void Flags_UnknownAlgorithm_ReturnsNone()
    {
        // Defensive — should never happen (UserAuth validates before invoking
        // the callback), but a future key type that reaches the agent shouldn't
        // crash with IndexOutOfRange or the like.
        Assert.Equal(SshAgentSignFlags.None, SshAgentExtensions.AlgorithmNameToFlags("ssh-futurekey-v1"));
    }

    [Fact]
    public void Flags_None_ReturnsZero()
    {
        Assert.Equal((SshAgentSignFlags)0, SshAgentSignFlags.None);
        Assert.Equal(0u, (uint)SshAgentSignFlags.None);
    }

    [Fact]
    public void Flags_BitValues_Match_AgentC()
    {
        // Parity with agent.c:107-108.
        Assert.Equal(2u, (uint)SshAgentSignFlags.RsaSha256);
        Assert.Equal(4u, (uint)SshAgentSignFlags.RsaSha512);
    }

    // ════════════════════════════════════════════════════════════════════════
    // AuthenticateWithIdentityAsync — argument validation
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Authenticate_NullAgent_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SshAgent a = null!;
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await a.AuthenticateWithIdentityAsync(new SshSession(), "user",
                new SshAgentIdentity { Blob = [], Comment = "" }, cancellationToken));
    }

    [Fact]
    public async Task Authenticate_NullSession_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await agent.AuthenticateWithIdentityAsync(null!, "user",
                new SshAgentIdentity { Blob = [], Comment = "" }, cancellationToken));
    }

    [Fact]
    public async Task Authenticate_NullUsername_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await agent.AuthenticateWithIdentityAsync(new SshSession(), null!,
                new SshAgentIdentity { Blob = [], Comment = "" }, cancellationToken));
    }

    [Fact]
    public async Task Authenticate_NullIdentity_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await agent.AuthenticateWithIdentityAsync(new SshSession(), "user", null!, cancellationToken));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Fake transport (for the ctor only; auth flow itself is covered by
    // DockerAgentTests which use a real ssh-agent).
    // ════════════════════════════════════════════════════════════════════════

    private sealed class FakeTransport : IAgentTransport
    {
        public Task ConnectAsync(CancellationToken ct) => Task.CompletedTask;
        public Task TransactAsync(ReadOnlyMemory<byte> request, IBufferWriter<byte> responseWriter, CancellationToken ct)
            => throw new NotImplementedException();
        public Task DisconnectAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
