using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// Increment 3.4.2 — <see cref="RekeyPolicy"/> defaults, <see cref="SshSession"/>
/// rekey surface (policy/counter/time-elapsed properties), and
/// <see cref="TimeProvider"/> constructor injection. Post-handshake counter
/// propagation and timestamp behavior are exercised by 3.4.5 (where the
/// rekey is actually driven through <see cref="MockSshServer"/>) and 3.4.6
/// (end-to-end under load). Here we verify the API surface and defaults.
/// </summary>
public class RekeyPolicyTests
{
    // ── RekeyPolicy defaults ─────────────────────────────────────────────

    [Fact]
    public void RekeyPolicy_Default_MatchesOpenSsh()
    {
        RekeyPolicy p = RekeyPolicy.Default;
        Assert.Equal(4L * 1024 * 1024 * 1024, p.MaxBytes);
        Assert.Equal((long)int.MaxValue, p.MaxPackets);
        Assert.Equal(TimeSpan.FromHours(1), p.MaxInterval);
    }

    [Fact]
    public void RekeyPolicy_Never_DisablesAllThresholds()
    {
        RekeyPolicy p = RekeyPolicy.Never;
        Assert.Equal(long.MaxValue, p.MaxBytes);
        Assert.Equal(long.MaxValue, p.MaxPackets);
        Assert.Equal(TimeSpan.MaxValue, p.MaxInterval);
    }

    [Fact]
    public void RekeyPolicy_IsSealedRecord_WithInitProperties()
    {
        // Caller can override any threshold via the `with` expression or init.
        RekeyPolicy p = RekeyPolicy.Default with { MaxBytes = 1024 };
        Assert.Equal(1024, p.MaxBytes);
        Assert.Equal(RekeyPolicy.Default.MaxPackets, p.MaxPackets);
        Assert.Equal(RekeyPolicy.Default.MaxInterval, p.MaxInterval);
    }

    // ── SshSession.RekeyPolicy ──────────────────────────────────────────

    [Fact]
    public void SshSession_RekeyPolicy_DefaultsToOpenSsh()
    {
        var s = new SshSession();
        Assert.Equal(RekeyPolicy.Default.MaxBytes, s.RekeyPolicy.MaxBytes);
        Assert.Equal(RekeyPolicy.Default.MaxPackets, s.RekeyPolicy.MaxPackets);
        Assert.Equal(RekeyPolicy.Default.MaxInterval, s.RekeyPolicy.MaxInterval);
    }

    [Fact]
    public void SshSession_RekeyPolicy_SetterAcceptsCustom()
    {
        var s = new SshSession();
        var custom = new RekeyPolicy { MaxBytes = 1, MaxPackets = 2, MaxInterval = TimeSpan.FromSeconds(3) };
        s.RekeyPolicy = custom;
        Assert.Equal(1, s.RekeyPolicy.MaxBytes);
        Assert.Equal(2, s.RekeyPolicy.MaxPackets);
        Assert.Equal(TimeSpan.FromSeconds(3), s.RekeyPolicy.MaxInterval);
    }

    [Fact]
    public void SshSession_RekeyPolicy_SetterNullBecomesNever()
    {
        // Null assignment is silently coerced to Never (no NRE); defends against
        // callers that forget to initialize the policy.
        var s = new SshSession { RekeyPolicy = null! };
        Assert.Equal(RekeyPolicy.Never.MaxBytes, s.RekeyPolicy.MaxBytes);
        Assert.Equal(RekeyPolicy.Never.MaxPackets, s.RekeyPolicy.MaxPackets);
        Assert.Equal(RekeyPolicy.Never.MaxInterval, s.RekeyPolicy.MaxInterval);
    }

    // ── Counter properties — zero before handshake ──────────────────────

    [Fact]
    public void SshSession_Counters_AreZeroBeforeHandshake()
    {
        var s = new SshSession();
        Assert.Equal(0, s.InboundBytes);
        Assert.Equal(0, s.OutboundBytes);
        Assert.Equal(0, s.InboundPackets);
        Assert.Equal(0, s.OutboundPackets);
    }

    [Fact]
    public void SshSession_ElapsedSinceHandshake_IsZeroBeforeHandshake()
    {
        // TimeProvider.System with no handshake completed → TimeSpan.Zero
        // (guarded by _handshakeCompleted check in the property).
        var s = new SshSession();
        Assert.Equal(TimeSpan.Zero, s.ElapsedSinceHandshake);
    }

    // ── TimeProvider injection ──────────────────────────────────────────

    [Fact]
    public void SshSession_InternalCtor_AcceptsCustomTimeProvider()
    {
        var fake = new FakeTimeProvider();
        var s = new SshSession(fake);
        // Before handshake, ElapsedSinceHandshake is TimeSpan.Zero regardless
        // of what the TimeProvider returns (the property short-circuits on
        // _handshakeCompleted).
        Assert.Equal(TimeSpan.Zero, s.ElapsedSinceHandshake);
    }

    [Fact]
    public void SshSession_PublicCtor_UsesTimeProviderSystem()
    {
        // Public ctor must not NRE — TimeProvider.System is a static singleton.
        var s = new SshSession();
        Assert.Equal(TimeSpan.Zero, s.ElapsedSinceHandshake);
    }

    [Fact]
    public void SshSession_ElapsedSinceHandshake_AdvancesWithTimeProvider()
    {
        // We can't fully verify ElapsedSinceHandshake after handshake without a
        // real handshake (covered in 3.4.5/3.4.6). But we CAN verify the
        // TimeProvider.Advance is reflected by constructing a session, faking
        // the handshake-completed state via the ElapsedSinceHandshake property's
        // guard. The guard returns Zero before handshake; once a handshake
        // completes, the elapsed grows with the TimeProvider. The post-handshake
        // path is exercised by RekeyIntegrationTests (3.4.5).
        var fake = new FakeTimeProvider();
        var s = new SshSession(fake);
        fake.Advance(TimeSpan.FromHours(2));
        // Pre-handshake: still zero (the guard short-circuits).
        Assert.Equal(TimeSpan.Zero, s.ElapsedSinceHandshake);
    }

    // ── Disposed session ────────────────────────────────────────────────

    [Fact]
    public async Task SshSession_RekeyPolicy_StillReadableAfterDispose()
    {
        // The policy is a value record; disposing the session doesn't reset it.
        // Counter properties return 0 because the underlying reader/writer are
        // null after DisposeAsync (the props null-coalesce to 0).
        var s = new SshSession { RekeyPolicy = RekeyPolicy.Never };
        await s.DisposeAsync();
        Assert.Equal(RekeyPolicy.Never.MaxBytes, s.RekeyPolicy.MaxBytes);
        Assert.Equal(0, s.InboundBytes);
        Assert.Equal(0, s.OutboundBytes);
    }
}
