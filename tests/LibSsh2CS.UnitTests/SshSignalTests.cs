namespace LibSsh2CS.UnitTests;

/// <summary>
/// Tests for <see cref="SshSignal"/> and <see cref="SshSignalExtensions.ToWireName"/>.
/// Increment 3.6.1 — verifies the AOT-safe wire-name mapping for the signal
/// enum consumed by <see cref="SshChannel.SignalAsync(SshSignal, CancellationToken)"/>.
/// </summary>
public class SshSignalTests
{
    [Fact]
    public void ToWireName_KnownMappings_ReturnUppercasedSuffix()
    {
        // Sample checks covering short, long, and digit-suffixed names.
        Assert.Equal("HUP", SshSignal.Hup.ToWireName());
        Assert.Equal("INT", SshSignal.Int.ToWireName());
        Assert.Equal("TERM", SshSignal.Term.ToWireName());
        Assert.Equal("KILL", SshSignal.Kill.ToWireName());
        Assert.Equal("USR1", SshSignal.Usr1.ToWireName());
        Assert.Equal("USR2", SshSignal.Usr2.ToWireName());
        Assert.Equal("VTALRM", SshSignal.Vtalrm.ToWireName());
        Assert.Equal("WINCH", SshSignal.Winch.ToWireName());
        Assert.Equal("IO", SshSignal.Io.ToWireName());
    }

    [Fact]
    public void ToWireName_AllMembersCovered_NoSwitchThrow()
    {
        // Guards against a future enum addition forgetting to extend the switch.
        // If this fails, add the missing case to SshSignalExtensions.ToWireName.
        foreach (SshSignal value in Enum.GetValues<SshSignal>())
        {
            string name = value.ToWireName();
            Assert.False(string.IsNullOrEmpty(name));
            Assert.Equal(name, name.ToUpperInvariant());
            Assert.False(name.StartsWith("SIG", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void ToWireName_InvalidValue_ThrowsArgumentOutOfRange()
    {
        // Cast an undefined integer to SshSignal — the switch must reject it.
        var invalid = (SshSignal)9999;
        Assert.Throws<ArgumentOutOfRangeException>(() => invalid.ToWireName());
    }

    [Fact]
    public void ToWireName_IsDeterministic_NoReflection()
    {
        // Sanity: the same value maps to the same string across repeated calls.
        // This is implicitly a regression test against replacing the switch
        // with Enum.GetName/GetFields (which would still be deterministic but
        // would lose the explicit uppercase normalization for any future name
        // style drift).
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal("TERM", SshSignal.Term.ToWireName());
            Assert.Equal("USR1", SshSignal.Usr1.ToWireName());
        }
    }
}
