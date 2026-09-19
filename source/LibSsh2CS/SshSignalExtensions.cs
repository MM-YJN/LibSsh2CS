namespace LibSsh2CS;

/// <summary>
/// Extension methods on <see cref="SshSignal"/>.
/// </summary>
public static class SshSignalExtensions
{
    /// <summary>
    /// Returns the RFC 4254 §6.9 wire string for <paramref name="signal"/> —
    /// the suffix without the <c>"SIG"</c> prefix, uppercased:
    /// <see cref="SshSignal.Term"/> → <c>"TERM"</c>, <see cref="SshSignal.Usr1"/>
    /// → <c>"USR1"</c>, etc. AOT-clean explicit mapping (no reflection, no
    /// <c>Enum.GetName</c>).
    /// </summary>
    /// <param name="signal">The signal to translate.</param>
    /// <returns>The wire-format ASCII signal name (no <c>"SIG"</c> prefix).</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="signal"/>
    /// is not a defined <see cref="SshSignal"/> value.</exception>
    public static string ToWireName(this SshSignal signal) => signal switch
    {
        SshSignal.Hup => "HUP",
        SshSignal.Int => "INT",
        SshSignal.Quit => "QUIT",
        SshSignal.Ill => "ILL",
        SshSignal.Trap => "TRAP",
        SshSignal.Abrt => "ABRT",
        SshSignal.Bus => "BUS",
        SshSignal.Fpe => "FPE",
        SshSignal.Kill => "KILL",
        SshSignal.Segv => "SEGV",
        SshSignal.Pipe => "PIPE",
        SshSignal.Alrm => "ALRM",
        SshSignal.Term => "TERM",
        SshSignal.Urg => "URG",
        SshSignal.Stop => "STOP",
        SshSignal.Tstp => "TSTP",
        SshSignal.Cont => "CONT",
        SshSignal.Chld => "CHLD",
        SshSignal.Ttin => "TTIN",
        SshSignal.Ttou => "TTOU",
        SshSignal.Io => "IO",
        SshSignal.Xcpu => "XCPU",
        SshSignal.Xfsz => "XFSZ",
        SshSignal.Vtalrm => "VTALRM",
        SshSignal.Prof => "PROF",
        SshSignal.Winch => "WINCH",
        SshSignal.Usr1 => "USR1",
        SshSignal.Usr2 => "USR2",
        _ => throw new ArgumentOutOfRangeException(nameof(signal), signal, "Unknown SshSignal."),
    };
}
