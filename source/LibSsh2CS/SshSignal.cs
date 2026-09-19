using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS;

/// <summary>
/// Standard POSIX signal names accepted by <see cref="SshChannel.SignalAsync(SshSignal, CancellationToken)"/>
/// for delivery to the remote process via <c>SSH_MSG_CHANNEL_REQUEST "signal"</c>
/// (RFC 4254 §6.9). Enum member names map to wire strings via
/// <see cref="SshSignalExtensions.ToWireName"/> — the suffix without the
/// <c>"SIG"</c> prefix, uppercased (e.g. <see cref="Term"/> → <c>"TERM"</c>).
/// </summary>
/// <remarks>
/// <para>
/// This enum covers the signals documented in OpenSSH's <c>signal(7)</c> that
/// are meaningful over SSH (RFC 4254 §6.10 lists these as the names a server
/// may report back in <c>exit-signal</c>). For signal names outside this set
/// (or server-specific extensions), use the <see cref="SshChannel.SignalAsync(string,
/// CancellationToken)"/> string overload directly.
/// </para>
/// <para>
/// <b>AOT note.</b> The wire-name mapping is an explicit switch expression in
/// <see cref="SshSignalExtensions.ToWireName"/> — no reflection, no
/// <c>Enum.GetName</c>. Future enum additions must extend the switch (enforced
/// by <c>SshSignalTests.ToWireName_AllMembersCovered</c>).
/// </para>
/// </remarks>
public enum SshSignal
{
    /// <summary><c>SIGHUP</c> — terminal line hangup.</summary>
    Hup,

    /// <summary><c>SIGINT</c> — interrupt program (Ctrl-C).</summary>
    [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames",
        Justification = "POSIX SIGINT parity — name follows the standard signal convention.")]
    Int,

    /// <summary><c>SIGQUIT</c> — quit program (Ctrl-\).</summary>
    Quit,

    /// <summary><c>SIGILL</c> — illegal instruction.</summary>
    Ill,

    /// <summary><c>SIGTRAP</c> — trace trap.</summary>
    Trap,

    /// <summary><c>SIGABRT</c> — abort program.</summary>
    Abrt,

    /// <summary><c>SIGBUS</c> — bus error (misaligned access).</summary>
    Bus,

    /// <summary><c>SIGFPE</c> — floating-point exception.</summary>
    Fpe,

    /// <summary><c>SIGKILL</c> — kill (cannot be caught/ignored).</summary>
    Kill,

    /// <summary><c>SIGSEGV</c> — segmentation fault.</summary>
    Segv,

    /// <summary><c>SIGPIPE</c> — write on a pipe with no reader.</summary>
    Pipe,

    /// <summary><c>SIGALRM</c> — alarm clock.</summary>
    Alrm,

    /// <summary><c>SIGTERM</c> — software termination (default <c>kill</c>).</summary>
    Term,

    /// <summary><c>SIGURG</c> — urgent condition on I/O channel.</summary>
    Urg,

    /// <summary><c>SIGSTOP</c> — stop (cannot be caught/ignored).</summary>
    Stop,

    /// <summary><c>SIGTSTP</c> — interactive stop (Ctrl-Z).</summary>
    Tstp,

    /// <summary><c>SIGCONT</c> — continue after stop.</summary>
    Cont,

    /// <summary><c>SIGCHLD</c> — child status change.</summary>
    Chld,

    /// <summary><c>SIGTTIN</c> — background read from controlling terminal.</summary>
    Ttin,

    /// <summary><c>SIGTTOU</c> — background write to controlling terminal.</summary>
    Ttou,

    /// <summary><c>SIGIO</c> — asynchronous I/O event (<c>SIGPOLL</c> on Linux).</summary>
    Io,

    /// <summary><c>SIGXCPU</c> — CPU time limit exceeded.</summary>
    Xcpu,

    /// <summary><c>SIGXFSZ</c> — file size limit exceeded.</summary>
    Xfsz,

    /// <summary><c>SIGVTALRM</c> — virtual time alarm.</summary>
    Vtalrm,

    /// <summary><c>SIGPROF</c> — profiling time alarm.</summary>
    Prof,

    /// <summary><c>SIGWINCH</c> — window size change.</summary>
    Winch,

    /// <summary><c>SIGUSR1</c> — user-defined signal 1.</summary>
    Usr1,

    /// <summary><c>SIGUSR2</c> — user-defined signal 2.</summary>
    Usr2,
}
