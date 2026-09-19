using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS;

/// <summary>
/// Exception carrying libssh2-style error information. Standalone — does not
/// reference any LibGit2CS type. Replaces libssh2's per-session
/// <c>err_code</c> + <c>err_msg</c> fields; the error state rides on the
/// exception stack instead of session state.
/// </summary>
/// <remarks>
/// <see cref="ErrorCode"/> maps to <c>LIBSSH2_ERROR_*</c>. Internal libssh2
/// <c>_libssh2_error()</c> call sites become <c>throw new LibSsh2Exception(...)</c>
/// in the managed port. <see cref="SshErrorCode.EAgain"/> is never surfaced —
/// async methods await rather than returning it.
/// </remarks>
[SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "The four-arg ctor is the canonical form; parameterless/default-message ctors would lose ErrorCode")]
public sealed class SshException : Exception
{
    /// <summary>
    /// The libssh2 error code (e.g. <see cref="SshErrorCode.AuthenticationFailed"/>).
    /// </summary>
    public SshErrorCode ErrorCode { get; }

    /// <summary>
    /// Creates a generic error (<see cref="SshErrorCode.SocketNone"/>) with the given message.
    /// </summary>
    public SshException(string message)
        : this(SshErrorCode.SocketNone, message)
    {
    }

    /// <summary>
    /// Creates a new exception with the given code and message.
    /// </summary>
    public SshException(SshErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Creates a new exception wrapping an inner cause. Defaults to
    /// <see cref="SshErrorCode.SocketNone"/>.
    /// </summary>
    public SshException(string message, Exception innerException)
        : this(SshErrorCode.SocketNone, message, innerException)
    {
    }

    /// <summary>
    /// Creates a new exception with the given code, message, and inner cause.
    /// </summary>
    public SshException(SshErrorCode errorCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}
