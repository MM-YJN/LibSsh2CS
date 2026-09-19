namespace LibSsh2CS;

/// <summary>
/// A password-change callback invoked when the server returns
/// <c>SSH_MSG_USERAUTH_PASSWD_CHANGEREQ</c> (the password has expired). Returns
/// the new password, or <see langword="null"/> to abort with
/// <see cref="SshErrorCode.PasswordExpired"/>. Replaces libssh2's
/// <c>LIBSSH2_PASSWD_CHANGEREQ_FUNC</c>.
/// </summary>
/// <param name="cancellationToken">Cooperative cancellation.</param>
/// <returns>The new password, or <see langword="null"/> to abort.</returns>
public delegate Task<string?> SshPasswordChangeCallback(CancellationToken cancellationToken);
