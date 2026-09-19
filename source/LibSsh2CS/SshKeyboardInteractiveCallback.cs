namespace LibSsh2CS;

/// <summary>
/// The user-supplied keyboard-interactive callback. Receives the server's
/// name, instruction, and prompts; returns one answer string per prompt
/// (empty string allowed). Replaces libssh2's
/// <c>LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC</c>.
/// </summary>
/// <param name="name">The server's challenge name (may be empty).</param>
/// <param name="instruction">The server's instruction (may be empty).</param>
/// <param name="prompts">The prompts to display to the user.</param>
/// <param name="cancellationToken">Cooperative cancellation.</param>
/// <returns>An array of answers, one per <paramref name="prompts"/> entry.</returns>
public delegate Task<string[]> SshKeyboardInteractiveCallback(
    string name,
    string instruction,
    SshKeyboardInteractivePrompt[] prompts,
    CancellationToken cancellationToken);
