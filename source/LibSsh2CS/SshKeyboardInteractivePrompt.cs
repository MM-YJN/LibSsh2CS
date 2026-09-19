namespace LibSsh2CS;

/// <summary>
/// A single prompt in a keyboard-interactive authentication challenge
/// (RFC 4252 §5.4). The server sends a list of prompts; the user callback
/// returns one answer per prompt.
/// </summary>
public sealed record SshKeyboardInteractivePrompt
{
    /// <summary>The prompt text the server wants displayed to the user.</summary>
    public required string Text { get; init; }

    /// <summary>
    /// Whether the answer should be echoed as typed (false for passwords / secrets).
    /// </summary>
    public required bool Echo { get; init; }
}
