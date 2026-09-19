namespace LibSsh2CS;

/// <summary>
/// The parsed content of an <c>SSH_MSG_USERAUTH_INFO_REQUEST</c> challenge
/// (RFC 4252 §5.4): the display name, the instruction text, and the list of
/// prompts (each with its echo flag). Returned by
/// <see cref="SshUserAuth.ParseInfoRequestPayload"/> — the managed
/// counterpart of the C's <c>userauth_keyboard_interactive_decode_info_request</c>
/// (<c>userauth_kbd_packet.c:43-152</c>).
/// </summary>
internal sealed record SshKbdInfoRequest(string Name, string Instruction, SshKeyboardInteractivePrompt[] Prompts);
