// Translated from the Pageant client code in libssh2 src/agent.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * Code to talk to Pageant was taken from PuTTY.
 *
 * Portions copyright Robert de Bath, Joris van Rantwijk, Delian
 * Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas
 * Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa,
 * Markus Kuhn, Colin Watson, and CORE SDI S.A.
 */

using System.Globalization;

namespace LibSsh2CS.Agent;

/// <summary>
/// The constants Pageant's window-message IPC imposes on its client, translated
/// from libssh2's <c>agent.c</c> (<c>PAGEANT_COPYDATA_ID</c>,
/// <c>PAGEANT_MAX_MSGLEN</c>) and the mapping name PuTTY's client builds.
/// </summary>
/// <remarks>
/// Pageant serves agent requests from a window rather than a socket: the client
/// writes the request into a file mapping named after the calling thread and
/// then hands that name to Pageant with a <c>WM_COPYDATA</c> message. The
/// constant values here must match Pageant's own expectations exactly — the
/// window class and title are both <c>Pageant</c>, <c>dwData</c> must equal
/// <see cref="CopyDataId"/>, and the mapping must be large enough for the
/// largest framed message (<c>PAGEANT_MAX_MSGLEN</c>, <c>agent.c:337</c>).
/// </remarks>
internal static class PageantIpc
{
    /// <summary>
    /// Pageant's marker for <c>COPYDATASTRUCT.dwData</c> (<c>PAGEANT_COPYDATA_ID</c>,
    /// <c>agent.c:336</c>). The value itself is arbitrary; Pageant ignores
    /// <c>WM_COPYDATA</c> messages that carry anything else.
    /// </summary>
    internal const nuint CopyDataId = 0x804e50ba;

    /// <summary>
    /// Size of the shared mapping Pageant reads requests from and writes
    /// responses into (<c>PAGEANT_MAX_MSGLEN</c>, <c>agent.c:337</c>).
    /// </summary>
    internal const int MaxMessageLength = 8192;

    /// <summary>
    /// Largest agent payload that fits in <see cref="MaxMessageLength"/> once
    /// the 4-byte big-endian length prefix on the wire framing is accounted
    /// for. libssh2 checks only <c>4 + request_len &gt; PAGEANT_MAX_MSGLEN</c>
    /// before writing and accepts responses of up to
    /// <c>PAGEANT_MAX_MSGLEN</c> bytes after the prefix; both are clamped here
    /// so no read or write can run past the mapping.
    /// </summary>
    internal const int MaxPayloadLength = MaxMessageLength - sizeof(uint);

    /// <summary>
    /// The name the request mapping is published under:
    /// <c>PageantRequest%08x</c> with the id of the calling thread
    /// (<c>agent.c:365-366</c>).
    /// </summary>
    /// <param name="threadId">
    /// Identifier of the thread performing the round trip. The name embeds it,
    /// so concurrent callers never collide — and so it must be computed on the
    /// thread that creates the mapping.
    /// </param>
    /// <returns>The mapping name Pageant is asked to open.</returns>
    internal static string MappingName(uint threadId)
        => string.Create(CultureInfo.InvariantCulture, $"PageantRequest{threadId:x8}");
}
