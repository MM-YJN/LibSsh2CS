using System.Buffers.Binary;
using System.Text;

namespace LibSsh2CS.Transport;

/// <summary>
/// <c>SSH_MSG_GLOBAL_REQUEST</c> (80) payload builder. Mirrors the
/// payload shape sent by libssh2's <c>channel.c:577-582</c> for
/// <c>tcpip-forward</c> / <c>cancel-tcpip-forward</c> and by
/// <c>keepalive.c:74-80</c> for <c>keepalive@libssh2.org</c>:
/// <code>
/// byte    SSH_MSG_GLOBAL_REQUEST (= 80)
/// string  request_name      (ASCII, e.g. "keepalive@libssh2.org")
/// byte    want_reply        (0 or 1)
/// byte[]  type-specific extra data
/// </code>
/// </summary>
/// <remarks>
/// The reply (<c>SSH_MSG_REQUEST_SUCCESS</c> = 81 / <c>SSH_MSG_REQUEST_FAILURE</c>
/// = 82) is routed by <see cref="ChannelRouter.RouteRoutableAsync"/>; the
/// awaiting caller is <see cref="ChannelRouter.SendGlobalRequestAsync"/>.
/// </remarks>
internal static class GlobalRequest
{
    /// <summary>
    /// Builds a <c>SSH_MSG_GLOBAL_REQUEST</c> payload.
    /// </summary>
    /// <param name="name">ASCII request name (no length-prefix — the BE32
    /// length is written by this method).</param>
    /// <param name="extra">Type-specific request data appended after the
    /// standard header. Pass <see cref="ReadOnlyMemory{T}.Empty"/> for
    /// name-only requests.</param>
    /// <param name="wantReply"><see langword="true"/> for want_reply=1,
    /// <see langword="false"/> for want_reply=0.</param>
    /// <returns>A payload beginning with the
    /// <see cref="PacketType.GlobalRequest"/> type byte (80).</returns>
    public static byte[] BuildPayload(string name, ReadOnlyMemory<byte> extra, bool wantReply)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        byte[] payload = new byte[1 + 4 + nameBytes.Length + 1 + extra.Length];
        int o = 0;
        payload[o++] = (byte)PacketType.GlobalRequest;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(o, 4), nameBytes.Length);
        o += 4;
        Buffer.BlockCopy(nameBytes, 0, payload, o, nameBytes.Length);
        o += nameBytes.Length;
        payload[o++] = (byte)(wantReply ? 1 : 0);
        if (!extra.IsEmpty)
        {
            extra.Span.CopyTo(payload.AsSpan(o, extra.Length));
        }

        return payload;
    }
}
