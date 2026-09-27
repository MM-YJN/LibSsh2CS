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
        int nameLength = Encoding.ASCII.GetByteCount(name);
        byte[] payload = new byte[1 + 4 + nameLength + 1 + extra.Length];
        int offset = WriteHeader(payload, name, wantReply);
        extra.Span.CopyTo(payload.AsSpan(offset));
        return payload;
    }

    internal static int WriteHeader(Span<byte> destination, string name, bool wantReply)
    {
        int nameLength = Encoding.ASCII.GetByteCount(name);
        destination[0] = (byte)PacketType.GlobalRequest;
        BinaryPrimitives.WriteInt32BigEndian(destination.Slice(1, 4), nameLength);
        Encoding.ASCII.GetBytes(name, destination.Slice(5, nameLength));
        destination[5 + nameLength] = wantReply ? (byte)1 : (byte)0;
        return 6 + nameLength;
    }

    internal static int GetForwardExtraLength(string host) => checked(8 + Encoding.UTF8.GetByteCount(host));

    internal static void WriteForwardExtra(Span<byte> destination, (string Host, int Port) state)
    {
        int hostLength = Encoding.UTF8.GetByteCount(state.Host);
        BinaryPrimitives.WriteInt32BigEndian(destination, hostLength);
        Encoding.UTF8.GetBytes(state.Host, destination.Slice(4, hostLength));
        BinaryPrimitives.WriteInt32BigEndian(destination.Slice(4 + hostLength, 4), state.Port);
    }
}
