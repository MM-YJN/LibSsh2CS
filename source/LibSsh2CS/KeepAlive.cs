namespace LibSsh2CS;

/// <summary>
/// Caller-driven SSH keepalive helper. Mirrors libssh2's <c>keepalive.c</c>
/// (~100 LOC): builds the <c>SSH_MSG_GLOBAL_REQUEST "keepalive@libssh2.org"</c>
/// wire payload and hosts the request name constant.
/// </summary>
/// <remarks>
/// <para>
/// <b>Per-message wire format</b> (<c>keepalive.c:74-80</c>):
/// <code>
/// byte    SSH_MSG_GLOBAL_REQUEST   (= 80)
/// string  "keepalive@libssh2.org"  (21 bytes, no length prefix in the source — the u32 length is 0x15)
/// byte    want_reply               (0 or 1)
/// </code>
/// Total: 27 bytes. The <c>keepalive_data[]</c> C string literal has a trailing
/// <c>'W'</c> placeholder that the send path overwrites with the live
/// <c>session-&gt;keepalive_want_reply</c> value (see <c>keepalive.c:79-80</c>).
/// </para>
/// <para>
/// <b>Caller-driven model.</b> The library never creates background threads or
/// timers. Callers configure the interval via
/// <see cref="SshSession.ConfigureKeepAlive"/> and then call
/// <see cref="SshSession.SendKeepAliveAsync"/> from their own
/// <see cref="PeriodicTimer"/> or <see cref="Task.Delay(int, CancellationToken)"/> loop.
/// </para>
/// <para>
/// The send method is fire-and-forget: when <c>wantReply=true</c>, the reply
/// (<c>SSH_MSG_REQUEST_SUCCESS</c> / <c>SSH_MSG_REQUEST_FAILURE</c>) is not awaited.
/// </para>
/// </remarks>
internal static class KeepAlive
{
    /// <summary>
    /// The keepalive global-request name, verbatim from <c>keepalive.c:75</c>.
    /// 21 ASCII bytes — the <c>0x15</c> length prefix in the wire payload.
    /// </summary>
    public static ReadOnlyMemory<byte> RequestNameBytes { get; } = "keepalive@libssh2.org"u8.ToArray();

    /// <summary>
    /// Builds the 27-byte <c>SSH_MSG_GLOBAL_REQUEST "keepalive@libssh2.org"</c>
    /// payload. Mirrors the <c>keepalive_data[]</c> literal in
    /// <c>keepalive.c:74-75</c>, with the live <paramref name="wantReply"/>
    /// flag substituted into the trailing placeholder byte
    /// (<c>keepalive.c:79-80</c>).
    /// </summary>
    /// <param name="wantReply">The want-reply flag (0 or 1) to write at offset
    /// 26. The C source placeholder is <c>'W'</c> (0x57); this method always
    /// overwrites it with the live value.</param>
    /// <returns>A 27-byte payload beginning with the
    /// <see cref="Transport.PacketType.GlobalRequest"/> type byte (80).</returns>
    public static byte[] BuildPayload(bool wantReply)
    {
        byte[] payload = new byte[27];
        payload[0] = (byte)Transport.PacketType.GlobalRequest;   // 0x50
        // u32 BE name length = 21 (0x15)
        payload[1] = 0;
        payload[2] = 0;
        payload[3] = 0;
        payload[4] = 0x15;
        RequestNameBytes.Span.CopyTo(payload.AsSpan(5, 21));
        payload[26] = (byte)(wantReply ? 1 : 0);
        return payload;
    }
}
