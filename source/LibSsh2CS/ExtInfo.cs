using System.Buffers;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS;

/// <summary>
/// Parsed <c>SSH_MSG_EXT_INFO</c> payload (RFC 8308). Carries server-advertised
/// extensions, most importantly <c>server-sig-algs</c> (RFC 8308 §3.1) which
/// drives RSA-SHA2 algorithm selection in publickey auth
/// (<c>userauth.c:1351</c> <c>_libssh2_key_sign_algorithm</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format</b> (RFC 8308 §2.2): <c>byte SSH_MSG_EXT_INFO (7) | uint32
/// nr-extensions | [string name | string value]*</c>. The payload begins with
/// the type byte (7). Values are opaque byte strings; their interpretation
/// depends on the extension name.
/// </para>
/// <para>
/// Exposes <c>server-sig-algs</c>; other extensions are parsed
/// and stored by name but not interpreted. The <c>PacketQueue</c> stashes the
/// raw EXT_INFO packet during the initial KEX
/// (<c>packet.c:848-908</c>); <c>SshSession.HandshakeAsync</c> retrieves it and
/// calls <see cref="Parse"/> to populate this record.
/// </para>
/// </remarks>
internal sealed record ExtInfo
{
    /// <summary>The <c>server-sig-algs</c> extension value split on commas, or
    /// an empty array if the server did not advertise it. Used by
    /// <c>UserAuth</c> to pick the strongest RSA-SHA2 variant the server
    /// accepts (parity with <c>userauth.c:1410-1440</c>).</summary>
    public required string[] ServerSignatureAlgorithms { get; init; }

    /// <summary>All extension (name, value) pairs in wire order. Values are raw
    /// bytes — callers must interpret them per the extension's spec. Kept for
    /// forward-compatibility (future extensions can be surfaced without a new
    /// parse path).</summary>
    public required (string Name, byte[] Value)[] Extensions { get; init; }

    /// <summary>
    /// Parses an <c>SSH_MSG_EXT_INFO</c> payload (beginning with the type byte
    /// 7) into an <see cref="ExtInfo"/>. Port of <c>packet.c:848-908</c>'s
    /// inline parse (which lives there as the KEX flow's responsibility; here it
    /// is deferred to a dedicated type so the session can call it post-KEX).
    /// </summary>
    /// <param name="payload">The full EXT_INFO packet payload, starting with
    /// the type byte <c>SSH_MSG_EXT_INFO (7)</c>.</param>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.Proto"/> if the payload is not an EXT_INFO or is
    /// truncated.</exception>
    public static ExtInfo Parse(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length == 0 || payload.Span[0] != PacketType.ExtInfo)
        {
            throw new SshException(SshErrorCode.Proto,
                "ParseExtInfo: payload does not begin with SSH_MSG_EXT_INFO");
        }

        var seq = new ReadOnlySequence<byte>(payload.ToArray());
        var r = new PacketWireReader(seq);
        _ = r.ReadByte();   // skip type byte (7)
        uint nrExtensions = r.ReadUInt32BigEndian();

        // Cap to a sane bound (packet.c doesn't, but a malicious 4G count would OOM).
        if (nrExtensions > 256)
        {
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"EXT_INFO: nr-extensions {nrExtensions} > 256");
        }

        var extensions = new (string Name, byte[] Value)[nrExtensions];
        string[] serverSigAlgs = [];

        for (int i = 0; i < (int)nrExtensions; i++)
        {
            string name = r.ReadString();
            byte[] value = r.ReadBlob();
            extensions[i] = (name, value);

            if (name == "server-sig-algs")
            {
                // The value is a UTF-8 comma-separated algorithm name-list
                // (RFC 8308 §3.1). Split now so UserAuth can index it directly.
                string algList = System.Text.Encoding.UTF8.GetString(value);
                serverSigAlgs = algList.Length == 0 ? [] : algList.Split(',');
            }
        }

        return new ExtInfo
        {
            ServerSignatureAlgorithms = serverSigAlgs,
            Extensions = extensions,
        };
    }
}
