namespace LibSsh2CS.Transport;

/// <summary>
/// SSH packet (message) type constants, verbatim from the numeric values in
/// <c>libssh2_priv.h:1121</c> ("SSH Packet Types -- Defined by internet draft",
/// RFC 4250-4254). Pure data; no behaviour.
/// </summary>
/// <remarks>
/// <para>
/// Several message numbers are reused across different key-exchange families
/// (DH group1/14, DH group-exchange, and ECDH all share <c>30</c>/<c>31</c>),
/// and the <c>60</c> slot is reused by three different userauth methods. The
/// distinct <see cref="int"/> constants below preserve libssh2's named aliases
/// even where they collide numerically — selection happens by context, not by
/// type value.
/// </para>
/// </remarks>
internal static class PacketType
{
    // ── Transport layer (RFC 4253 §11) ───────────────────────────────
    public const int Disconnect = 1;
    public const int Ignore = 2;
    public const int Unimplemented = 3;
    public const int Debug = 4;
    public const int ServiceRequest = 5;
    public const int ServiceAccept = 6;
    public const int ExtInfo = 7;

    // ── Key exchange ─────────────────────────────────────────────────
    public const int KexInit = 20;
    public const int NewKeys = 21;

    // diffie-hellman-group1-sha1 / group14 — also KEX_DH_GEX_REQUEST_OLD,
    // also SSH2_MSG_KEX_ECDH_INIT.
    public const int KexDhInit = 30;
    // group1/14 reply — also KEX_DH_GEX_GROUP, also SSH2_MSG_KEX_ECDH_REPLY.
    public const int KexDhReply = 31;

    // diffie-hellman-group-exchange (sha1 / sha256) — distinct numbers.
    public const int KexDhGexRequest = 34;
    public const int KexDhGexInit = 32;
    public const int KexDhGexReply = 33;

    // ── User authentication (RFC 4252) ───────────────────────────────
    public const int UserauthRequest = 50;
    public const int UserauthFailure = 51;
    public const int UserauthSuccess = 52;
    public const int UserauthBanner = 53;

    // The 60 slot is overloaded by three userauth methods (selected by context).
    public const int UserauthPkOk = 60;              // "publickey"
    public const int UserauthPasswdChangereq = 60;   // "password"
    public const int UserauthInfoRequest = 60;       // "keyboard-interactive"
    public const int UserauthInfoResponse = 61;

    // ── Channels (RFC 4254) ──────────────────────────────────────────
    public const int GlobalRequest = 80;
    public const int RequestSuccess = 81;
    public const int RequestFailure = 82;

    public const int ChannelOpen = 90;
    public const int ChannelOpenConfirmation = 91;
    public const int ChannelOpenFailure = 92;
    public const int ChannelWindowAdjust = 93;
    public const int ChannelData = 94;
    public const int ChannelExtendedData = 95;
    public const int ChannelEof = 96;
    public const int ChannelClose = 97;
    public const int ChannelRequest = 98;
    public const int ChannelSuccess = 99;
    public const int ChannelFailure = 100;
}
