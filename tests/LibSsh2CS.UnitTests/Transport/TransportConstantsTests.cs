using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for the Phase 1 increment-4 pure-data constants: <see cref="PacketType"/>
/// (SSH message numbers) and <see cref="SessionState"/> (the session state bitmask).
/// Values are pinned to <c>libssh2_priv.h</c> for wire/state parity.
/// </summary>
public class TransportConstantsTests
{
    // ── PacketType: numeric parity with libssh2_priv.h:1123 ───────────

    [Fact]
    public void PacketType_TransportLayerNumbers_MatchSpec()
    {
        Assert.Equal(1, PacketType.Disconnect);
        Assert.Equal(2, PacketType.Ignore);
        Assert.Equal(3, PacketType.Unimplemented);
        Assert.Equal(4, PacketType.Debug);
        Assert.Equal(5, PacketType.ServiceRequest);
        Assert.Equal(6, PacketType.ServiceAccept);
        Assert.Equal(7, PacketType.ExtInfo);
    }

    [Fact]
    public void PacketType_KeyExchangeNumbers_MatchSpec()
    {
        Assert.Equal(20, PacketType.KexInit);
        Assert.Equal(21, PacketType.NewKeys);
    }

    [Fact]
    public void PacketType_DhAndEcdhShareSlots_30_31()
    {
        // DH group1/14 and ECDH reuse the 30/31 slots (context-selected).
        Assert.Equal(30, PacketType.KexDhInit);
        Assert.Equal(31, PacketType.KexDhReply);

        // group-exchange has its own 32/33/34 numbers.
        Assert.Equal(32, PacketType.KexDhGexInit);
        Assert.Equal(33, PacketType.KexDhGexReply);
        Assert.Equal(34, PacketType.KexDhGexRequest);
    }

    [Fact]
    public void PacketType_UserauthNumbers_MatchSpec()
    {
        Assert.Equal(50, PacketType.UserauthRequest);
        Assert.Equal(51, PacketType.UserauthFailure);
        Assert.Equal(52, PacketType.UserauthSuccess);
        Assert.Equal(53, PacketType.UserauthBanner);
        Assert.Equal(61, PacketType.UserauthInfoResponse);
    }

    [Fact]
    public void PacketType_Slot60_IsOverloadedByThreeMethods()
    {
        Assert.Equal(60, PacketType.UserauthPkOk);
        Assert.Equal(60, PacketType.UserauthPasswdChangereq);
        Assert.Equal(60, PacketType.UserauthInfoRequest);
    }

    [Fact]
    public void PacketType_ChannelNumbers_MatchSpec()
    {
        Assert.Equal(80, PacketType.GlobalRequest);
        Assert.Equal(81, PacketType.RequestSuccess);
        Assert.Equal(82, PacketType.RequestFailure);
        Assert.Equal(90, PacketType.ChannelOpen);
        Assert.Equal(93, PacketType.ChannelWindowAdjust);
        Assert.Equal(94, PacketType.ChannelData);
        Assert.Equal(95, PacketType.ChannelExtendedData);
        Assert.Equal(96, PacketType.ChannelEof);
        Assert.Equal(97, PacketType.ChannelClose);
        Assert.Equal(98, PacketType.ChannelRequest);
        Assert.Equal(99, PacketType.ChannelSuccess);
        Assert.Equal(100, PacketType.ChannelFailure);
    }

    // ── SessionState: bitmask parity with libssh2_priv.h:953 ──────────

    [Fact]
    public void SessionState_FlagValues_MatchSpec()
    {
        Assert.Equal(0x0000_0001, (int)SessionState.InitialKex);
        Assert.Equal(0x0000_0002, (int)SessionState.ExchangingKeys);
        Assert.Equal(0x0000_0004, (int)SessionState.NewKeys);
        Assert.Equal(0x0000_0008, (int)SessionState.Authenticated);
        Assert.Equal(0x0000_0010, (int)SessionState.KexActive);
    }

    [Fact]
    public void SessionState_None_IsZero()
    {
        Assert.Equal(0, (int)SessionState.None);
    }

    [Fact]
    public void SessionState_CombinesAsBitmask()
    {
        SessionState combined = SessionState.NewKeys | SessionState.Authenticated;
        Assert.True(combined.HasFlag(SessionState.NewKeys));
        Assert.True(combined.HasFlag(SessionState.Authenticated));
        Assert.False(combined.HasFlag(SessionState.InitialKex));
        Assert.Equal(0x0000_000C, (int)combined);
    }
}
