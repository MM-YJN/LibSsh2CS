using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for <see cref="KeyExchange.BuildKexInit"/> /
/// <see cref="KeyExchange.ParseKexInit"/>: KEXINIT wire-format build/parse
/// round-trip, extension prepend, and parsing of a real captured KEXINIT from
/// the libssh2 capture harness.
/// </summary>
/// <remarks>
/// The captured KEXINIT lives at <c>Fixtures/packet/cleartext/pkt_0_out.pt</c>
/// (1630 bytes, type byte 20). Its <c>meta.json</c> records the negotiated
/// algorithm names, which we cross-check against the parsed name-lists.
/// </remarks>
public class KexInitTests
{
    // ── Build → Parse round-trip ───────────────────────────────────────

    [Fact]
    public void Build_Parse_RoundTrip_PreservesAllNameLists()
    {
        var prefs = new MethodPreferences();
        byte[] built = KeyExchange.BuildKexInit(prefs);
        KexInit parsed = KeyExchange.ParseKexInit(built);

        // Cookie is random; just check length + that build produced 16 bytes.
        Assert.Equal(16, parsed.Cookie.Length);

        // first_kex_packet_follows is always false (kex.c:3440).
        Assert.False(parsed.FirstKexPacketFollows);
        // reserved is always 0 (kex.c:3443).
        Assert.Equal(0u, parsed.Reserved);

        // All 8 algorithm name-lists should round-trip to the defaults
        // (the prefs were empty, so BuildKexInit falls back to DefaultPreferences).
        Assert.Equal(KexMethods.DefaultPreferences.Concat(new[] { KeyExchange.ExtInfoC, KeyExchange.KexStrictC }).OrderBy(n => n),
            parsed.KexAlgorithms.OrderBy(n => n));
        Assert.Equal(HostKeyMethods.DefaultPreferences, parsed.ServerHostKeyAlgorithms);
        Assert.Equal(CipherMethods.DefaultPreferences, parsed.EncryptionAlgorithmsClientToServer);
        Assert.Equal(CipherMethods.DefaultPreferences, parsed.EncryptionAlgorithmsServerToClient);
        Assert.Equal(MacMethods.DefaultPreferences, parsed.MacAlgorithmsClientToServer);
        Assert.Equal(MacMethods.DefaultPreferences, parsed.MacAlgorithmsServerToClient);
        Assert.Equal(CompressionMethods.DefaultPreferences, parsed.CompressionAlgorithmsClientToServer);
        Assert.Equal(CompressionMethods.DefaultPreferences, parsed.CompressionAlgorithmsServerToClient);
        // Languages default to empty.
        Assert.Empty(parsed.LanguagesClientToServer);
        Assert.Empty(parsed.LanguagesServerToClient);
    }

    [Fact]
    public void Build_AlwaysPrependsExtInfoCAndKexStrictC()
    {
        // Even with no user prefs, the kex name-list starts with the two
        // extensions.
        var prefs = new MethodPreferences();
        byte[] built = KeyExchange.BuildKexInit(prefs);
        KexInit parsed = KeyExchange.ParseKexInit(built);

        Assert.Equal(KeyExchange.ExtInfoC, parsed.KexAlgorithms[0]);
        Assert.Equal(KeyExchange.KexStrictC, parsed.KexAlgorithms[1]);
    }

    [Fact]
    public void Build_PrependsExtensionsEvenWithUserPrefs()
    {
        // User sets a custom kex pref — extensions still prepend (kex.c:4199).
        var prefs = new MethodPreferences
        {
            [SshMethodType.Kex] = "diffie-hellman-group14-sha256",
        };
        byte[] built = KeyExchange.BuildKexInit(prefs);
        KexInit parsed = KeyExchange.ParseKexInit(built);

        Assert.Equal(KeyExchange.ExtInfoC, parsed.KexAlgorithms[0]);
        Assert.Equal(KeyExchange.KexStrictC, parsed.KexAlgorithms[1]);
        Assert.Equal("diffie-hellman-group14-sha256", parsed.KexAlgorithms[2]);
    }

    [Fact]
    public void Build_UserPrefsOverrideDefaults_ForNonKexCategories()
    {
        var prefs = new MethodPreferences
        {
            [SshMethodType.CryptCs] = "aes256-ctr",
            [SshMethodType.MacCs] = "hmac-sha2-256",
        };
        byte[] built = KeyExchange.BuildKexInit(prefs);
        KexInit parsed = KeyExchange.ParseKexInit(built);

        // The user-set categories use the user's list; others fall back to defaults.
        Assert.Equal(new[] { "aes256-ctr" }, parsed.EncryptionAlgorithmsClientToServer);
        Assert.Equal(new[] { "hmac-sha2-256" }, parsed.MacAlgorithmsClientToServer);
        // Unset categories still default.
        Assert.Equal(CipherMethods.DefaultPreferences, parsed.EncryptionAlgorithmsServerToClient);
    }

    [Fact]
    public void Build_PayloadBeginsWithTypeByte()
    {
        var prefs = new MethodPreferences();
        byte[] built = KeyExchange.BuildKexInit(prefs);

        // The payload must begin with SSH_MSG_KEXINIT (20) so it can be handed
        // directly to PacketWriter.WritePacketAsync.
        Assert.Equal(PacketType.KexInit, built[0]);
    }

    [Fact]
    public void Parse_RejectsPayloadNotBeginningWithTypeByte()
    {
        byte[] bad = new byte[20];
        bad[0] = 99; // not SSH_MSG_KEXINIT

        SshException? ex = null;
        try
        {
            _ = KeyExchange.ParseKexInit(bad);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.Proto, ex.ErrorCode);
    }

    // ── Captured KEXINIT parse (parity with real libssh2 output) ───────

    [Fact]
    public void Parse_CapturedClientKexInit_NameListsParseCleanly()
    {
        // The cleartext fixture's packet 0 is the client's outbound KEXINIT
        // (1630 bytes, type byte 20), captured from a real libssh2 handshake
        // against OpenSSH. Parsing it must succeed and produce non-empty
        // name-lists for the negotiated categories.
        PacketFixture fx = PacketFixtureLoader.Load("cleartext");
        byte[] kexinitBytes = fx.Packets[0].Plaintext;
        Assert.Equal(PacketType.KexInit, kexinitBytes[0]);

        KexInit parsed = KeyExchange.ParseKexInit(kexinitBytes);

        // The captured client offered real algorithms.
        Assert.NotEmpty(parsed.KexAlgorithms);
        Assert.NotEmpty(parsed.ServerHostKeyAlgorithms);
        Assert.NotEmpty(parsed.EncryptionAlgorithmsClientToServer);

        // The negotiated kex (from meta.json) must appear in the client's
        // offered kex name-list — otherwise negotiation would have failed.
        Assert.Contains(fx.NegotiatedKex, parsed.KexAlgorithms);
        Assert.Contains(fx.NegotiatedHostkey, parsed.ServerHostKeyAlgorithms);
        Assert.Contains(fx.NegotiatedCipher, parsed.EncryptionAlgorithmsClientToServer);

        // The captured client should have sent ext-info-c (libssh2 1.11 always
        // does). kex-strict-c may or may not be present depending on the libssh2
        // build; we assert only ext-info-c.
        Assert.Contains(KeyExchange.ExtInfoC, parsed.KexAlgorithms);

        // first_kex_packet_follows is always false from libssh2.
        Assert.False(parsed.FirstKexPacketFollows);
        Assert.Equal(0u, parsed.Reserved);
    }
}
