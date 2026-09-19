using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for <see cref="KeyExchange.Negotiate"/>: the client-preference-first
/// matching rule, the AES-GCM MAC override, strict-KEX detection, and the
/// no-overlap failure path. These pin the parity-critical behaviors documented
/// in the libssh2 <c>kex_agree_*</c> audit (<c>kex.c:3598-4040</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>The matching rule is CLIENT-PREF-FIRST</b> (<c>kex.c:3688-3724</c>): for
/// each client-preferred algorithm (in client order), the first one also in the
/// server's name-list wins. This is NOT server-pref-first — the
/// <see cref="Negotiate_ClientPrefFirst_PicksFirstClientPrefInServerList"/> test
/// pins the difference with a case where the two rules would disagree.
/// </para>
/// <para>
/// Synthetic KEXINITs are used (negotiation is pure string matching, no crypto)
/// so the tests can construct adversarial preference orders without needing a
/// live server.
/// </para>
/// </remarks>
public class KexNegotiationTests
{
    // ── Client-preference-first rule (the parity-critical pin) ─────────

    [Fact]
    public void Negotiate_ClientPrefFirst_PicksFirstClientPrefInServerList()
    {
        // Client prefers [A, B, C]; server offers [C, B].
        // Client-pref-first → picks B (first client pref that's in the server list).
        // Server-pref-first would pick C (first server pref in the client list).
        // This test FAILS if the implementation is server-pref-first.
        KexInit client = SyntheticKexInit(
            kex: ["curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384"],
            hostkey: ["ssh-ed25519"],
            cryptCs: ["aes256-ctr"],
            cryptSc: ["aes256-ctr"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"],
            compCs: ["none"],
            compSc: ["none"]);
        KexInit server = SyntheticKexInit(
            kex: ["ecdh-sha2-nistp384", "ecdh-sha2-nistp256"],  // reversed order
            hostkey: ["ssh-ed25519"],
            cryptCs: ["aes256-ctr"],
            cryptSc: ["aes256-ctr"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"],
            compCs: ["none"],
            compSc: ["none"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);

        // Client-pref-first: client's first pref "curve25519-sha256" is NOT in
        // the server list; client's second pref "ecdh-sha2-nistp256" IS — so
        // that's the pick. Server-pref-first would pick "ecdh-sha2-nistp384"
        // (server's first). This assertion pins the rule.
        Assert.Equal("ecdh-sha2-nistp256", n.KexName);
        Assert.Equal(KexAlgorithm.EcdhSha2Nistp256, n.Kex);
    }

    [Fact]
    public void Negotiate_PicksFirstClientPrefWhenServerAlsoListsItFirst()
    {
        // When the client's first preference is also in the server's list, it
        // wins regardless of the server's order.
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"]);
        KexInit server = SyntheticKexInit(kex: ["ecdh-sha2-nistp256", "curve25519-sha256"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);
        Assert.Equal("curve25519-sha256", n.KexName);
    }

    // ── No-overlap failure ─────────────────────────────────────────────

    [Fact]
    public void Negotiate_NoOverlap_ThrowsKexFailure()
    {
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"]);
        KexInit server = SyntheticKexInit(kex: ["diffie-hellman-group1-sha1"]);  // out of scope

        SshException? ex = null;
        try
        {
            _ = KeyExchange.Negotiate(client, server);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    [Fact]
    public void Negotiate_NoOverlapInCipher_ThrowsKexFailure()
    {
        // KEX overlaps but cipher doesn't — still a KexFailure (the category
        // name appears in the error message).
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"], cryptCs: ["aes256-ctr"]);
        KexInit server = SyntheticKexInit(kex: ["curve25519-sha256"], cryptCs: ["blowfish-cbc"]);

        SshException? ex = null;
        try
        {
            _ = KeyExchange.Negotiate(client, server);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
        Assert.Contains("crypt_cs", ex.Message);
    }

    [Fact]
    public void Negotiate_UnsupportedCipherName_ThrowsKexFailureAtNegotiation()
    {
        // Parity: the C's kex_agree_crypt walks the client's method table, so
        // an agreed name outside the library's registry fails at NEGOTIATION
        // with KEX_FAILURE — not at key-install time AFTER NEWKEYS was sent
        // (a protocol desync + wrong error).
        // Reachable when a caller sets a method pref to an out-of-scope name
        // (e.g. blowfish-cbc) on both sides.
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"], cryptCs: ["blowfish-cbc"]);
        KexInit server = SyntheticKexInit(kex: ["curve25519-sha256"], cryptCs: ["blowfish-cbc"]);

        SshException ex = Assert.Throws<SshException>(() => KeyExchange.Negotiate(client, server));

        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
        Assert.Contains("blowfish-cbc", ex.Message);
    }

    [Fact]
    public void Negotiate_UnsupportedMacName_ThrowsKexFailureAtNegotiation()
    {
        // Same validation for the MAC category (hmac-sha1-96 is out of scope;
        // if a caller forces it into the client prefs, the negotiation fails
        // cleanly instead of dying after NEWKEYS).
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"], macCs: ["hmac-sha1-96"]);
        KexInit server = SyntheticKexInit(kex: ["curve25519-sha256"], macCs: ["hmac-sha1-96"]);

        SshException ex = Assert.Throws<SshException>(() => KeyExchange.Negotiate(client, server));

        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
        Assert.Contains("hmac-sha1-96", ex.Message);
    }

    // ── AES-GCM MAC override (mac.c:542-553) ──────────────────────────
    [Fact]
    public void Negotiate_AesGcmCipher_ForcesNoopMac()
    {
        // AES-GCM triggers _libssh2_mac_override → NoopMac, regardless of the
        // MAC name-lists. The negotiated MAC name is "none" (NoopMac.Name).
        KexInit client = SyntheticKexInit(
            kex: ["curve25519-sha256"],
            cryptCs: ["aes256-gcm@openssh.com"],
            cryptSc: ["aes256-gcm@openssh.com"],
            macCs: ["hmac-sha2-256"],  // offered but overridden
            macSc: ["hmac-sha2-256"]);
        KexInit server = SyntheticKexInit(
            kex: ["curve25519-sha256"],
            cryptCs: ["aes256-gcm@openssh.com"],
            cryptSc: ["aes256-gcm@openssh.com"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);

        Assert.Equal("aes256-gcm@openssh.com", n.CipherCs);
        Assert.Equal("aes256-gcm@openssh.com", n.CipherSc);
        // The MAC is overridden to Noop ("none") for AES-GCM.
        Assert.Equal(MacMethods.Noop.Name, n.MacCs);
        Assert.Equal(MacMethods.Noop.Name, n.MacSc);
    }

    [Fact]
    public void Negotiate_Aes128GcmCipher_ForcesNoopMac()
    {
        KexInit client = SyntheticKexInit(
            kex: ["curve25519-sha256"],
            cryptCs: ["aes128-gcm@openssh.com"],
            cryptSc: ["aes128-gcm@openssh.com"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"]);
        KexInit server = SyntheticKexInit(
            kex: ["curve25519-sha256"],
            cryptCs: ["aes128-gcm@openssh.com"],
            cryptSc: ["aes128-gcm@openssh.com"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);
        Assert.Equal(MacMethods.Noop.Name, n.MacCs);
    }

    // ── ChaCha20-Poly1305: real MAC negotiated (mirrors libssh2) ──────

    [Fact]
    public void Negotiate_ChaCha20Poly1305_NegotiatesRealMac()
    {
        // ChaCha20-Poly1305 does NOT trigger the MAC override — a real MAC is
        // negotiated (the transport layer ignores it via REQUIRES_FULL_PACKET).
        // This mirrors libssh2's mac.c:542-553 exactly: only AES-GCM gets the
        // override.
        KexInit client = SyntheticKexInit(
            kex: ["curve25519-sha256"],
            cryptCs: ["chacha20-poly1305@openssh.com"],
            cryptSc: ["chacha20-poly1305@openssh.com"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"]);
        KexInit server = SyntheticKexInit(
            kex: ["curve25519-sha256"],
            cryptCs: ["chacha20-poly1305@openssh.com"],
            cryptSc: ["chacha20-poly1305@openssh.com"],
            macCs: ["hmac-sha2-256"],
            macSc: ["hmac-sha2-256"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);

        Assert.Equal("chacha20-poly1305@openssh.com", n.CipherCs);
        // Real MAC negotiated, NOT Noop.
        Assert.Equal("hmac-sha2-256", n.MacCs);
        Assert.Equal("hmac-sha2-256", n.MacSc);
    }

    // ── Strict-KEX detection (kex.c:3681-3686) ────────────────────────

    [Fact]
    public void Negotiate_ServerKexListContainsKexStrictS_SetsStrictKex()
    {
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"]);
        KexInit server = SyntheticKexInit(kex: ["curve25519-sha256", KeyExchange.KexStrictS]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);
        Assert.True(n.StrictKex);
    }

    [Fact]
    public void Negotiate_ServerKexListLacksKexStrictS_StrictKexFalse()
    {
        KexInit client = SyntheticKexInit(kex: ["curve25519-sha256"]);
        KexInit server = SyntheticKexInit(kex: ["curve25519-sha256"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);
        Assert.False(n.StrictKex);
    }

    // ── Full negotiation against a synthetic server KEXINIT ────────────

    [Fact]
    public void Negotiate_FullEightMethodNegotiation_AllAgreed()
    {
        // A realistic server offering the OpenSSH defaults; the client offers
        // the shipped defaults. All 8 methods should agree.
        KexInit client = SyntheticKexInit(
            kex: [KeyExchange.ExtInfoC, KeyExchange.KexStrictC, "curve25519-sha256", "ecdh-sha2-nistp256"],
            hostkey: ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"],
            cryptCs: ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"],
            cryptSc: ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"],
            macCs: ["hmac-sha2-256", "hmac-sha2-256-etm@openssh.com"],
            macSc: ["hmac-sha2-256", "hmac-sha2-256-etm@openssh.com"],
            compCs: ["none", "zlib@openssh.com"],
            compSc: ["none", "zlib@openssh.com"]);
        KexInit server = SyntheticKexInit(
            kex: ["curve25519-sha256", KeyExchange.KexStrictS, "ecdh-sha2-nistp256"],
            hostkey: ["ssh-ed25519", "rsa-sha2-512"],
            cryptCs: ["chacha20-poly1305@openssh.com", "aes256-ctr"],
            cryptSc: ["chacha20-poly1305@openssh.com", "aes256-ctr"],
            macCs: ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"],
            macSc: ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"],
            compCs: ["none"],
            compSc: ["none"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);

        // Client-pref-first picks the client's first pref that the server offers.
        Assert.Equal(KexAlgorithm.Curve25519Sha256, n.Kex);
        Assert.Equal("curve25519-sha256", n.KexName);
        Assert.Equal(SshHostKeyType.Ed25519, n.HostKey);
        Assert.Equal("ssh-ed25519", n.HostKeyName);
        Assert.Equal("chacha20-poly1305@openssh.com", n.CipherCs);
        Assert.Equal("chacha20-poly1305@openssh.com", n.CipherSc);
        // ChaCha → real MAC (client-pref-first: "hmac-sha2-256" is in both lists).
        Assert.Equal("hmac-sha2-256", n.MacCs);
        Assert.Equal("hmac-sha2-256", n.MacSc);
        Assert.Equal("none", n.CompCs);
        Assert.Equal("none", n.CompSc);
        Assert.True(n.StrictKex);  // server offered kex-strict-s
    }

    [Fact]
    public void Negotiate_PseudoKexMethodOnly_ThrowsKexFailure()
    {
        // If the only "overlap" is a pseudo-method (ext-info-c), there's no
        // real KEX algorithm — negotiation must fail.
        KexInit client = SyntheticKexInit(kex: [KeyExchange.ExtInfoC, KeyExchange.KexStrictC]);
        KexInit server = SyntheticKexInit(kex: [KeyExchange.KexStrictS]);

        SshException? ex = null;
        try
        {
            _ = KeyExchange.Negotiate(client, server);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
    }

    [Fact]
    public void Negotiate_ServerEchoesClientPseudoMethods_AgreesOnRealKex()
    {
        // a server (or echoing proxy) whose kex name-list contains the
        // client-only pseudo-methods (ext-info-c / kex-strict-c) must NOT win
        // the agreement — the pseudo-methods sit at the head of the client
        // list, so pre-fix the first match was a pseudo-method and the
        // handshake aborted with KexFailure even though a real overlap exists.
        // The C's default-preference agreement walks its own real-method table
        // (kex.c:3719-3724) and never matches pseudo-methods.
        KexInit client = SyntheticKexInit(
            kex: [KeyExchange.ExtInfoC, KeyExchange.KexStrictC, "curve25519-sha256"]);
        KexInit server = SyntheticKexInit(
            kex: [KeyExchange.ExtInfoC, KeyExchange.KexStrictC, KeyExchange.KexStrictS,
                "curve25519-sha256", "ecdh-sha2-nistp256"]);

        NegotiatedMethods n = KeyExchange.Negotiate(client, server);

        // The real overlap (curve25519-sha256) wins; strict-KEX detection from
        // the server's kex-strict-s marker still works.
        Assert.Equal("curve25519-sha256", n.KexName);
        Assert.Equal(KexAlgorithm.Curve25519Sha256, n.Kex);
        Assert.True(n.StrictKex);
    }

    [Fact]
    public void Negotiate_ServerEchoesOnlyClientPseudoMethods_ThrowsKexFailure()
    {
        // if the ONLY overlap is a pseudo-method, there is no real KEX
        // algorithm — negotiation fails with KexFailure exactly like the C's
        // kex_agree_kex_hostkey returning -1 (no entry in the real-method
        // table matches). The error must NOT claim a pseudo-method was
        // "negotiated".
        KexInit client = SyntheticKexInit(
            kex: [KeyExchange.ExtInfoC, KeyExchange.KexStrictC, "curve25519-sha256"]);
        KexInit server = SyntheticKexInit(
            kex: [KeyExchange.ExtInfoC, KeyExchange.KexStrictC]);

        SshException? ex = null;
        try
        {
            _ = KeyExchange.Negotiate(client, server);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.KexFailure, ex.ErrorCode);
        Assert.Contains("no agreed kex", ex.Message);
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a synthetic <see cref="KexInit"/> with the given name-lists and
    /// neutral defaults for the unspecified fields (cookie, first_kex, reserved).
    /// Used by the negotiation tests to construct adversarial preference orders
    /// without spinning up a real server.
    /// </summary>
    private static KexInit SyntheticKexInit(
        string[] kex,
        string[]? hostkey = null,
        string[]? cryptCs = null,
        string[]? cryptSc = null,
        string[]? macCs = null,
        string[]? macSc = null,
        string[]? compCs = null,
        string[]? compSc = null)
    {
        return new KexInit
        {
            Cookie = new byte[16],
            KexAlgorithms = kex,
            ServerHostKeyAlgorithms = hostkey ?? ["ssh-ed25519"],
            EncryptionAlgorithmsClientToServer = cryptCs ?? ["aes256-ctr"],
            EncryptionAlgorithmsServerToClient = cryptSc ?? ["aes256-ctr"],
            MacAlgorithmsClientToServer = macCs ?? ["hmac-sha2-256"],
            MacAlgorithmsServerToClient = macSc ?? ["hmac-sha2-256"],
            CompressionAlgorithmsClientToServer = compCs ?? ["none"],
            CompressionAlgorithmsServerToClient = compSc ?? ["none"],
            LanguagesClientToServer = [],
            LanguagesServerToClient = [],
            FirstKexPacketFollows = false,
            Reserved = 0,
        };
    }
}
