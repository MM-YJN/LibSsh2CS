using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

using LibSsh2CS.Util;

namespace LibSsh2CS.Transport;

/// <summary>
/// KEXINIT build, parse, and algorithm negotiation — a 1:1 managed port of
/// libssh2's <c>kexinit()</c> (<c>kex.c:3349</c>), <c>kex_agree_methods()</c>
/// (<c>kex.c:3935</c>), and the per-category <c>kex_agree_*</c> helpers
/// (<c>kex.c:3598-3924</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Parity-critical: the matching rule is CLIENT-PREFERENCE-FIRST.</b> For
/// every algorithm category, iterate the <em>client's</em> preference list in
/// order; the first entry that also appears in the server's name-list wins
/// (<c>kex.c:3688-3724</c> and all other <c>kex_agree_*</c> functions). This is
/// NOT server-pref-first — a test pins the difference (client <c>[A,B,C]</c>
/// vs server <c>[C,B]</c> must pick <c>B</c>, not <c>C</c>).
/// </para>
/// <para>
/// <b>Negotiation order</b> (parity-critical, <c>kex.c:3994</c>): KEX +
/// hostkey together → cipher_cs → cipher_sc → <em>then</em> mac_cs → mac_sc
/// (MAC after cipher, because the GCM MAC override depends on the negotiated
/// cipher) → comp_cs → comp_sc.
/// </para>
/// <para>
/// <b>GCM MAC override</b> (<c>mac.c:542-553</c>): only AES-GCM ciphers force
/// <see cref="MacMethods.Noop"/>. ChaCha20-Poly1305 negotiates a real MAC
/// (the transport layer ignores it via the <c>REQUIRES_FULL_PACKET</c> flag).
/// This mirrors libssh2 exactly.
/// </para>
/// <para>
/// <b>Strict-KEX detection</b> (<c>kex.c:3681-3686</c>): scan the server's kex
/// name-list for <c>kex-strict-s-v00@openssh.com</c>; if present, set
/// <see cref="NegotiatedMethods.StrictKex"/>. The client always prepends
/// <c>kex-strict-c-v00@openssh.com</c> to its own kex name-list
/// (<c>kex.c:4199</c>); this port always prepends both
/// extensions regardless of user prefs (functionally equivalent to the C
/// append-when-defaults path).
/// </para>
/// <para>
/// <see cref="RunExchangeAsync"/> performs the DH/ECDH/X25519 math,
/// computes the exchange hash <c>H</c>, derives keys, and exchanges NEWKEYS.
/// </para>
/// </remarks>
internal static class KeyExchange
{
    /// <summary>The SSH_MSG_KEXINIT cookie length (RFC 4253 §7.1).</summary>
    private const int CookieLen = 16;

    /// <summary>
    /// The two pseudo-kex extensions prepended to the client's kex name-list
    /// (<c>kex.c:4199</c>). <c>ext-info-c</c> signals the client can receive
    /// SSH_MSG_EXT_INFO (RFC 8308); <c>kex-strict-c-v00@openssh.com</c> opts
    /// into the Terrapin strict-KEX rules. The server's counterparts are
    /// <c>ext-info-s</c> (implicit — handled whenever SSH_MSG_EXT_INFO arrives)
    /// and <c>kex-strict-s-v00@openssh.com</c> (detected in
    /// <see cref="Negotiate"/>).
    /// </summary>
    public const string ExtInfoC = "ext-info-c";

    /// <summary>The client-side strict-KEX extension name.</summary>
    public const string KexStrictC = "kex-strict-c-v00@openssh.com";

    /// <summary>The server-side strict-KEX extension name (detected in negotiation).</summary>
    public const string KexStrictS = "kex-strict-s-v00@openssh.com";

    /// <summary>
    /// Builds the SSH_MSG_KEXINIT payload (including the type byte) from the
    /// caller's method preferences. Always prepends <see cref="ExtInfoC"/> and
    /// <see cref="KexStrictC"/> to the kex name-list.
    /// Generates a fresh 16-byte random cookie via <see cref="RandomNumberGenerator"/>.
    /// Port of <c>kexinit()</c> (<c>kex.c:3349</c>).
    /// </summary>
    /// <param name="prefs">The caller's pre-handshake preferences. Categories
    /// that are unset (<c>!IsSet</c>) fall back to the corresponding
    /// <c>DefaultPreferences</c> list, mirroring libssh2's
    /// <c>LIBSSH2_METHOD_PREFS_STR</c> macro (<c>kex.c:3332</c>).</param>
    public static byte[] BuildKexInit(MethodPreferences prefs)
    {
        // The payload starts with the SSH_MSG_KEXINIT type byte.
        using var ms = new MemoryStream(2048);
        ms.WriteByte((byte)PacketType.KexInit);

        // 16-byte random cookie (kex.c:3404-3409, _libssh2_random).
        byte[] cookie = new byte[CookieLen];
        RandomNumberGenerator.Fill(cookie);
        ms.Write(cookie, 0, CookieLen);

        // 10 name-lists. Each uses the user-set pref string if non-empty,
        // otherwise the DefaultPreferences list. The kex name-list always
        // gets the two extensions prepended.
        WriteNameList(ms, BuildKexPrefs(prefs));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.HostKey, HostKeyMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.CryptCs, CipherMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.CryptSc, CipherMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.MacCs, MacMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.MacSc, MacMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.CompCs, CompressionMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.CompSc, CompressionMethods.DefaultPreferences));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.LangCs, [""]));
        WriteNameList(ms, BuildPrefs(prefs, SshMethodType.LangSc, [""]));

        // first_kex_packet_follows = false (kex.c:3440). libssh2 never sends an
        // optimistic KEX packet; we mirror that.
        ms.WriteByte(0);

        // reserved uint32 = 0 (kex.c:3443).
        Span<byte> reserved = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(reserved, 0u);
        ms.Write(reserved);

        return ms.ToArray();
    }

    /// <summary>
    /// Parses an SSH_MSG_KEXINIT payload (beginning with the type byte) into a
    /// <see cref="KexInit"/> record. Port of <c>kex_agree_methods</c>'s
    /// name-list extraction (<c>kex.c:3935-3980</c>). Throws
    /// <see cref="SshException"/>(<see cref="SshErrorCode.OutOfBoundary"/>) on
    /// truncation.
    /// </summary>
    public static KexInit ParseKexInit(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length == 0 || payload.Span[0] != PacketType.KexInit)
        {
            throw new SshException(SshErrorCode.Proto,
                "ParseKexInit: payload does not begin with SSH_MSG_KEXINIT");
        }

        // Slice past the type byte; the rest is cookie + 10 name-lists + bool + u32.
        var seq = new ReadOnlySequence<byte>(payload.ToArray());
        var r = new PacketWireReader(seq);
        _ = r.ReadByte(); // consume the type byte

        byte[] cookie = r.ReadBytes(CookieLen);
        string[] kex = r.ReadNameList();
        string[] hostkey = r.ReadNameList();
        string[] cryptCs = r.ReadNameList();
        string[] cryptSc = r.ReadNameList();
        string[] macCs = r.ReadNameList();
        string[] macSc = r.ReadNameList();
        string[] compCs = r.ReadNameList();
        string[] compSc = r.ReadNameList();
        string[] langCs = r.ReadNameList();
        string[] langSc = r.ReadNameList();
        bool firstKexFollows = r.ReadByte() != 0;
        uint reserved = r.ReadUInt32BigEndian();

        return new KexInit
        {
            Cookie = cookie,
            KexAlgorithms = kex,
            ServerHostKeyAlgorithms = hostkey,
            EncryptionAlgorithmsClientToServer = cryptCs,
            EncryptionAlgorithmsServerToClient = cryptSc,
            MacAlgorithmsClientToServer = macCs,
            MacAlgorithmsServerToClient = macSc,
            CompressionAlgorithmsClientToServer = compCs,
            CompressionAlgorithmsServerToClient = compSc,
            LanguagesClientToServer = langCs,
            LanguagesServerToClient = langSc,
            FirstKexPacketFollows = firstKexFollows,
            Reserved = reserved,
        };
    }

    /// <summary>
    /// Runs algorithm negotiation over the two KEXINITs and returns the
    /// negotiated methods. Port of <c>kex_agree_methods</c> (<c>kex.c:3935</c>)
    /// and the per-category <c>kex_agree_*</c> helpers. Throws
    /// <see cref="SshException"/>(<see cref="SshErrorCode.KexFailure"/>) on
    /// no-overlap in any category.
    /// </summary>
    /// <param name="client">The client's (local) KEXINIT — <see cref="BuildKexInit"/> output.</param>
    /// <param name="server">The server's (remote) KEXINIT — <see cref="ParseKexInit"/> of the inbound packet.</param>
    public static NegotiatedMethods Negotiate(KexInit client, KexInit server)
    {
        // ── Strict-KEX detection (kex.c:3681-3686) ───────────────────────
        // Scan the server's kex name-list for kex-strict-s-v00@openssh.com.
        bool strictKex = Array.IndexOf(server.KexAlgorithms, KexStrictS) >= 0;

        // ── KEX + hostkey together (kex.c:3675, kex_agree_kex_hostkey) ──
        // libssh2 negotiates KEX and hostkey in one function because the KEX
        // choice can constrain the hostkey (e.g. for RSA-SHA2 selection). We
        // negotiate them independently but in sequence — the wire behavior is
        // identical for the in-scope algorithm set.
        //
        // The client's pseudo-extensions (ext-info-c / kex-strict-c) are
        // EXCLUDED from the agreement: the C's default-preference
        // agreement walks its own real-method table (kex.c:3719-3724), so a
        // server echoing the client-only pseudo-names back (a non-conforming
        // peer or echoing proxy) never matches them there — the real overlap
        // wins. Pre-fix the pseudo-methods sat at the head of the client list
        // and won the first match, aborting the handshake with KexFailure
        // even when a real KEX overlap existed. The server's own marker
        // (kex-strict-s) is handled by the strict detection above and never
        // appears in the client list.
        string kexName = AgreeClientFirst(
            client.KexAlgorithms.Where(IsRealKexMethod).ToArray(),
            server.KexAlgorithms, "kex");
        KexAlgorithm kexAlgo = KexMethods.Lookup(kexName);
        if (kexAlgo == KexAlgorithm.None)
        {
            // The negotiated name was a pseudo-method (ext-info-c / kex-strict-*).
            // This happens only if both sides' real-KEX overlap is empty but the
            // pseudo-methods matched — which is a negotiation failure in practice.
            throw new SshException(SshErrorCode.KexFailure,
                $"negotiated kex '{kexName}' is not a real KEX algorithm");
        }

        string hostkeyName = AgreeClientFirst(
            client.ServerHostKeyAlgorithms, server.ServerHostKeyAlgorithms, "hostkey");
        SshHostKeyType hostkeyType = HostKeyMethods.Lookup(hostkeyName);
        if (hostkeyType == SshHostKeyType.Unknown)
        {
            throw new SshException(SshErrorCode.KexFailure,
                $"negotiated hostkey '{hostkeyName}' is not recognized");
        }

        // ── Cipher (kex.c:3757, kex_agree_crypt) ─────────────────────────
        string cipherCs = AgreeClientFirst(
            client.EncryptionAlgorithmsClientToServer,
            server.EncryptionAlgorithmsClientToServer, "crypt_cs");
        string cipherSc = AgreeClientFirst(
            client.EncryptionAlgorithmsServerToClient,
            server.EncryptionAlgorithmsServerToClient, "crypt_sc");

        // ── MAC (kex.c:3814, kex_agree_mac) — AFTER cipher (kex.c:3994) ──
        // The GCM MAC override depends on the negotiated cipher. ChaCha20-Poly1305
        // does NOT get the override — a real MAC is negotiated (the transport
        // layer ignores it via REQUIRES_FULL_PACKET). Mirrors mac.c:542-553.
        string macCs = NegotiateMac(cipherCs,
            client.MacAlgorithmsClientToServer, server.MacAlgorithmsClientToServer, "mac_cs");
        string macSc = NegotiateMac(cipherSc,
            client.MacAlgorithmsServerToClient, server.MacAlgorithmsServerToClient, "mac_sc");

        // ── Compression (kex.c:3877, kex_agree_comp) ────────────────────
        string compCs = AgreeClientFirst(
            client.CompressionAlgorithmsClientToServer,
            server.CompressionAlgorithmsClientToServer, "comp_cs");
        string compSc = AgreeClientFirst(
            client.CompressionAlgorithmsServerToClient,
            server.CompressionAlgorithmsServerToClient, "comp_sc");

        // ── Registry validation for crypt/mac/comp ──
        // The C's kex_agree_* helpers walk the CLIENT's method tables, so an
        // agreed name is always one the library supports; a no-overlap fails
        // at NEGOTIATION with LIBSSH2_ERROR_KEX_FAILURE (kex.c:3774-3784,
        // 4140-4142) — before any NEWKEYS is sent. The port previously agreed
        // on any string overlap and only threw AlgoUnsupported at key-install
        // time, AFTER sending NEWKEYS — a protocol desync (the peer installs
        // the new keys, the client dies) plus a wrong error code. Reachable
        // when a caller sets a method pref to a name outside the in-scope
        // registries (set-time pref validation is not ported). The GCM
        // no-op MAC name ("none") is registry-external by design.
        ValidateRegistered(cipherCs, "cipher", CipherMethods.Create(cipherCs) is not null);
        ValidateRegistered(cipherSc, "cipher", CipherMethods.Create(cipherSc) is not null);
        ValidateRegistered(macCs, "MAC", macCs == MacMethods.Noop.Name || MacMethods.Create(macCs) is not null);
        ValidateRegistered(macSc, "MAC", macSc == MacMethods.Noop.Name || MacMethods.Create(macSc) is not null);
        ValidateRegistered(compCs, "compression", CompressionMethods.Create(compCs) is not null);
        ValidateRegistered(compSc, "compression", CompressionMethods.Create(compSc) is not null);

        return new NegotiatedMethods
        {
            Kex = kexAlgo,
            KexName = kexName,
            HostKey = hostkeyType,
            HostKeyName = hostkeyName,
            CipherCs = cipherCs,
            CipherSc = cipherSc,
            MacCs = macCs,
            MacSc = macSc,
            CompCs = compCs,
            CompSc = compSc,
            StrictKex = strictKex,
        };
    }

    /// <summary>
    /// True iff <paramref name="name"/> can be agreed as a real KEX algorithm —
    /// i.e. it is not one of the client's pseudo-extensions
    /// (<see cref="ExtInfoC"/> / <see cref="KexStrictC"/>). The C never matches
    /// pseudo-methods in kex agreement (its default path walks the real-method
    /// table, kex.c:3719-3724); a server echoing the client-only pseudo-names
    /// must not win the agreement.
    /// </summary>
    private static bool IsRealKexMethod(string name)
        => name is not (ExtInfoC or KexStrictC);

    /// <summary>
    /// Throws <see cref="SshErrorCode.KexFailure"/> when a negotiated
    /// algorithm name is not in the in-scope registry (see the validation
    /// block in <see cref="Negotiate"/>).
    /// </summary>
    private static void ValidateRegistered(string name, string category, bool registered)
    {
        if (!registered)
        {
            throw new SshException(SshErrorCode.KexFailure,
                $"negotiated {category} '{name}' is not supported");
        }
    }

    /// <summary>
    /// Client-preference-first matching: iterate <paramref name="clientPrefs"/>
    /// in order, return the first entry that also appears in
    /// <paramref name="serverList"/>. Port of the <c>kex_agree_*</c> inner loop
    /// (<c>kex.c:3688-3724</c> and siblings). Throws
    /// <see cref="SshException"/>(<see cref="SshErrorCode.KexFailure"/>) on
    /// no overlap.
    /// </summary>
    /// <param name="clientPrefs">The client's ordered preference list (first match wins).</param>
    /// <param name="serverList">The server's offered algorithms (order-independent).</param>
    /// <param name="category">Used only for the error message (e.g. "kex", "crypt_cs").</param>
    private static string AgreeClientFirst(
        string[] clientPrefs, string[] serverList, string category)
    {
        // The server list is typically short (≤ 20 entries); a HashSet is overkill
        // and a linear scan matches libssh2's _libssh2_kex_agree_instr exactly.
        foreach (string c in clientPrefs)
        {
            if (Array.IndexOf(serverList, c) >= 0)
            {
                return c;
            }
        }

        throw new SshException(SshErrorCode.KexFailure,
            $"no agreed {category} algorithm (client={string.Join(',', clientPrefs)}, server={string.Join(',', serverList)})");
    }

    /// <summary>
    /// MAC negotiation with the AES-GCM no-op override. If the negotiated
    /// cipher is AES-GCM, returns <see cref="MacMethods.Noop"/>'s name
    /// (<c>"none"</c>) without scanning the name-lists — matching
    /// <c>_libssh2_mac_override</c> (<c>mac.c:542-553</c>). Otherwise runs the
    /// normal client-pref-first match. ChaCha20-Poly1305 does NOT get the
    /// override (a real MAC is negotiated; the transport layer ignores it).
    /// </summary>
    private static string NegotiateMac(
        string negotiatedCipher, string[] clientPrefs, string[] serverList, string category)
    {
        if (IsAesGcm(negotiatedCipher))
        {
            // mac_method_hmac_aesgcm has name "INTEGRATED-AES-GCM" in libssh2; the
            // C# NoopMac.Name is "none". The transport layer treats both as
            // "no separate MAC" — the AEAD tag provides integrity. Use the C#
            // adapter's name for consistency with the rest of the port.
            return MacMethods.Noop.Name;
        }

        return AgreeClientFirst(clientPrefs, serverList, category);
    }

    /// <summary>True iff <paramref name="cipherName"/> is an AES-GCM cipher
    /// (the only family that triggers the <c>_libssh2_mac_override</c> path).</summary>
    private static bool IsAesGcm(string cipherName)
        => cipherName is "aes256-gcm@openssh.com" or "aes128-gcm@openssh.com";

    /// <summary>
    /// Resolves the kex name-list for <see cref="BuildKexInit"/>: prepends
    /// <see cref="ExtInfoC"/> and <see cref="KexStrictC"/> to the user's kex
    /// prefs (or to <see cref="KexMethods.DefaultPreferences"/> if unset).
    /// Always prepend, regardless of user prefs.
    /// </summary>
    private static string[] BuildKexPrefs(MethodPreferences prefs)
    {
        string[] basePrefs = prefs.IsSet(SshMethodType.Kex)
            ? SplitCsv(prefs[SshMethodType.Kex])
            : KexMethods.DefaultPreferences.ToArray();

        // Prepend the two extensions. Avoid duplicates if the user already
        // included them (defensive — libssh2's kex.c:4199 does not dedup either,
        // but a duplicate in the name-list is harmless per RFC 4251 §3.6.1).
        string[] result = new string[basePrefs.Length + 2];
        result[0] = ExtInfoC;
        result[1] = KexStrictC;
        Array.Copy(basePrefs, 0, result, 2, basePrefs.Length);
        return result;
    }

    /// <summary>
    /// Resolves a non-kex name-list: the user's pref string (split on commas)
    /// if set, otherwise the <paramref name="defaults"/> array. Mirrors
    /// libssh2's <c>LIBSSH2_METHOD_PREFS_STR</c> macro (<c>kex.c:3332</c>).
    /// </summary>
    private static string[] BuildPrefs(
        MethodPreferences prefs, SshMethodType type, IReadOnlyList<string> defaults)
    {
        if (prefs.IsSet(type))
        {
            return SplitCsv(prefs[type]);
        }

        return defaults.ToArray();
    }

    /// <summary>Splits a comma-separated preference string, skipping empty entries.</summary>
    private static string[] SplitCsv(string csv)
    {
        if (string.IsNullOrEmpty(csv))
        {
            return [];
        }

        // SSH name-lists do not allow empty names (RFC 4251 §3.6.1); drop any
        // empty entries that would come from a stray trailing comma.
        return csv.Split(',', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// Writes one SSH name-list to <paramref name="ms"/>: a BE32 length prefix
    /// followed by the UTF-8 bytes of the comma-joined names. Port of
    /// <c>kex_method_list</c> (<c>kex.c:3310</c>) + the
    /// <c>LIBSSH2_METHOD_PREFS_STR</c> length-prefix wrapper.
    /// </summary>
    private static void WriteNameList(MemoryStream ms, string[] names)
    {
        // RFC 4251 §3.6.1: the name-list is a string of comma-separated names.
        // An empty list encodes as a zero-length string (4 bytes of 0).
        string joined = names.Length == 0 ? string.Empty : string.Join(',', names);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(joined);

        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, bytes.Length);
        ms.Write(len);
        ms.Write(bytes, 0, bytes.Length);
    }

    // ════════════════════════════════════════════════════════════════════
    // Exchange hash + key derivation.
    // ════════════════════════════════════════════════════════════════════

    /// <summary>
    /// The hash algorithm used by a KEX method for the exchange hash AND key
    /// derivation (RFC 4253 §7.2: "HASH" is the exchange-hash algorithm).
    /// <c>curve25519</c>/<c>ecdh-sha2-nistp256</c>/<c>dh-group14</c> → SHA-256;
    /// <c>ecdh-sha2-nistp384</c> → SHA-384; <c>ecdh-sha2-nistp521</c> → SHA-512.
    /// </summary>
    public static HashAlgorithmName HashForKex(KexAlgorithm algorithm)
        => algorithm switch
        {
            KexAlgorithm.Curve25519Sha256 => HashAlgorithmName.SHA256,
            KexAlgorithm.EcdhSha2Nistp256 => HashAlgorithmName.SHA256,
            KexAlgorithm.EcdhSha2Nistp384 => HashAlgorithmName.SHA384,
            KexAlgorithm.EcdhSha2Nistp521 => HashAlgorithmName.SHA512,
            KexAlgorithm.DhGroup14Sha256 => HashAlgorithmName.SHA256,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm),
                $"{algorithm} has no hash mapping."),
        };

    /// <summary>
    /// The output length (bytes) of <see cref="HashForKex"/> for a KEX method.
    /// </summary>
    public static int HashDigestLength(KexAlgorithm algorithm)
        => algorithm == KexAlgorithm.EcdhSha2Nistp521 ? 64
           : algorithm == KexAlgorithm.EcdhSha2Nistp384 ? 48
           : 32;

    /// <summary>
    /// Computes the exchange hash <c>H</c> from the KEX inputs. Byte-exact port
    /// of the two hash-finalize sites in <c>kex.c</c>:
    /// <c>diffie_hellman_sha_algo</c> (<c>kex.c:640</c>) for DH, and the
    /// <c>LIBSSH2_KEX_METHOD_EC_SHA_HASH_CREATE_VERIFY</c> macro
    /// (<c>kex.c:1713</c>) for ECDH + curve25519.
    /// </summary>
    /// <param name="algorithm">The negotiated KEX method (selects hash + e/f encoding).</param>
    /// <param name="clientBanner">V_C — the client identification string, CRLF stripped.</param>
    /// <param name="serverBanner">V_S — the server identification string, CRLF stripped.</param>
    /// <param name="clientKexInit">I_C — the raw client KEXINIT payload (including the type byte).</param>
    /// <param name="serverKexInit">I_S — the raw server KEXINIT payload (including the type byte).</param>
    /// <param name="serverHostKey">K_S — the server host key blob.</param>
    /// <param name="clientPublicKey">
    /// For DH (<c>e</c>): the raw big-endian unsigned bytes of the client DH public value.
    /// For ECDH/curve25519 (<c>Q_C</c>): the client ephemeral public key bytes (SEC1 point or 32-byte u-coord).
    /// </param>
    /// <param name="serverPublicKey">
    /// For DH (<c>f</c>): the raw big-endian unsigned bytes of the server DH public value.
    /// For ECDH/curve25519 (<c>Q_S</c>): the server ephemeral public key bytes.
    /// </param>
    /// <param name="sharedSecret">K — the shared secret (mpint-encoded into H for all methods).</param>
    /// <returns>The exchange hash <c>H</c> (32 / 48 / 64 bytes per <see cref="HashDigestLength"/>).</returns>
    /// <remarks>
    /// <para>
    /// Field order (both C sites): <c>string V_C, string V_S, string I_C, string I_S,
    /// string K_S,</c> then per method — DH: <c>mpint e, mpint f, mpint K</c>;
    /// ECDH/curve25519: <c>string Q_C, string Q_S, mpint K</c>. All string/mpint
    /// fields are length-prefixed per RFC 4251 §5.
    /// </para>
    /// <para>
    /// For DH the <c>e</c>/<c>f</c> public values are mpint-encoded here (leading-zero
    /// rule applied); for ECDH/curve25519 the public keys are SSH strings (raw bytes,
    /// no sign handling). <c>K</c> is always mpint-encoded.
    /// </para>
    /// </remarks>
    public static byte[] ComputeExchangeHash(
        KexAlgorithm algorithm,
        ReadOnlySpan<byte> clientBanner,
        ReadOnlySpan<byte> serverBanner,
        ReadOnlyMemory<byte> clientKexInit,
        ReadOnlyMemory<byte> serverKexInit,
        ReadOnlyMemory<byte> serverHostKey,
        ReadOnlyMemory<byte> clientPublicKey,
        ReadOnlyMemory<byte> serverPublicKey,
        BigInteger sharedSecret)
    {
        HashAlgorithmName hashName = HashForKex(algorithm);
        bool isDh = algorithm == KexAlgorithm.DhGroup14Sha256;
        using var h = IncrementalHash.CreateHash(hashName);

        HashString(h, clientBanner);
        HashString(h, serverBanner);
        HashString(h, clientKexInit.Span);
        HashString(h, serverKexInit.Span);
        HashString(h, serverHostKey.Span);

        if (isDh)
        {
            // DH: e and f are mpint. The client's own e is minimal by
            // construction — HashMpint adds the sign guard, matching the
            // bytes we actually sent. The server's f is hashed VERBATIM as
            // received (kex.c:726-732): a non-minimal encoding (extra leading
            // zeros) must NOT be normalized, or H diverges from the C.
            HashMpint(h, clientPublicKey.Span);
            HashMpintRaw(h, serverPublicKey.Span);
        }
        else
        {
            // ECDH / curve25519: Q_C and Q_S are SSH strings (raw point / u-coord bytes).
            HashString(h, clientPublicKey.Span);
            HashString(h, serverPublicKey.Span);
        }

        // K is always mpint-encoded (the shared secret as a non-negative integer).
        byte[] kBE = Endian.BigIntegerToBigEndianBytes(sharedSecret);
        HashMpint(h, kBE);

        return h.GetHashAndReset();
    }

    /// <summary>
    /// Derives a key of <paramref name="length"/> bytes from the shared secret
    /// <c>K</c>, exchange hash <c>H</c>, and session id, using letter
    /// <paramref name="letter"/> (<c>'A'</c>..<c>'F'</c>). Port of
    /// <c>LIBSSH2_KEX_METHOD_SHA_VALUE_HASH</c> (<c>kex.c:73</c>) — RFC 4253 §7.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// First block: <c>HASH(K ‖ H ‖ letter ‖ session_id)</c>. Subsequent blocks:
    /// <c>HASH(K ‖ H ‖ K1 ‖ … ‖ K_n-1)</c> — the libssh2 macro accumulates ALL
    /// prior blocks (verified against the macro source at <c>kex.c:73</c>), not
    /// just the previous one.
    /// </para>
    /// <para>
    /// <c>K</c> is fed as its mpint encoding (matching the macro's
    /// <c>k_value</c>); <c>H</c> and <c>session_id</c> are the raw digest/value
    /// bytes. The result is the concatenation of successive hash blocks,
    /// truncated to <paramref name="length"/>.
    /// </para>
    /// </remarks>
    public static byte[] DeriveKey(
        KexAlgorithm algorithm,
        BigInteger sharedSecret,
        ReadOnlySpan<byte> exchangeHash,
        ReadOnlySpan<byte> sessionId,
        char letter,
        int length)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(length, 0, nameof(length));
        ArgumentOutOfRangeException.ThrowIfNegative(sharedSecret.Sign, nameof(sharedSecret));

        HashAlgorithmName hashName = HashForKex(algorithm);
        int digestLen = HashDigestLength(algorithm);
        byte[] kMpint = BuildMpint(Endian.BigIntegerToBigEndianBytes(sharedSecret));

        byte[] result = new byte[length];
        int done = 0;
        // All prior key blocks concatenated (K1‖K2‖…), mirroring the C macro's
        // `value` buffer which grows by DIGEST_LENGTH per block (kex.c:95-118)
        // and is allocated with reqlen + DIGEST_LENGTH slack (kex.c:81-84) so
        // the final append always fits. Previously only the LAST digest was
        // re-hashed, and a third block
        // would throw ArgumentOutOfRangeException instead of hashing K1‖K2.
        byte[] priorBlocks = new byte[length + digestLen];
        Span<byte> letterByte = stackalloc byte[1];
        letterByte[0] = (byte)letter;

        while (done < length)
        {
            using var h = IncrementalHash.CreateHash(hashName);
            h.AppendData(kMpint);
            h.AppendData(exchangeHash);
            if (done == 0)
            {
                // First iteration: letter byte + session_id.
                h.AppendData(letterByte);
                h.AppendData(sessionId);
            }
            else
            {
                // Subsequent iterations: all prior blocks concatenated (K1‖K2‖…).
                h.AppendData(priorBlocks.AsSpan(0, done));
            }

            byte[] block = h.GetHashAndReset();
            int copy = Math.Min(digestLen, length - done);
            block.AsSpan(0, copy).CopyTo(result.AsSpan(done));
            // The full block is appended to the prior-blocks buffer even when
            // the output truncates mid-block (the C always appends
            // DIGEST_LENGTH bytes, kex.c:118).
            block.CopyTo(priorBlocks.AsSpan(done));
            done += digestLen;
        }

        return result;
    }

    /// <summary>Appends an SSH string (BE32 length + data) to the hash.</summary>
    private static void HashString(IncrementalHash h, ReadOnlySpan<byte> data)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, data.Length);
        h.AppendData(len);
        h.AppendData(data);
    }

    /// <summary>
    /// Appends an SSH mpint (BE32 length + value) to the hash. Delegates the
    /// leading-zero rule to the tested <see cref="Endian.WriteMpint"/>.
    /// </summary>
    private static void HashMpint(IncrementalHash h, ReadOnlySpan<byte> bigEndian)
    {
        byte[] be = bigEndian.ToArray();
        byte[] buf = new byte[4 + Endian.GetMpintLength(be)];
        Endian.WriteMpint(buf, be);
        h.AppendData(buf);
    }

    /// <summary>
    /// Appends an SSH mpint (BE32 length + body) WITHOUT normalization —
    /// used for the server's raw <c>f</c> bytes, which the C hashes verbatim
    /// as received (kex.c:726-732).
    /// </summary>
    private static void HashMpintRaw(IncrementalHash h, ReadOnlySpan<byte> body)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, body.Length);
        h.AppendData(len);
        h.AppendData(body);
    }

    /// <summary>Builds the full mpint wire encoding (BE32 length + value) of a big-endian value.</summary>
    private static byte[] BuildMpint(byte[] bigEndian)
    {
        byte[] buf = new byte[4 + Endian.GetMpintLength(bigEndian)];
        Endian.WriteMpint(buf, bigEndian);
        return buf;
    }

    // ════════════════════════════════════════════════════════════════════
    // The KEX state-machine orchestrator (RunExchangeAsync).
    // ════════════════════════════════════════════════════════════════════

    /// <summary>
    /// The outcome of one KEX run: the server host key, exchange hash, session
    /// id, and the hostkey signature blob. <c>SshSession</c> (with
    /// <c>HostKeyVerifier</c>) uses these to verify the host key.
    /// </summary>
    public sealed record KexExchangeResult
    {
        /// <summary>The server host key blob <c>K_S</c> (raw, as parsed from KEXDH_REPLY).</summary>
        public required byte[] HostKey { get; init; }

        /// <summary>The exchange hash <c>H</c> (32 / 48 / 64 bytes per the KEX hash).</summary>
        public required byte[] ExchangeHash { get; init; }

        /// <summary>
        /// The session id — set once from <c>H</c> on the first KEX, then
        /// immutable (<c>kex.c:808</c>). Equals <see cref="ExchangeHash"/> on
        /// the initial exchange.
        /// </summary>
        public required byte[] SessionId { get; init; }

        /// <summary>The raw hostkey signature blob over <see cref="ExchangeHash"/>
        /// (for hostkey verification).</summary>
        public required byte[] Signature { get; init; }
    }

    /// <summary>
    /// Runs the KEX math + NEWKEYS exchange: generates an ephemeral keypair,
    /// sends SSH_MSG_KEXDH_INIT / KEX_ECDH_INIT, receives the reply, computes
    /// the exchange hash <c>H</c> + shared secret <c>K</c>, optionally verifies
    /// the hostkey signature, derives the 6 RFC 4253 keys, and installs them on
    /// the reader/writer via the NEWKEYS transition. Port of the three KEX
    /// functions in <c>kex.c</c>: <c>diffie_hellman_sha_algo</c>,
    /// <c>ecdh_sha2_nistp</c>, <c>curve25519_sha256</c>.
    /// </summary>
    /// <param name="writer">The outbound packet framer (cleartext pre-NEWKEYS).</param>
    /// <param name="queue">The inbound packet queue (wraps the reader that gets
    /// <see cref="PacketReader.SetInboundKeys"/> after NEWKEYS).</param>
    /// <param name="negotiated">The 8 negotiated algorithm names + strict-KEX flag.</param>
    /// <param name="clientBanner">V_C — client identification string, CRLF stripped.</param>
    /// <param name="serverBanner">V_S — server identification string, CRLF stripped.</param>
    /// <param name="clientKexInit">I_C — raw client KEXINIT payload (incl type byte).</param>
    /// <param name="serverKexInit">I_S — raw server KEXINIT payload (incl type byte).</param>
    /// <param name="verifyAsync">
    /// Optional hostkey-signature verifier. Invoked AFTER computing
    /// <c>H</c> and BEFORE sending NEWKEYS — matching <c>kex.c</c>'s ordering.
    /// Receives <c>(hostKey, exchangeHash, signature)</c>; a <c>false</c> return
    /// aborts the exchange with <see cref="SshErrorCode.KeyExchangeFailure"/>.
    /// Pass <c>null</c> to skip verification.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="existingSessionId">
    /// The session id from a prior handshake, if rekeying. When non-null, the
    /// exchange hash <c>H</c> is computed but the existing session id is
    /// preserved (RFC 4253 §7.2 — the session id is the first H, immutable
    /// across rekeys). Pass <c>null</c> on initial handshake.
    /// </param>
    /// <returns>The exchange result (host key, H, session id, signature blob).</returns>
    public static async Task<KexExchangeResult> RunExchangeAsync(
        PacketWriter writer,
        PacketQueue queue,
        NegotiatedMethods negotiated,
        string clientBanner,
        string serverBanner,
        ReadOnlyMemory<byte> clientKexInit,
        ReadOnlyMemory<byte> serverKexInit,
        Func<byte[], byte[], byte[], CancellationToken, Task<bool>>? verifyAsync = null,
        byte[]? existingSessionId = null,
        CancellationToken cancellationToken = default)
    {
        bool isDh = negotiated.Kex == KexAlgorithm.DhGroup14Sha256;

        // ── 1. Generate ephemeral keypair + build KEXDH_INIT / ECDH_INIT ──────
        // The payload starts with the type byte (30) per PacketWriter's contract.
        byte[] initPayload;
        byte[] clientPublicBytes;   // e (DH raw BE) or Q_C (ECDH/curve25519 point)
        DhGroup14? dh = null;
        EcdhNistP? ecdh = null;
        Curve25519KeyExchange? x25519 = null;

        if (isDh)
        {
            dh = new DhGroup14();
            byte[] eBE = Endian.BigIntegerToBigEndianBytes(dh.PublicKey);
            initPayload = BuildKexDhInit(eBE);
            clientPublicBytes = eBE;
        }
        else if (negotiated.Kex == KexAlgorithm.Curve25519Sha256)
        {
            x25519 = new Curve25519KeyExchange();
            clientPublicBytes = x25519.PublicKey;
            initPayload = BuildKexEcdhInit(clientPublicBytes);
        }
        else
        {
            ecdh = new EcdhNistP(negotiated.Kex);
            clientPublicBytes = ecdh.PublicKeyPoint;
            initPayload = BuildKexEcdhInit(clientPublicBytes);
        }

        // ── 2. Send KEXDH_INIT (type 30), cleartext ──────────────────────────
        await writer.WritePacketAsync(PacketType.KexDhInit, initPayload, cancellationToken)
            .ConfigureAwait(false);

        // NOTE: optimistic-KEXINIT burn is DH-only in libssh2 (kex.c:411) and
        // OpenSSH never sends first_kex_packet_follows=1, so it is not reachable
        // against a real server.

        // ── 3. Receive KEXDH_REPLY / ECDH_REPLY (type 31) ────────────────────
        RawPacket reply = await queue.WaitForTypeAsync(PacketType.KexDhReply, cancellationToken)
            .ConfigureAwait(false);
        var r = new PacketWireReader(new ReadOnlySequence<byte>(reply.Payload));
        r.ReadByte();   // skip type byte (31)

        byte[] serverHostKey = r.ReadBlob();   // K_S
        byte[] serverPublicBytes;              // f (DH) or Q_S (ECDH/curve25519)
        BigInteger sharedSecret;

        if (isDh)
        {
            // f: keep the RAW received mpint body for the exchange hash — the
            // C hashes the wire bytes verbatim (kex.c:726-732); re-encoding
            // from the BigInteger would normalize a non-minimal f (extra
            // leading zeros) and produce a different H than the reference
            // against a sloppy server.
            byte[] fRaw = r.ReadMpint();
            if (fRaw.Length == 0 || (fRaw[0] & 0x80) != 0)
            {
                throw new SshException(SshErrorCode.KeyExchangeFailure, "DH server public value must be a positive mpint.");
            }

            BigInteger f = Endian.BigIntegerFromBigEndian(fRaw);
            serverPublicBytes = fRaw;
            sharedSecret = dh!.ComputeSharedSecret(f);
        }
        else
        {
            serverPublicBytes = r.ReadBlob();  // Q_S (string)
            byte[] kBytes = negotiated.Kex == KexAlgorithm.Curve25519Sha256
                ? x25519!.ComputeSharedSecret(serverPublicBytes)
                : ecdh!.ComputeSharedSecret(serverPublicBytes);
            sharedSecret = Endian.BigIntegerFromBigEndian(kBytes);
        }

        byte[] sigBlob = r.ReadBlob();   // hostkey signature over H

        // ── 4. Compute the exchange hash H ───────────────────────────────────
        byte[] exchangeHash = ComputeExchangeHash(
            negotiated.Kex,
            System.Text.Encoding.ASCII.GetBytes(clientBanner),
            System.Text.Encoding.ASCII.GetBytes(serverBanner),
            clientKexInit,
            serverKexInit,
            serverHostKey,
            clientPublicBytes,
            serverPublicBytes,
            sharedSecret);

        // ── 5. Optional hostkey signature verify ─────
        if (verifyAsync is not null)
        {
            bool ok = await verifyAsync(serverHostKey, exchangeHash, sigBlob, cancellationToken)
                .ConfigureAwait(false);
            if (!ok)
            {
                throw new SshException(SshErrorCode.KeyExchangeFailure,
                    "Hostkey signature verification failed.");
            }
        }

        // ── 6. session_id = H on the first KEX (immutable thereafter) ────────
        // RFC 4253 §7.1: the session identifier is the first exchange hash and
        // never changes. On rekey, the SAME original session_id feeds the key
        // derivation (DeriveKey's letter+session_id loop), NOT the new H. The
        // caller passes the cached session_id via existingSessionId; null means
        // first KEX (session_id := exchangeHash).
        byte[] sessionId = existingSessionId ?? exchangeHash;

        // ── 7. Send NEWKEYS (type 21, bare), then install OUTBOUND keys ──────
        // The NEWKEYS packet is the last under the old (cleartext) framing;
        // SetOutboundKeys flips the writer to encrypted + resets seqno.
        await writer.WritePacketAsync(PacketType.NewKeys, new byte[] { (byte)PacketType.NewKeys }, cancellationToken)
            .ConfigureAwait(false);
        await InstallOutboundKeysAsync(writer, negotiated, sharedSecret, exchangeHash, sessionId, cancellationToken)
            .ConfigureAwait(false);

        // ── 8. Receive server NEWKEYS, then install INBOUND keys ─────────────
        // The server's NEWKEYS arrives under the OLD (cleartext) inbound keys;
        // SetInboundKeys flips the reader to encrypted for subsequent reads.
        _ = await queue.WaitForTypeAsync(PacketType.NewKeys, cancellationToken)
            .ConfigureAwait(false);
        InstallInboundKeys(queue.Reader, negotiated, sharedSecret, exchangeHash, sessionId);

        // Initial KEX is over; disable the strict-KEX type-enforcement for rekeys.
        queue.InitialKex = false;

        // Dispose the ephemeral keypair handles (DH holds none; ECDH holds an
        // ECDiffieHellman and curve25519 holds an X25519DiffieHellman, both of
        // which should be released).
        ecdh?.Dispose();
        x25519?.Dispose();

        return new KexExchangeResult
        {
            HostKey = serverHostKey,
            ExchangeHash = exchangeHash,
            SessionId = sessionId,
            Signature = sigBlob,
        };
    }

    /// <summary>Builds the SSH_MSG_KEXDH_INIT payload: <c>[30][mpint e]</c>.</summary>
    private static byte[] BuildKexDhInit(byte[] eBigEndian)
    {
        int mpintLen = Endian.GetMpintLength(eBigEndian);
        byte[] payload = new byte[1 + 4 + mpintLen];
        payload[0] = (byte)PacketType.KexDhInit;
        Endian.WriteMpint(payload.AsSpan(1), eBigEndian);
        return payload;
    }

    /// <summary>Builds the SSH_MSG_KEX_ECDH_INIT payload: <c>[30][string Q_C]</c>.</summary>
    private static byte[] BuildKexEcdhInit(byte[] clientPoint)
    {
        byte[] payload = new byte[1 + 4 + clientPoint.Length];
        payload[0] = (byte)PacketType.KexDhInit;   // ECDH_INIT reuses type 30
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            payload.AsSpan(1, 4), (uint)clientPoint.Length);
        clientPoint.CopyTo(payload, 5);
        return payload;
    }

    /// <summary>
    /// Derives the 6 RFC 4253 keys and installs the OUTBOUND (client→server)
    /// cipher/MAC/compression on <paramref name="writer"/>. Letters A/C/E.
    /// </summary>
    private static async Task InstallOutboundKeysAsync(PacketWriter writer, NegotiatedMethods negotiated,
        BigInteger k, byte[] h, byte[] sessionId, CancellationToken cancellationToken)
    {
        ICipher cipher = CreateCipherOrThrow(negotiated.CipherCs);
        ICompression compression = CreateCompressionOrThrow(negotiated.CompCs);
        bool isAead = CipherMethods.IsAead(cipher);

        byte[] iv = DeriveKey(negotiated.Kex, k, h, sessionId, 'A', cipher.IvLen);
        byte[] encKey = DeriveKey(negotiated.Kex, k, h, sessionId, 'C', cipher.KeyLen);
        cipher.Init(encKey, iv, encrypt: true);

        IMac mac = isAead ? MacMethods.Noop : CreateMacOrThrow(negotiated.MacCs);
        if (!isAead)
        {
            byte[] macKey = DeriveKey(negotiated.Kex, k, h, sessionId, 'E', mac.MacLen);
            mac.Init(macKey);
        }

        compression.Init(compress: true);
        bool compressionActive = compression.Compresses && compression.UseInAuth;

        // SetOutboundKeys now acquires the writer lock internally
        // so it cannot race with a concurrent channel WritePacketAsync during
        // rekey. Previously this was a sync call; it is awaited now.
        await writer.SetOutboundKeysAsync(cipher, mac, compression, negotiated.StrictKex, compressionActive,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Derives the 6 RFC 4253 keys and installs the INBOUND (server→client)
    /// cipher/MAC/compression on <paramref name="reader"/>. Letters B/D/F.
    /// </summary>
    private static void InstallInboundKeys(PacketReader reader, NegotiatedMethods negotiated,
        BigInteger k, byte[] h, byte[] sessionId)
    {
        ICipher cipher = CreateCipherOrThrow(negotiated.CipherSc);
        ICompression compression = CreateCompressionOrThrow(negotiated.CompSc);
        bool isAead = CipherMethods.IsAead(cipher);

        byte[] iv = DeriveKey(negotiated.Kex, k, h, sessionId, 'B', cipher.IvLen);
        byte[] encKey = DeriveKey(negotiated.Kex, k, h, sessionId, 'D', cipher.KeyLen);
        cipher.Init(encKey, iv, encrypt: false);

        IMac mac = isAead ? MacMethods.Noop : CreateMacOrThrow(negotiated.MacSc);
        if (!isAead)
        {
            byte[] macKey = DeriveKey(negotiated.Kex, k, h, sessionId, 'F', mac.MacLen);
            mac.Init(macKey);
        }

        compression.Init(compress: false);
        // Inbound decompression uses the same activation rule as outbound.
        bool compressionActive = compression.Compresses && compression.UseInAuth;

        reader.SetInboundKeys(cipher, mac, compression, negotiated.StrictKex, compressionActive);
    }

    private static ICipher CreateCipherOrThrow(string name)
        => CipherMethods.Create(name)
           ?? throw new SshException(SshErrorCode.AlgoUnsupported, $"Unknown cipher: {name}");

    private static IMac CreateMacOrThrow(string name)
        => MacMethods.Create(name)
           ?? throw new SshException(SshErrorCode.AlgoUnsupported, $"Unknown MAC: {name}");

    private static ICompression CreateCompressionOrThrow(string name)
        => CompressionMethods.Create(name)
           ?? throw new SshException(SshErrorCode.AlgoUnsupported, $"Unknown compression: {name}");
}
