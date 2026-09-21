using System.Buffers;
using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS;

/// <summary>
/// SSH-2 user authentication methods. All methods are extension methods on
/// <see cref="SshSession"/> (mirroring the libssh2 API where auth functions take
/// a <c>LIBSSH2_SESSION *</c>). The session must have completed
/// <see cref="SshSession.HandshakeAsync(System.IO.Pipelines.IDuplexPipe, Func{byte[], byte[], CancellationToken, Task{bool}}, CancellationToken)"/> before any auth method is called.
/// </summary>
/// <remarks>
/// <para>
/// <b>State-machine collapse.</b> Each auth method's C state machine
/// (<c>userauth_pswd_state</c>, <c>userauth_pblc_state</c>, etc.) collapses to
/// local variables inside the async method — the C# compiler's state machine
/// replaces libssh2's hand-rolled non-blocking states. The only persistent
/// state is <see cref="SshSession.IsAuthenticated"/>, set once any method
/// succeeds via <see cref="SshSession.MarkAuthenticated"/>.
/// </para>
/// <para>
/// <b>Banner capture.</b> <c>SSH_MSG_USERAUTH_BANNER</c> (type 53) may arrive
/// during any auth wait; <see cref="WaitForAuthResponseAsync"/> captures it
/// into <see cref="SshSession.UserAuthBanner"/> and re-waits, mirroring
/// <c>userauth_list</c>'s inline banner handling (<c>userauth.c:141-190</c>).
/// </para>
/// <para>
/// <b>RSA-SHA2 algorithm selection.</b> For RSA keys the signing algorithm is
/// chosen from <see cref="SshSession.ServerSignatureAlgorithms"/> (the
/// <c>server-sig-algs</c> EXT_INFO extension). Picks the strongest of
/// <c>rsa-sha2-512</c> / <c>rsa-sha2-256</c> the server advertises; falls back
/// to <c>ssh-rsa</c> (SHA-1) if neither is advertised (parity with
/// <c>userauth.c:1351</c> <c>_libssh2_key_sign_algorithm</c>).
/// </para>
/// </remarks>
public static class SshUserAuth
{
    /// <summary>The SSH-2 service name for all auth methods.</summary>
    private const string ServiceConnection = "ssh-connection";

    // ════════════════════════════════════════════════════════════════════════
    // Method discovery: "none" probe → FAILURE carries can-continue methods.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sends a <c>"none"</c> userauth request to discover the methods the server
    /// accepts. Returns the comma-separated methods-that-can-continue from the
    /// server's <c>SSH_MSG_USERAUTH_FAILURE</c>. If the server accepts
    /// <c>"none"</c> (rare), returns <c>["none"]</c> and marks the session
    /// authenticated. Mirrors <c>libssh2_userauth_list</c>
    /// (<c>userauth.c:65-228</c>).
    /// </summary>
    public static async Task<string[]> GetAuthMethodsAsync(
        this SshSession session,
        string username,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        EnsureReady(session);

        // USERAUTH_REQUEST: [50] [user] [ssh-connection] [none]
        byte[] payload = BuildUserauthRequest(username, "none", extra: null);

        await session.Writer!.WritePacketAsync(PacketType.UserauthRequest, payload, cancellationToken)
            .ConfigureAwait(false);

        int[] replyCodes = [PacketType.UserauthSuccess, PacketType.UserauthFailure, PacketType.UserauthBanner];
        RawPacket resp = await WaitForAuthResponseAsync(session, replyCodes, cancellationToken)
            .ConfigureAwait(false);

        if (resp.Type == PacketType.UserauthSuccess)
        {
            session.MarkAuthenticated();
            return ["none"];
        }

        // FAILURE: parse the can-continue name-list.
        // Payload: [51] [string methods] [bool partial_success]
        var r = new PacketWireReader(new ReadOnlySequence<byte>(resp.Payload));
        _ = r.ReadByte();   // type (51)
        string methods = r.ReadString();
        _ = r.ReadByte();   // partial_success (ignored)
        return methods.Length == 0 ? [] : methods.Split(',');
    }

    // ════════════════════════════════════════════════════════════════════════
    // Password
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Authenticates with a password. Mirrors <c>libssh2_userauth_password_ex</c>
    /// (<c>userauth.c:289-539</c>). If the server returns
    /// <c>SSH_MSG_USERAUTH_PASSWD_CHANGEREQ</c> (password expired) and
    /// <paramref name="onChangePassword"/> is non-null, invokes the callback for
    /// a new password and retries with the change-password flow; otherwise throws
    /// <see cref="SshErrorCode.PasswordExpired"/>.
    /// </summary>
    public static async Task AuthenticateWithPasswordAsync(
        this SshSession session,
        string username,
        string password,
        SshPasswordChangeCallback? onChangePassword = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);
        EnsureReady(session);

        // USERAUTH_REQUEST: [50] [user] [ssh-connection] [password] [FALSE=0] [4 + password]
        // (password is appended inline — libssh2 sends it as a separate iovec,
        // but the wire form is identical).
        byte[] payload = BuildPasswordRequest(username, password, change: false, oldPassword: null);
        await session.Writer!.WritePacketAsync(PacketType.UserauthRequest, payload, cancellationToken)
            .ConfigureAwait(false);

        int[] replyCodes =
        [
            PacketType.UserauthSuccess, PacketType.UserauthFailure, PacketType.UserauthPasswdChangereq,
        ];

        bool changeRequestSent = false;

        while (true)
        {
            RawPacket resp = await WaitForAuthResponseAsync(session, replyCodes, cancellationToken)
                .ConfigureAwait(false);

            if (resp.Type == PacketType.UserauthSuccess)
            {
                session.MarkAuthenticated();
                return;
            }

            if (resp.Type == PacketType.UserauthFailure)
            {
                throw new SshException(SshErrorCode.AuthenticationFailed,
                    "Password authentication failed");
            }

            // PASSWD_CHANGEREQ (type 60): server wants a password change.
            // Payload: [60] [string prompt] [string language]
            if (changeRequestSent)
            {
                // C parity: libssh2's password auth state machine accepts a
                // CHANGEREQ only in the initial states; once the change request
                // has been sent, a repeated CHANGEREQ falls through to
                // authentication failure. Do not loop forever invoking the
                // callback and re-sending the change request.
                throw new SshException(SshErrorCode.AuthenticationFailed,
                    "Password change was requested again after the change request was sent");
            }

            if (onChangePassword is null)
            {
                throw new SshException(SshErrorCode.PasswordExpired,
                    "Password expired and no change callback provided");
            }

            string? newPassword = await onChangePassword(cancellationToken).ConfigureAwait(false);
            if (newPassword is null)
            {
                throw new SshException(SshErrorCode.PasswordExpired,
                    "Password change cancelled by user");
            }

            // Build the change-password USERAUTH_REQUEST: [50] [user] [ssh-connection]
            // [password] [TRUE=1] [4 + old_password] [4 + new_password]
            byte[] changePayload = BuildPasswordRequest(username, newPassword, change: true, oldPassword: password);
            await session.Writer.WritePacketAsync(PacketType.UserauthRequest, changePayload, cancellationToken)
                .ConfigureAwait(false);
            changeRequestSent = true;

            // Loop back to wait for the response to the change request.
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Public key (the two-step probe → sign → send flow)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Authenticates with a public key from in-memory key data. Parses the
    /// private key bytes via <see cref="SshPemParser"/> and runs the two-step
    /// publickey flow (probe → sign → send). Mirrors
    /// <c>libssh2_userauth_publickey_frommemory</c>.
    /// </summary>
    /// <remarks>
    /// <b>File IO is the caller's responsibility.</b> LibSsh2CS does no file IO
    /// (the async-convention test <c>NoBufferedFileIO</c> forbids it); the
    /// caller reads the key file and hands the bytes here. LibSsh2CS does not
    /// own sockets / files. The
    /// <see cref="AuthenticateWithPublicKeyAsync(SshSession, string, OpenSshKey,
    /// CancellationToken)"/> overload takes an already-parsed key.
    /// </remarks>
    public static async Task AuthenticateWithPublicKeyAsync(
        this SshSession session,
        string username,
        byte[]? publicKeyBlob,
        byte[] privateKeyData,
        string? passphrase = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(privateKeyData);
        EnsureReady(session);

        OpenSshKey openSshKey = SshPemParser.ParseOpenSshPrivateKey(privateKeyData, passphrase);
        var pemKey = SshPemKey.Parse(openSshKey);
        byte[] pubBlob = publicKeyBlob ?? openSshKey.PublicKeyBlob;
        string algoName = SelectSigningAlgorithm(session, pemKey);

        // Bind pemKey into the sign callback closure. SshSign.Sign is synchronous
        // (CPU-only); wrap in Task.FromResult for the async contract.
        Task<byte[]> SignAsync(byte[] data, string algo, CancellationToken ct)
            => Task.FromResult(SshSign.Sign(pemKey, data, algo));

        await AuthenticateWithPublicKeyCoreAsync(session, username, pubBlob, algoName, SignAsync, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Authenticates with an already-parsed <see cref="SshPemKey"/> (from
    /// <see cref="SshPemKey.Parse(OpenSshKey)"/>). The public key blob is taken
    /// from the <see cref="OpenSshKey.PublicKeyBlob"/> of the source
    /// <see cref="OpenSshKey"/>.
    /// </summary>
    public static async Task AuthenticateWithPublicKeyAsync(
        this SshSession session,
        string username,
        OpenSshKey privateKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(privateKey);
        EnsureReady(session);

        var pemKey = SshPemKey.Parse(privateKey);
        string algoName = SelectSigningAlgorithm(session, pemKey);
        byte[] pubBlob = privateKey.PublicKeyBlob;

        // Bind pemKey into the sign callback closure. SshSign.Sign is synchronous
        // (CPU-only); wrap in Task.FromResult for the async contract.
        Task<byte[]> SignAsync(byte[] data, string algo, CancellationToken ct)
            => Task.FromResult(SshSign.Sign(pemKey, data, algo));

        await AuthenticateWithPublicKeyCoreAsync(session, username, pubBlob, algoName, SignAsync, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Authenticates with a public key blob and an externally-supplied signing
    /// callback. Use this overload when the private key is not directly held —
    /// an SSH agent (<see cref="Agent.SshAgent"/>), HSM, PKCS#11
    /// token, or any other non-file-backed sign source.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library selects the signing algorithm name internally (RSA-SHA2
    /// selection consults <see cref="SshSession.ServerSignatureAlgorithms"/>,
    /// parity with the PemKey overloads) and passes it to
    /// <paramref name="signAsync"/> at sign time. The callback does not need
    /// to do algorithm negotiation — it only needs to produce a signature for
    /// the algorithm it is handed.
    /// </para>
    /// <para>
    /// <paramref name="publicKeyBlob"/> must be the SSH wire-format public key
    /// blob (e.g. <see cref="Agent.SshAgentIdentity.Blob"/> from
    /// <see cref="Agent.SshAgent.ListIdentitiesAsync(CancellationToken)"/>).
    /// The first SSH string in the blob determines the key type
    /// (<c>"ssh-rsa"</c>, <c>"ssh-ed25519"</c>, <c>"ecdsa-sha2-nistpXXX"</c>).
    /// </para>
    /// <para>
    /// <paramref name="signAsync"/> must return the full SSH signature blob
    /// <c>[string algoName][string rawSig]</c> — the same shape
    /// <see cref="SshSign.Sign(SshPemKey, byte[], string)"/> returns. For RSA,
    /// <c>rawSig</c> is the PKCS#1 v1.5 signature; for ECDSA it is
    /// <c>[string r][string s]</c>; for Ed25519 it is the 64-byte R‖S.
    /// </para>
    /// </remarks>
    public static async Task AuthenticateWithPublicKeyAsync(
        this SshSession session,
        string username,
        byte[] publicKeyBlob,
        PublicKeySignCallback signAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(publicKeyBlob);
        ArgumentNullException.ThrowIfNull(signAsync);
        EnsureReady(session);

        string algoName = SelectSigningAlgorithm(session, publicKeyBlob);

        await AuthenticateWithPublicKeyCoreAsync(session, username, publicKeyBlob, algoName, signAsync, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// The core two-step publickey flow: (1) send a probe USERAUTH_REQUEST with
    /// <c>sig_included=FALSE</c>; (2) on PK_OK, sign <c>session_id ‖ probe</c>
    /// and send the real USERAUTH_REQUEST with <c>sig_included=TRUE</c> + the
    /// signature. Mirrors <c>_libssh2_userauth_publickey</c>
    /// (<c>userauth.c:1516-1900</c>).
    /// </summary>
    private static async Task AuthenticateWithPublicKeyCoreAsync(
        SshSession session,
        string username,
        byte[] publicKeyBlob,
        string algoName,
        PublicKeySignCallback signAsync,
        CancellationToken cancellationToken)
    {
        // ── Step 1: probe packet (sig_included = FALSE) ─────────────────────
        // [50] [user] [ssh-connection] [publickey] [FALSE] [string algoName] [string pubKeyBlob]
        byte[] probe = BuildPublickeyProbe(username, algoName, publicKeyBlob);
        await session.Writer!.WritePacketAsync(PacketType.UserauthRequest, probe, cancellationToken)
            .ConfigureAwait(false);

        int[] probeReplies =
        [
            PacketType.UserauthSuccess, PacketType.UserauthFailure, PacketType.UserauthPkOk,
        ];
        RawPacket probeResp = await WaitForAuthResponseAsync(session, probeReplies, cancellationToken)
            .ConfigureAwait(false);

        if (probeResp.Type == PacketType.UserauthSuccess)
        {
            // "Prematurely successful" — server accepted the probe without a
            // signature (userauth.c:1689-1704).
            session.MarkAuthenticated();
            return;
        }

        if (probeResp.Type == PacketType.UserauthFailure)
        {
            throw new SshException(SshErrorCode.AuthenticationFailed,
                "Public key rejected by server (probe stage)");
        }

        // PK_OK (type 60): server accepts the key; now sign and send the real request.
        // ── Step 2: build signed data = string(session_id) ‖ probe_packet_with_TRUE ──
        // Flip the sig_included byte from FALSE (0x00) to TRUE (0x01) in-place
        // (userauth.c:1724). The probe layout puts the bool at a fixed offset:
        //   [50][4+user][4+14 ssh-connection][4+9 publickey][BOOL][...]
        // Find the bool offset: 1 + 4 + user_len + 4 + 14 + 4 + 9 = 1 + 4 + user_len + 31
        int userBytesLen = Encoding.UTF8.GetByteCount(username);
        int boolOffset = 1 + 4 + userBytesLen + 4 + ServiceConnection.Length + 4 + "publickey".Length;
        byte[] signedPacket = (byte[])probe.Clone();
        signedPacket[boolOffset] = 0x01;

        byte[] signedData = BuildSignedData(session.SessionId.Span, signedPacket);
        byte[] sigBlob;
        try
        {
            sigBlob = await signAsync(signedData, algoName, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.AlgoUnsupported && algoName != "ssh-rsa")
        {
            // Parity userauth.c:1754-1764: on the FIRST attempt, a signer that
            // rejects the upgraded (rsa-sha2-*) algorithm triggers one retry —
            // the probe is re-sent with the key's DEFAULT algorithm (the C's
            // auth_attempts becomes 2, which skips the upgrade at
            // userauth.c:1580-1587). A second ALGO_UNSUPPORTED falls through
            // to the generic PUBLICKEY_UNVERIFIED mapping below, matching the
            // C's `else if(rc)` branch.
            await AuthenticateWithPublicKeyCoreAsync(
                session, username, publicKeyBlob, "ssh-rsa", signAsync, cancellationToken).ConfigureAwait(false);
            return;
        }
        catch (SshException ex)
        {
            // Parity userauth.c:1765-1773: any other signer error maps to
            // PUBLICKEY_UNVERIFIED "Callback returned error". Previously the
            // callback's exception propagated unmodified.
            throw new SshException(SshErrorCode.PublicKeyUnverified,
                "Callback returned error", ex);
        }

        // ── Step 3: build the final packet: probe (with TRUE) + [string sigBlob] ──
        // The sigBlob is [string algoName][string rawSig]; the USERAUTH_REQUEST
        // appends it as a single SSH string (userauth.c:1823-1828).
        byte[] finalPayload = AppendSignature(signedPacket, sigBlob);
        await session.Writer.WritePacketAsync(PacketType.UserauthRequest, finalPayload, cancellationToken)
            .ConfigureAwait(false);

        int[] finalReplies = [PacketType.UserauthSuccess, PacketType.UserauthFailure];
        RawPacket finalResp = await WaitForAuthResponseAsync(session, finalReplies, cancellationToken)
            .ConfigureAwait(false);

        if (finalResp.Type == PacketType.UserauthSuccess)
        {
            session.MarkAuthenticated();
            return;
        }

        throw new SshException(SshErrorCode.PublicKeyUnverified,
            "Public key signature rejected by server");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Keyboard-interactive
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Reads one INFO_REQUEST string field, mapping an under-read to
    /// <see cref="SshErrorCode.Alloc"/> — parity with the C's
    /// <c>_libssh2_copy_string</c> failure, which is reported as ALLOC
    /// whether it ran out of memory or out of bytes
    /// (userauth_kbd_packet.c:65-106).
    /// </summary>
    private static string ReadKbdStringField(ref PacketWireReader r, string message)
    {
        try
        {
            return r.ReadString();
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            throw new SshException(SshErrorCode.Alloc, message, ex);
        }
    }

    /// <summary>
    /// Authenticates via keyboard-interactive (RFC 4252 §5.4). Sends the initial
    /// <c>"keyboard-interactive"</c> request, then loops on
    /// <c>SSH_MSG_USERAUTH_INFO_REQUEST</c> (calling <paramref name="onPrompt"/>
    /// for each challenge and sending back the responses) until SUCCESS or
    /// FAILURE. Mirrors <c>libssh2_userauth_keyboard_interactive_ex</c>
    /// (<c>userauth.c:2100-2366</c>).
    /// </summary>
    public static async Task AuthenticateWithKeyboardInteractiveAsync(
        this SshSession session,
        string username,
        SshKeyboardInteractiveCallback onPrompt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(onPrompt);
        EnsureReady(session);

        // USERAUTH_REQUEST: [50] [user] [ssh-connection] [keyboard-interactive]
        //                    [string ""] [string ""]  (language + submethods, both empty)
        byte[] payload = BuildKbdIntRequest(username);
        await session.Writer!.WritePacketAsync(PacketType.UserauthRequest, payload, cancellationToken)
            .ConfigureAwait(false);

        int[] replyCodes =
        [
            PacketType.UserauthSuccess, PacketType.UserauthFailure, PacketType.UserauthInfoRequest,
        ];

        while (true)
        {
            RawPacket resp = await WaitForAuthResponseAsync(session, replyCodes, cancellationToken)
                .ConfigureAwait(false);

            if (resp.Type == PacketType.UserauthSuccess)
            {
                session.MarkAuthenticated();
                return;
            }

            if (resp.Type == PacketType.UserauthFailure)
            {
                throw new SshException(SshErrorCode.AuthenticationFailed,
                    "Keyboard-interactive authentication failed");
            }

            // INFO_REQUEST (type 60): parse name, instruction, language, num-prompts, prompts.
            // Error mapping mirrors userauth_kbd_packet.c:57-152 exactly.
            SshKbdInfoRequest info = ParseInfoRequestPayload(resp.Payload);
            string[] answers = await onPrompt(info.Name, info.Instruction, info.Prompts, cancellationToken)
                .ConfigureAwait(false);
            if (answers.Length != info.Prompts.Length)
            {
                throw new SshException(SshErrorCode.Inval,
                    $"Keyboard-interactive callback returned {answers.Length} answers for {info.Prompts.Length} prompts");
            }

            // INFO_RESPONSE (type 61): [61] [uint32 num-responses] [ [string response] ]*
            byte[] responsePayload = BuildKbdIntResponse(answers);
            await session.Writer.WritePacketAsync(PacketType.UserauthInfoResponse, responsePayload,
                cancellationToken).ConfigureAwait(false);

            // Loop back to wait for the next INFO_REQUEST or SUCCESS/FAILURE.
        }
    }

    /// <summary>
    /// Parses an <c>SSH_MSG_USERAUTH_INFO_REQUEST</c> payload:
    /// <c>[60] [string name] [string instruction] [string lang]
    /// [uint32 num-prompts] [ [string prompt] [bool echo] ]*</c>.
    /// The managed counterpart of libssh2's separate decode function
    /// <c>userauth_keyboard_interactive_decode_info_request</c>
    /// (userauth_kbd_packet.c:43-152), with its exact error mapping: the
    /// <c>&lt;17</c> gate, the u32/boolean under-reads → BUFFER_TOO_SMALL,
    /// string under-reads (the C's <c>_libssh2_copy_string</c> failure) →
    /// ALLOC, and the <c>&gt;100</c> prompts gate → OUT_OF_BOUNDARY.
    /// </summary>
    internal static SshKbdInfoRequest ParseInfoRequestPayload(byte[] payload)
    {
        if (payload.Length < 17)
        {
            // Parity userauth_kbd_packet.c:57-62 — the C's minimum-length
            // gate is BUFFER_TOO_SMALL.
            throw new SshException(SshErrorCode.BufferTooSmall,
                "userauth keyboard data buffer too small");
        }

        var r = new PacketWireReader(new ReadOnlySequence<byte>(payload));
        _ = r.ReadByte();   // type (60)
        string name = ReadKbdStringField(ref r,
            "Unable to decode keyboard-interactive 'name' request field");
        string instruction = ReadKbdStringField(ref r,
            "Unable to decode keyboard-interactive 'instruction' request field");
        _ = ReadKbdStringField(ref r,
            "Unable to decode keyboard-interactive 'language tag' request field");
        uint numPrompts;
        try
        {
            numPrompts = r.ReadUInt32BigEndian();
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            // Parity userauth_kbd_packet.c:119-124.
            throw new SshException(SshErrorCode.BufferTooSmall,
                "Unable to decode keyboard-interactive number of keyboard prompts", ex);
        }

        if (numPrompts > 100)
        {
            // Parity userauth_kbd_packet.c:109-114 — the C's >100 gate is
            // OUT_OF_BOUNDARY.
            throw new SshException(SshErrorCode.OutOfBoundary,
                $"Keyboard-interactive: too many prompts ({numPrompts} > 100)");
        }

        var prompts = new SshKeyboardInteractivePrompt[numPrompts];
        for (int i = 0; i < (int)numPrompts; i++)
        {
            string text = ReadKbdStringField(ref r,
                "Unable to decode keyboard-interactive prompt message");
            bool echo;
            try
            {
                echo = r.ReadByte() != 0;
            }
            catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
            {
                // Parity userauth_kbd_packet.c:141-146.
                throw new SshException(SshErrorCode.BufferTooSmall,
                    "Unable to decode user auth keyboard prompt echo", ex);
            }

            prompts[i] = new SshKeyboardInteractivePrompt { Text = text, Echo = echo };
        }

        return new SshKbdInfoRequest(name, instruction, prompts);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Host-based
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Authenticates via host-based authentication. The client proves its
    /// identity by signing with a host private key and presenting a hostname +
    /// local username. The server must have the client host's public key in its
    /// <c>known_hosts</c> with hostbased authorization enabled. Mirrors
    /// <c>libssh2_userauth_hostbased_fromfile_ex</c> (<c>userauth.c:1007-1233</c>).
    /// </summary>
    /// <remarks>
    /// Takes an already-parsed <see cref="OpenSshKey"/> (caller reads the file —
    /// LibSsh2CS does no file IO).
    /// </remarks>
    public static async Task AuthenticateWithHostBasedAsync(
        this SshSession session,
        string username,
        OpenSshKey privateKey,
        string hostname,
        string localUsername,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(hostname);
        ArgumentNullException.ThrowIfNull(localUsername);
        EnsureReady(session);

        var pemKey = SshPemKey.Parse(privateKey);

        // Pick the signing algorithm (RSA-SHA2 selection applies to hostbased too).
        string algoName = SelectSigningAlgorithm(session, pemKey);

        // USERAUTH_REQUEST: [50] [user] [ssh-connection] [hostbased]
        //   [string algoName] [string pubKeyBlob] [string hostname] [string localUsername]
        byte[] packet = BuildHostbasedRequest(username, algoName, privateKey.PublicKeyBlob,
            hostname, localUsername);

        // Sign session_id ‖ the USERAUTH_REQUEST packet (no probe step for hostbased).
        byte[] signedData = BuildSignedData(session.SessionId.Span, packet);
        byte[] sigBlob = SshSign.Sign(pemKey, signedData, algoName);

        // Append [string sigBlob] and send.
        byte[] finalPayload = AppendSignature(packet, sigBlob);
        await session.Writer!.WritePacketAsync(PacketType.UserauthRequest, finalPayload, cancellationToken)
            .ConfigureAwait(false);

        int[] replyCodes = [PacketType.UserauthSuccess, PacketType.UserauthFailure];
        RawPacket resp = await WaitForAuthResponseAsync(session, replyCodes, cancellationToken)
            .ConfigureAwait(false);

        if (resp.Type == PacketType.UserauthSuccess)
        {
            session.MarkAuthenticated();
            return;
        }

        throw new SshException(SshErrorCode.PublicKeyUnverified,
            "Host-based authentication failed");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Banner retrieval
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Returns the pre-auth banner the server sent (if any), captured during
    /// the auth methods. Returns <see langword="null"/> if no banner was sent.
    /// Mirrors <c>libssh2_userauth_banner</c>.
    /// </summary>
    public static Task<string?> GetBannerAsync(this SshSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(session.UserAuthBanner);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Throws if the session is not ready for auth (not handed out, or already
    /// authenticated, or disposed). Replaces libssh2's per-method state checks.
    /// </summary>
    private static void EnsureReady(SshSession session)
    {
        // Without this, all five auth entry points passed EnsureReady after
        // DisposeAsync and threw a raw ObjectDisposedException from deep inside
        // PacketWriter (disposed SemaphoreSlim) instead of the clean entry-point
        // guard every other public SshSession member uses. The C has no dispose.
        ObjectDisposedException.ThrowIf(session.IsDisposed, session);

        if (session.Writer is null || session.Queue is null)
        {
            throw new InvalidOperationException(
                "SshSession must complete HandshakeAsync before calling auth methods.");
        }

        if (session.IsAuthenticated)
        {
            throw new InvalidOperationException("SshSession is already authenticated.");
        }
    }

    /// <summary>
    /// Waits for one of <paramref name="replyCodes"/>, capturing any
    /// <c>SSH_MSG_USERAUTH_BANNER</c> (type 53) into
    /// <see cref="SshSession.UserAuthBanner"/> and re-waiting. Mirrors
    /// <c>userauth_list</c>'s inline banner handling (<c>userauth.c:141-190</c>).
    /// </summary>
    private static async Task<RawPacket> WaitForAuthResponseAsync(
        SshSession session, int[] replyCodes, CancellationToken cancellationToken)
    {
        while (true)
        {
            RawPacket pkt = await session.Queue!.WaitForTypesAsync(replyCodes, cancellationToken)
                .ConfigureAwait(false);

            if (pkt.Type == PacketType.UserauthBanner)
            {
                // SSH_MSG_USERAUTH_BANNER (type 53): [53] [string message] [string lang]
                if (pkt.Payload.Length < 5)
                {
                    // Parity userauth.c:146-149 — the C's <5-byte gate is
                    // PROTO.
                    throw new SshException(SshErrorCode.Proto, "Unexpected packet size");
                }

                var r = new PacketWireReader(new ReadOnlySequence<byte>(pkt.Payload));
                _ = r.ReadByte();   // type
                string banner = r.ReadString();   // an over-long banner → OutOfBoundary (the C's OUT_OF_BOUNDARY, userauth.c:151-156)
                session.UserAuthBanner = banner;
                continue;   // re-wait for the actual response
            }

            return pkt;
        }
    }

    /// <summary>
    /// Selects the signing algorithm name for a key. For RSA keys, consults
    /// <see cref="SshSession.ServerSignatureAlgorithms"/> to pick the strongest
    /// mutually-supported RSA-SHA2 variant, falling back to <c>ssh-rsa</c>
    /// (SHA-1). For ECDSA / Ed25519, returns the key's own wire name (the
    /// algorithm is fixed by the key type). Parity with
    /// <c>_libssh2_key_sign_algorithm</c> (<c>userauth.c:1351</c>).
    /// </summary>
    internal static string SelectSigningAlgorithm(SshSession session, SshPemKey pemKey)
    {
        return pemKey switch
        {
            RsaPemKey => SelectRsaAlgorithm(session),
            SshEcdsaPemKey ecdsa => ecdsa.CurveName switch
            {
                "nistp256" => "ecdsa-sha2-nistp256",
                "nistp384" => "ecdsa-sha2-nistp384",
                "nistp521" => "ecdsa-sha2-nistp521",
                _ => throw new SshException(SshErrorCode.PublicKeyProtocol,
                    $"Unknown ECDSA curve: {ecdsa.CurveName}"),
            },
            SshEd25519PemKey => "ssh-ed25519",
            _ => throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Unknown key type: {pemKey.GetType()}"),
        };
    }

    /// <summary>
    /// Selects the signing algorithm from an SSH wire-format public key blob
    /// (e.g. an <see cref="Agent.SshAgentIdentity.Blob"/> returned by an
    /// SSH agent). Reads the first SSH string — the key type — and dispatches:
    /// RSA consults <see cref="SshSession.ServerSignatureAlgorithms"/> for
    /// SHA-2 selection; ECDSA / Ed25519 return the blob's own key type (the
    /// algorithm name equals the key type per RFC 8332 §3.1).
    /// </summary>
    /// <remarks>
    /// Used by the agent authentication path (<see cref="AuthenticateWithPublicKeyAsync(
    /// SshSession, string, byte[], PublicKeySignCallback, CancellationToken)"/>)
    /// where no <see cref="SshPemKey"/> exists — only the public key blob.
    /// </remarks>
    internal static string SelectSigningAlgorithm(SshSession session, byte[] publicKeyBlob)
    {
        ArgumentNullException.ThrowIfNull(publicKeyBlob);

        if (publicKeyBlob.Length < 4)
        {
            throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Public key blob too short ({publicKeyBlob.Length} bytes)");
        }

        var r = new PacketWireReader(new ReadOnlySequence<byte>(publicKeyBlob));
        string keyType = r.ReadString();

        return keyType switch
        {
            "ssh-rsa" => SelectRsaAlgorithm(session),
            // For ECDSA / Ed25519 the algorithm name is the blob's own key type
            // (RFC 8332 §3.1: the stored key type IS the signing algorithm).
            "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521" or "ssh-ed25519"
                => keyType,
            _ => throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Unsupported key type in blob: {keyType}"),
        };
    }

    /// <summary>
    /// RSA algorithm selection: prefer rsa-sha2-512, then rsa-sha2-256, then
    /// fall back to ssh-rsa (SHA-1). Parity with the filtered-algs + pref-match
    /// loop in <c>_libssh2_key_sign_algorithm</c> (<c>userauth.c:1410-1507</c>).
    /// </summary>
    /// <remarks>
    /// User-set <see cref="SshMethodType.SignAlgo"/> preferences order the
    /// match (parity <c>userauth.c:1444-1449</c>: <c>sign_algo_prefs</c> —
    /// e.g. <c>"ssh-rsa,rsa-sha2-256"</c> picks ssh-rsa even when rsa-sha2-256
    /// is advertised). Previously the prefs were exposed but never consulted.
    /// </remarks>
    private static string SelectRsaAlgorithm(SshSession session)
    {
        IReadOnlyList<string>? serverAlgs = session.ServerSignatureAlgorithms;
        if (serverAlgs is null || serverAlgs.Count == 0)
        {
            // No EXT_INFO received — fall back to ssh-rsa (the historical
            // default; userauth.c:1570-1590 skips the upgrade when
            // server_sign_algorithms is unset).
            return "ssh-rsa";
        }

        string signAlgoPrefs = session[SshMethodType.SignAlgo];
        string[] candidates = signAlgoPrefs.Length > 0
            ? signAlgoPrefs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"];

        foreach (string candidate in candidates)
        {
            // Backend-support filter (parity: filtered_algs is the intersection
            // with supported_algs; this port supports exactly these three RSA
            // signing names).
            if (candidate is not ("rsa-sha2-512" or "rsa-sha2-256" or "ssh-rsa"))
            {
                continue;
            }

            if (serverAlgs.Contains(candidate, StringComparer.Ordinal))
            {
                return candidate;
            }
        }

        // No candidate advertised (e.g. the server advertises only ssh-ed25519).
        // The C aborts with METHOD_NONE before sending anything
        // (userauth.c:1503-1507); the port falls back to ssh-rsa and lets the
        // server's FAILURE surface as AuthenticationFailed — better interop
        // against servers that accept ssh-rsa unadvertised.
        return "ssh-rsa";
    }

    // ── Packet builders ─────────────────────────────────────────────────────

    /// <summary>
    /// Builds a minimal USERAUTH_REQUEST: [50] [user] [ssh-connection] [method]
    /// [+ extra]. Mirrors the common header of <c>userauth_list</c>'s packet.
    /// </summary>
    private static byte[] BuildUserauthRequest(string username, string method, byte[]? extra)
    {
        byte[] user = Encoding.UTF8.GetBytes(username);
        byte[] methodBytes = Encoding.UTF8.GetBytes(method);
        int extraLen = extra?.Length ?? 0;
        byte[] payload = new byte[1 + 4 + user.Length + 4 + ServiceConnection.Length + 4 + methodBytes.Length + extraLen];
        int offset = 0;
        payload[offset++] = (byte)PacketType.UserauthRequest;
        WriteString(payload, ref offset, user);
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes(ServiceConnection));
        WriteString(payload, ref offset, methodBytes);
        if (extra is not null)
        {
            Buffer.BlockCopy(extra, 0, payload, offset, extra.Length);
        }
        return payload;
    }

    /// <summary>
    /// Builds the password USERAUTH_REQUEST. When <paramref name="change"/> is
    /// false: [50] [user] [ssh-connection] [password] [FALSE] [4 + password].
    /// When true: [50] [user] [ssh-connection] [password] [TRUE] [4 + old] [4 + new].
    /// Mirrors <c>userauth.c:306-331</c> (initial) and the change flow at 429-484.
    /// </summary>
    private static byte[] BuildPasswordRequest(string username, string password, bool change, string? oldPassword)
    {
        byte[] user = Encoding.UTF8.GetBytes(username);
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[]? oldPw = oldPassword is null ? null : Encoding.UTF8.GetBytes(oldPassword);
        int oldLen = oldPw?.Length ?? 0;

        int len = 1 + 4 + user.Length + 4 + ServiceConnection.Length + 4 + 8 /*"password"*/
            + 1 /*bool*/ + 4 + pw.Length;
        if (change)
        {
            len += 4 + oldLen;
        }

        byte[] payload = new byte[len];
        int offset = 0;
        payload[offset++] = (byte)PacketType.UserauthRequest;
        WriteString(payload, ref offset, user);
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes(ServiceConnection));
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes("password"));
        payload[offset++] = (byte)(change ? 1 : 0);
        if (change && oldPw is not null)
        {
            WriteString(payload, ref offset, oldPw);
        }
        WriteString(payload, ref offset, pw);
        return payload;
    }

    /// <summary>
    /// Builds the publickey probe packet: [50] [user] [ssh-connection] [publickey]
    /// [FALSE] [string algoName] [string pubKeyBlob]. Mirrors
    /// <c>userauth.c:1629-1640</c>. The bool byte is at a fixed offset the
    /// caller flips to TRUE in-place before signing.
    /// </summary>
    private static byte[] BuildPublickeyProbe(string username, string algoName, byte[] publicKeyBlob)
    {
        byte[] user = Encoding.UTF8.GetBytes(username);
        byte[] algo = Encoding.UTF8.GetBytes(algoName);
        int len = 1 + 4 + user.Length + 4 + ServiceConnection.Length + 4 + 9 /*"publickey"*/
            + 1 /*bool FALSE*/ + 4 + algo.Length + 4 + publicKeyBlob.Length;
        byte[] payload = new byte[len];
        int offset = 0;
        payload[offset++] = (byte)PacketType.UserauthRequest;
        WriteString(payload, ref offset, user);
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes(ServiceConnection));
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes("publickey"));
        payload[offset++] = 0;   // sig_included = FALSE
        WriteString(payload, ref offset, algo);
        WriteString(payload, ref offset, publicKeyBlob);
        return payload;
    }

    /// <summary>
    /// Builds the keyboard-interactive request: [50] [user] [ssh-connection]
    /// [keyboard-interactive] [string ""] [string ""]. Mirrors
    /// <c>userauth.c:2128-2162</c>.
    /// </summary>
    private static byte[] BuildKbdIntRequest(string username)
    {
        byte[] user = Encoding.UTF8.GetBytes(username);
        int len = 1 + 4 + user.Length + 4 + ServiceConnection.Length + 4 + 20 /*"keyboard-interactive"*/
            + 4 + 4;   // two empty strings (language, submethods)
        byte[] payload = new byte[len];
        int offset = 0;
        payload[offset++] = (byte)PacketType.UserauthRequest;
        WriteString(payload, ref offset, user);
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes(ServiceConnection));
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes("keyboard-interactive"));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset, 4), 0);   // empty language
        offset += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset, 4), 0);   // empty submethods
        return payload;
    }

    /// <summary>
    /// Builds the keyboard-interactive response: [61] [uint32 num-responses]
    /// [ [string response] ]*. Mirrors <c>userauth.c:2255-2296</c>.
    /// </summary>
    private static byte[] BuildKbdIntResponse(string[] answers)
    {
        byte[][] answerBytes = new byte[answers.Length][];
        int totalLen = 1 + 4;
        for (int i = 0; i < answers.Length; i++)
        {
            answerBytes[i] = Encoding.UTF8.GetBytes(answers[i]);
            totalLen += 4 + answerBytes[i].Length;
        }

        byte[] payload = new byte[totalLen];
        int offset = 0;
        payload[offset++] = (byte)PacketType.UserauthInfoResponse;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(offset, 4), answers.Length);
        offset += 4;
        foreach (byte[] a in answerBytes)
        {
            WriteString(payload, ref offset, a);
        }
        return payload;
    }

    /// <summary>
    /// Builds the hostbased USERAUTH_REQUEST: [50] [user] [ssh-connection]
    /// [hostbased] [string algoName] [string pubKeyBlob] [string hostname]
    /// [string localUsername]. Mirrors <c>userauth.c:1079-1091</c>.
    /// </summary>
    private static byte[] BuildHostbasedRequest(
        string username, string algoName, byte[] publicKeyBlob,
        string hostname, string localUsername)
    {
        byte[] user = Encoding.UTF8.GetBytes(username);
        byte[] algo = Encoding.UTF8.GetBytes(algoName);
        byte[] host = Encoding.UTF8.GetBytes(hostname);
        byte[] localUser = Encoding.UTF8.GetBytes(localUsername);
        int len = 1 + 4 + user.Length + 4 + ServiceConnection.Length + 4 + 9 /*"hostbased"*/
            + 4 + algo.Length + 4 + publicKeyBlob.Length + 4 + host.Length + 4 + localUser.Length;
        byte[] payload = new byte[len];
        int offset = 0;
        payload[offset++] = (byte)PacketType.UserauthRequest;
        WriteString(payload, ref offset, user);
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes(ServiceConnection));
        WriteString(payload, ref offset, Encoding.UTF8.GetBytes("hostbased"));
        WriteString(payload, ref offset, algo);
        WriteString(payload, ref offset, publicKeyBlob);
        WriteString(payload, ref offset, host);
        WriteString(payload, ref offset, localUser);
        return payload;
    }

    /// <summary>
    /// Builds the signed data blob: [string session_id] ‖ <paramref name="request"/>.
    /// Mirrors <c>userauth.c:1733-1746</c> (publickey) and <c>userauth.c:1106-1113</c>
    /// (hostbased) — both sign <c>session_id ‖ USERAUTH_REQUEST</c>.
    /// </summary>
    private static byte[] BuildSignedData(ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> request)
    {
        byte[] blob = new byte[4 + sessionId.Length + request.Length];
        BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(0, 4), sessionId.Length);
        sessionId.CopyTo(blob.AsSpan(4));
        request.CopyTo(blob.AsSpan(4 + sessionId.Length));
        return blob;
    }

    /// <summary>
    /// Appends the signature blob as an SSH string to the USERAUTH_REQUEST
    /// packet. Mirrors <c>userauth.c:1823-1828</c>: the sig blob is
    /// <c>[string algoName][string rawSig]</c>, appended as a single SSH string.
    /// </summary>
    private static byte[] AppendSignature(byte[] request, byte[] sigBlob)
    {
        byte[] result = new byte[request.Length + 4 + sigBlob.Length];
        Buffer.BlockCopy(request, 0, result, 0, request.Length);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(request.Length, 4), sigBlob.Length);
        Buffer.BlockCopy(sigBlob, 0, result, request.Length + 4, sigBlob.Length);
        return result;
    }

    /// <summary>Writes an SSH string (BE32 length + UTF-8 bytes) and advances the offset.</summary>
    private static void WriteString(byte[] buf, ref int offset, byte[] bytes)
    {
        BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(offset, 4), bytes.Length);
        offset += 4;
        Buffer.BlockCopy(bytes, 0, buf, offset, bytes.Length);
        offset += bytes.Length;
    }
}
