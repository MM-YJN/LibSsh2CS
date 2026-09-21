using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Security.Cryptography;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// End-to-end tests for <see cref="KeyExchange.RunExchangeAsync"/>: a mock SSH
/// server over a pair of pipes exercises the full KEXDH_INIT → KEXDH_REPLY →
/// NEWKEYS → NEWKEYS flow, then confirms the installed keys round-trip an
/// encrypted packet. curve25519-sha256 + aes256-ctr + hmac-sha2-256.
/// </summary>
public class RunExchangeFlowTests
{
    private const int C2S = 0;  // client→server pipe index
    private const int S2C = 1;  // server→client pipe index

    [Theory]
    [InlineData("", false)]
    [InlineData("80", false)]
    [InlineData("ff", false)]
    [InlineData("00", false)]
    [InlineData("01", false)]
    [InlineData("0080", true)]
    [InlineData("000002", true)]
    public async Task RunExchange_DhValidatesWireValueBeforeVerification(string hex, bool valid)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var outbound = new Pipe();
        var inbound = new Pipe();
        await using var writer = new PacketWriter(outbound.Writer);
        await using var reader = new PacketReader(inbound.Reader);
        var queue = new PacketQueue(reader);
        NegotiatedMethods neg = BuildNegotiated(true) with { Kex = KexAlgorithm.DhGroup14Sha256, KexName = "diffie-hellman-group14-sha256" };
        bool called = false;
        byte[] raw = Convert.FromHexString(hex);
        byte[] clientInit = [20];
        byte[] serverInit = [20];
        byte[] hostKey = [1];
        byte[]? actualHash = null;
        Task<KeyExchange.KexExchangeResult> exchange = KeyExchange.RunExchangeAsync(
            writer, queue, neg, "client", "server", clientInit, serverInit,
            verifyAsync: (_, hash, _, _) =>
            {
                called = true;
                actualHash = hash.ToArray();
                return Task.FromResult(false);
            }, cancellationToken: ct);
        await using var serverReader = new PacketReader(outbound.Reader);
        await using var serverWriter = new PacketWriter(inbound.Writer);
        RawPacket init = await serverReader.ReadPacketAsync(ct);
        byte[] e = ExtractString(init.Payload, 1);
        await serverWriter.WritePacketAsync(PacketType.KexDhReply, BuildKexReply(hostKey, raw, [1]), ct);
        SshException ex = await Assert.ThrowsAsync<SshException>(() => exchange);
        Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
        Assert.Equal(valid, called);
        Assert.Equal(1u, writer.Seqno); // No NEWKEYS or key installation.
        if (valid)
        {
            // f = 2^x; independently derive K from e and verify the original padded f is hashed.
            int exponent = hex == "0080" ? 7 : 1;
            var peer = new DhGroup14(exponent);
            byte[] expected = KeyExchange.ComputeExchangeHash(neg.Kex, "client"u8.ToArray(), "server"u8.ToArray(),
                clientInit, serverInit, hostKey, e, raw, peer.ComputeSharedSecret(Endian.BigIntegerFromBigEndian(e)));
            Assert.Equal(expected, actualHash);
        }
    }

    [Theory]
    [InlineData(true)]   // strict-KEX on  → seqno must reset to 0 after NEWKEYS
    [InlineData(false)]  // strict-KEX off → seqno continues
    public async Task RunExchange_Curve25519_InstallsKeysAndResetsSeqno(bool strictKex)
    {
        var pipes = new Pipe[2];
        pipes[C2S] = new Pipe();
        pipes[S2C] = new Pipe();

        // Client transport: writes to c2s, reads from s2c.
        var clientWriter = new PacketWriter(pipes[C2S].Writer);
        var clientQueue = new PacketQueue(new PacketReader(pipes[S2C].Reader));

        NegotiatedMethods neg = BuildNegotiated(strictKex);
        byte[] iClient = [PacketType.KexInit, 0x01, 0x02, 0x03];
        byte[] iServer = [PacketType.KexInit, 0x04, 0x05, 0x06];

        // The client's outbound ephemeral (Q_C) is unknown to the test until the
        // exchange runs; the server learns it from KEXDH_INIT. The shared secret
        // K is computed server-side and reused to verify the post-NEWKEYS keys.
        Task<KeyExchange.KexExchangeResult> clientTask = KeyExchange.RunExchangeAsync(
            clientWriter, clientQueue, neg,
            "SSH-2.0-test-client", "SSH-2.0-test-server",
            iClient, iServer, verifyAsync: null, cancellationToken: TestContext.Current.CancellationToken);

        // ── Mock server (cleartext, pre-NEWKEYS) ───────────────────────────
        var serverReader = new PacketReader(pipes[C2S].Reader);
        var serverWriter = new PacketWriter(pipes[S2C].Writer);

        // (a) read KEXDH_INIT, extract Q_C
        RawPacket init = await serverReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexDhInit, init.Type);
        byte[] qC = ExtractString(init.Payload, 1);

        // (b) server curve25519 keypair + shared secret
        var serverKp = new Curve25519KeyExchange();
        byte[] qS = serverKp.PublicKey;
        byte[] kBytes = serverKp.ComputeSharedSecret(qC);
        System.Numerics.BigInteger k = Endian.BigIntegerFromBigEndian(kBytes);

        // (c) build + send KEXDH_REPLY: [31][string K_S][string Q_S][string sig]
        byte[] hostKey = [0x00, 0x00, 0x00, 0x07, (byte)'s', (byte)'s', (byte)'h', 0xAA];
        byte[] sig = [(byte)'X'];
        await serverWriter.WritePacketAsync(PacketType.KexDhReply,
            BuildKexReply(hostKey, qS, sig), TestContext.Current.CancellationToken);

        // (d) read client NEWKEYS
        RawPacket nk1 = await serverReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys, nk1.Type);

        // (e) send server NEWKEYS
        await serverWriter.WritePacketAsync(PacketType.NewKeys,
            new byte[] { (byte)PacketType.NewKeys }, TestContext.Current.CancellationToken);

        // Wait for the client to finish installing keys.
        KeyExchange.KexExchangeResult result = await clientTask;

        // ── Assertions on the exchange result ──────────────────────────────
        // Recompute H independently and confirm RunExchangeAsync got the same.
        byte[] expectedH = KeyExchange.ComputeExchangeHash(
            neg.Kex,
            System.Text.Encoding.ASCII.GetBytes("SSH-2.0-test-client"),
            System.Text.Encoding.ASCII.GetBytes("SSH-2.0-test-server"),
            iClient, iServer, hostKey, qC, qS, k);
        Assert.Equal(expectedH, result.ExchangeHash);
        Assert.Equal(expectedH, result.SessionId);   // first kex: session_id == H

        // Seqno reset: the client sent KEXDH_INIT (seqno 0) + NEWKEYS (seqno 1),
        // so after NEWKEYS the count is 2. Strict-KEX resets to 0; non-strict
        // continues at 2 (SetOutboundKeys/SetInboundKeys now reset only when
        // strict-KEX, matching transport.c:342-345 / 1271-1273).
        Assert.Equal(strictKex ? 0u : 2u, clientWriter.Seqno);
        Assert.Equal(strictKex ? 0u : 2u, clientQueue.Reader.Seqno);

        // ── Post-NEWKEYS encrypted round-trip ──────────────────────────────
        // The client sends an encrypted SERVICE_REQUEST; the mock server reads
        // it from the SAME serverReader (which tracked the client's cleartext
        // seqno through KEXDH_INIT+NEWKEYS, so after SetInboundKeys its seqno
        // matches the client's first encrypted seqno: 0 strict / 2 non-strict).
        InstallKeys(serverReader, neg, k, expectedH, isOutboundDirection: true);

        byte[] servicePayload = new byte[] { PacketType.ServiceRequest, (byte)'s', 0, 0, 0, 1, (byte)'x' };
        await clientWriter.WritePacketAsync(PacketType.ServiceRequest, servicePayload,
            TestContext.Current.CancellationToken);

        RawPacket svc = await serverReader.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ServiceRequest, svc.Type);
        Assert.Equal(servicePayload, svc.Payload);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Increment-8 hostkey-verify integration: the verify-callback seam in
    // RunExchangeAsync (invoked AFTER H, BEFORE NEWKEYS) is wired to
    // HostKeyVerifier.Verify. The mock server produces a REAL RSA-SHA256
    // signature over H (Ed25519 Sign is deferred to Phase 2, so RSA — which
    // the BCL can sign — exercises the same uniform parse + verify path).
    // ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(true)]   // strict-KEX
    [InlineData(false)]  // non-strict
    public async Task RunExchange_HostKeyVerifier_RsaSha256_AcceptsValidSig(bool strictKex)
    {
        Pipe[] pipes = SetupPipes();
        var clientWriter = new PacketWriter(pipes[C2S].Writer);
        var clientQueue = new PacketQueue(new PacketReader(pipes[S2C].Reader));
        NegotiatedMethods neg = BuildNegotiated(strictKex, SshHostKeyType.RsaSha256, "rsa-sha2-256");
        byte[] iClient = [PacketType.KexInit, 0x01, 0x02, 0x03];
        byte[] iServer = [PacketType.KexInit, 0x04, 0x05, 0x06];

        // D3 seam: the caller closes over negotiated.HostKey and delegates to
        // HostKeyVerifier.Verify. RunExchangeAsync invokes this after computing H,
        // before NEWKEYS.
        Task<KeyExchange.KexExchangeResult> clientTask = KeyExchange.RunExchangeAsync(
            clientWriter, clientQueue, neg,
            "SSH-2.0-test-client", "SSH-2.0-test-server",
            iClient, iServer,
            verifyAsync: (ks, h, sig, ct) => Task.FromResult(HostKeyVerifier.Verify(ks, h, sig, neg.HostKey)),
            cancellationToken: TestContext.Current.CancellationToken);

        // Mock server: RSA host key + curve25519 KEX + RSA-SHA256 sign over H.
        using var rsa = RSA.Create(2048);
        byte[] hostKey = BuildRsaHostKey(rsa);
        var serverReader = new PacketReader(pipes[C2S].Reader);
        var serverWriter = new PacketWriter(pipes[S2C].Writer);

        byte[] qC = ExtractString(
            (await serverReader.ReadPacketAsync(TestContext.Current.CancellationToken)).Payload, 1);
        var serverKp = new Curve25519KeyExchange();
        byte[] qS = serverKp.PublicKey;
        System.Numerics.BigInteger k = Endian.BigIntegerFromBigEndian(serverKp.ComputeSharedSecret(qC));

        byte[] h = KeyExchange.ComputeExchangeHash(
            neg.Kex,
            System.Text.Encoding.ASCII.GetBytes("SSH-2.0-test-client"),
            System.Text.Encoding.ASCII.GetBytes("SSH-2.0-test-server"),
            iClient, iServer, hostKey, qC, qS, k);
        byte[] sigBlob = BuildSigBlob("rsa-sha2-256",
            rsa.SignHash(SHA256.HashData(h), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        await serverWriter.WritePacketAsync(PacketType.KexDhReply,
            BuildKexReply(hostKey, qS, sigBlob), TestContext.Current.CancellationToken);

        // Client verifies, sends NEWKEYS; server answers NEWKEYS.
        Assert.Equal(PacketType.NewKeys,
            (await serverReader.ReadPacketAsync(TestContext.Current.CancellationToken)).Type);
        await serverWriter.WritePacketAsync(PacketType.NewKeys,
            new byte[] { (byte)PacketType.NewKeys }, TestContext.Current.CancellationToken);

        KeyExchange.KexExchangeResult result = await clientTask;
        Assert.Equal(hostKey, result.HostKey);
        Assert.Equal(sigBlob, result.Signature);
    }

    [Fact]
    public async Task RunExchange_HostKeyVerifier_TamperedSig_AbortsBeforeNewKeys()
    {
        Pipe[] pipes = SetupPipes();
        var clientWriter = new PacketWriter(pipes[C2S].Writer);
        var clientQueue = new PacketQueue(new PacketReader(pipes[S2C].Reader));
        NegotiatedMethods neg = BuildNegotiated(strictKex: true, SshHostKeyType.RsaSha256, "rsa-sha2-256");
        byte[] iClient = [PacketType.KexInit, 0x01, 0x02, 0x03];
        byte[] iServer = [PacketType.KexInit, 0x04, 0x05, 0x06];

        Task<KeyExchange.KexExchangeResult> clientTask = KeyExchange.RunExchangeAsync(
            clientWriter, clientQueue, neg,
            "SSH-2.0-test-client", "SSH-2.0-test-server",
            iClient, iServer,
            verifyAsync: (ks, h, sig, ct) => Task.FromResult(HostKeyVerifier.Verify(ks, h, sig, neg.HostKey)),
            cancellationToken: TestContext.Current.CancellationToken);

        using var rsa = RSA.Create(2048);
        byte[] hostKey = BuildRsaHostKey(rsa);
        var serverWriter = new PacketWriter(pipes[S2C].Writer);
        var serverReader = new PacketReader(pipes[C2S].Reader);

        byte[] qC = ExtractString(
            (await serverReader.ReadPacketAsync(TestContext.Current.CancellationToken)).Payload, 1);
        var serverKp = new Curve25519KeyExchange();
        byte[] qS = serverKp.PublicKey;
        System.Numerics.BigInteger k = Endian.BigIntegerFromBigEndian(serverKp.ComputeSharedSecret(qC));
        byte[] h = KeyExchange.ComputeExchangeHash(
            neg.Kex,
            System.Text.Encoding.ASCII.GetBytes("SSH-2.0-test-client"),
            System.Text.Encoding.ASCII.GetBytes("SSH-2.0-test-server"),
            iClient, iServer, hostKey, qC, qS, k);

        byte[] rawSig = rsa.SignHash(SHA256.HashData(h), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rawSig[0] ^= 0xFF;   // corrupt the signature — verify must reject
        byte[] sigBlob = BuildSigBlob("rsa-sha2-256", rawSig);

        await serverWriter.WritePacketAsync(PacketType.KexDhReply,
            BuildKexReply(hostKey, qS, sigBlob), TestContext.Current.CancellationToken);

        // The client aborts after verify returns false, BEFORE sending NEWKEYS
        // (kex.c:746 ordering). The server therefore never sees a NEWKEYS.
        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await clientTask);
        Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
    }

    private static Pipe[] SetupPipes()
    {
        var p = new Pipe[2];
        p[C2S] = new Pipe();
        p[S2C] = new Pipe();
        return p;
    }

    /// <summary>Builds an RSA host-key blob K_S: <c>string "ssh-rsa" + string e + string n</c>.</summary>
    private static byte[] BuildRsaHostKey(RSA rsa)
    {
        RSAParameters p = rsa.ExportParameters(includePrivateParameters: false);
        byte[] name = System.Text.Encoding.ASCII.GetBytes("ssh-rsa");
        return ConcatStrings([name, p.Exponent!, p.Modulus!]);
    }

    /// <summary>Builds a sig-blob envelope: <c>string name + string body</c>.</summary>
    private static byte[] BuildSigBlob(string name, byte[] body)
    {
        byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
        return ConcatStrings([nameBytes, body]);
    }

    /// <summary>Concatenates SSH strings (each BE32-length-prefixed) end-to-end.</summary>
    private static byte[] ConcatStrings(byte[][] parts)
    {
        int total = parts.Sum(part => 4 + part.Length);
        byte[] buf = new byte[total];
        int o = 0;
        foreach (byte[] part in parts)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(o, 4), (uint)part.Length);
            part.CopyTo(buf, o + 4);
            o += 4 + part.Length;
        }

        return buf;
    }

    /// <summary>Builds a NegotiatedMethods for curve25519 + aes256-ctr + hmac-sha2-256.</summary>
    private static NegotiatedMethods BuildNegotiated(bool strictKex)
        => BuildNegotiated(strictKex, SshHostKeyType.Ed25519, "ssh-ed25519");

    /// <summary>Builds a NegotiatedMethods for curve25519 + aes256-ctr + hmac-sha2-256,
    /// with a caller-selected host-key type (for the RSA verify tests).</summary>
    private static NegotiatedMethods BuildNegotiated(bool strictKex, SshHostKeyType hk, string hkName)
        => new()
        {
            Kex = KexAlgorithm.Curve25519Sha256,
            KexName = "curve25519-sha256",
            HostKey = hk,
            HostKeyName = hkName,
            CipherCs = "aes256-ctr",
            CipherSc = "aes256-ctr",
            MacCs = "hmac-sha2-256",
            MacSc = "hmac-sha2-256",
            CompCs = "none",
            CompSc = "none",
            StrictKex = strictKex,
        };

    /// <summary>Extracts an SSH string (BE32 len + bytes) at byte offset <paramref name="off"/>.</summary>
    private static byte[] ExtractString(byte[] data, int off)
    {
        uint len = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(off, 4));
        return data.AsSpan(off + 4, (int)len).ToArray();
    }

    /// <summary>Builds a KEXDH_REPLY payload: [31][string K_S][string Q_S][string sig].</summary>
    private static byte[] BuildKexReply(byte[] hostKey, byte[] qS, byte[] sig)
    {
        int total = 1 + (4 + hostKey.Length) + (4 + qS.Length) + (4 + sig.Length);
        byte[] p = new byte[total];
        p[0] = (byte)PacketType.KexDhReply;
        int o = 1;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(o, 4), (uint)hostKey.Length);
        hostKey.CopyTo(p, o + 4);
        o += 4 + hostKey.Length;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(o, 4), (uint)qS.Length);
        qS.CopyTo(p, o + 4);
        o += 4 + qS.Length;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(o, 4), (uint)sig.Length);
        sig.CopyTo(p, o + 4);
        return p;
    }

    /// <summary>
    /// Derives + installs keys on a reader for the post-NEWKEYS round-trip.
    /// <paramref name="isOutboundDirection"/> = true → use the client's outbound
    /// keys (A/C/E), since the mock server reads the client's ciphertext.
    /// <paramref name="sessionId"/> defaults to <paramref name="h"/> (correct for
    /// the first KEX, where session_id := H); pass the original session_id for
    /// rekey per RFC 4253 §7.1 (session_id is immutable across rekeys).
    /// </summary>
    private static void InstallKeys(PacketReader reader, NegotiatedMethods neg,
        System.Numerics.BigInteger k, byte[] h, bool isOutboundDirection,
        byte[]? sessionId = null)
    {
        byte[] sid = sessionId ?? h;
        string cipherName = isOutboundDirection ? neg.CipherCs : neg.CipherSc;
        string macName = isOutboundDirection ? neg.MacCs : neg.MacSc;
        ICipher cipher = CipherMethods.Create(cipherName)!;
        bool aead = CipherMethods.IsAead(cipher);

        char ivLetter = isOutboundDirection ? 'A' : 'B';
        char keyLetter = isOutboundDirection ? 'C' : 'D';
        char macLetter = isOutboundDirection ? 'E' : 'F';

        byte[] iv = KeyExchange.DeriveKey(neg.Kex, k, h, sid, ivLetter, cipher.IvLen);
        byte[] encKey = KeyExchange.DeriveKey(neg.Kex, k, h, sid, keyLetter, cipher.KeyLen);
        cipher.Init(encKey, iv, encrypt: false);

        IMac mac = aead ? MacMethods.Noop : MacMethods.Create(macName)!;
        if (!aead)
        {
            byte[] macKey = KeyExchange.DeriveKey(neg.Kex, k, h, sid, macLetter, mac.MacLen);
            mac.Init(macKey);
        }

        ICompression comp = CompressionMethods.Create(neg.CompCs)!;
        comp.Init(compress: false);
        reader.SetInboundKeys(cipher, mac, comp, strictKex: neg.StrictKex, compressionActive: false);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Rekey KAT: verifies a second RunExchangeAsync call
    // produces a fresh exchange hash H2 (distinct from H1) and that the rekey
    // KEX path completes. The full encrypted-rekey-on-same-transport interop
    // (where the rekey KEXINIT is encrypted under the first-KEX keys and the
    // server must decrypt/re-encrypt mid-rekey) is validated by the live
    // DockerAuth test; this unit test exercises the rekey KEX math in isolation
    // on a fresh cleartext pipe pair.
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Rekey_SecondRunExchange_ProducesFreshExchangeHash()
    {
        // First KEX on pipes[0..1]; rekey KEX on pipes[2..3] (fresh, cleartext).
        // The rekey uses a fresh writer/queue (the "same writer/queue" rekey is
        // the DockerAuth test's job — here we isolate the KEX math).
        Pipe[] pipes = SetupPipes();
        var clientWriter1 = new PacketWriter(pipes[C2S].Writer);
        var clientQueue1 = new PacketQueue(new PacketReader(pipes[S2C].Reader));
        const bool Strict = true;
        NegotiatedMethods neg = BuildNegotiated(Strict);
        byte[] iClient1 = [PacketType.KexInit, 0x01, 0x02, 0x03];
        byte[] iServer1 = [PacketType.KexInit, 0x04, 0x05, 0x06];

        // ── First KEX ──────────────────────────────────────────────────────
        Task<KeyExchange.KexExchangeResult> firstTask = KeyExchange.RunExchangeAsync(
            clientWriter1, clientQueue1, neg,
            "SSH-2.0-test-client", "SSH-2.0-test-server",
            iClient1, iServer1, verifyAsync: null, cancellationToken: TestContext.Current.CancellationToken);

        var serverReader1 = new PacketReader(pipes[C2S].Reader);
        var serverWriter1 = new PacketWriter(pipes[S2C].Writer);

        byte[] qC1 = ExtractString(
            (await serverReader1.ReadPacketAsync(TestContext.Current.CancellationToken)).Payload, 1);
        var serverKp1 = new Curve25519KeyExchange();
        byte[] qS1 = serverKp1.PublicKey;
        System.Numerics.BigInteger k1 = Endian.BigIntegerFromBigEndian(serverKp1.ComputeSharedSecret(qC1));

        byte[] hostKey = [0x00, 0x00, 0x00, 0x07, (byte)'s', (byte)'s', (byte)'h', 0xAA];
        byte[] sig = [(byte)'X'];
        await serverWriter1.WritePacketAsync(PacketType.KexDhReply,
            BuildKexReply(hostKey, qS1, sig), TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys,
            (await serverReader1.ReadPacketAsync(TestContext.Current.CancellationToken)).Type);
        await serverWriter1.WritePacketAsync(PacketType.NewKeys,
            new byte[] { (byte)PacketType.NewKeys }, TestContext.Current.CancellationToken);

        KeyExchange.KexExchangeResult firstResult = await firstTask;
        byte[] sessionId = firstResult.SessionId;

        // ── Rekey KEX on a fresh pipe pair (cleartext, isolating the KEX math) ──
        Pipe[] pipes2 = SetupPipes();
        var clientWriter2 = new PacketWriter(pipes2[C2S].Writer);
        var clientQueue2 = new PacketQueue(new PacketReader(pipes2[S2C].Reader));
        byte[] iClient2 = [PacketType.KexInit, 0xAA, 0xBB, 0xCC];
        byte[] iServer2 = [PacketType.KexInit, 0xDD, 0xEE, 0xFF];

        Task<KeyExchange.KexExchangeResult> rekeyTask = KeyExchange.RunExchangeAsync(
            clientWriter2, clientQueue2, neg,
            "SSH-2.0-test-client", "SSH-2.0-test-server",
            iClient2, iServer2,
            verifyAsync: null,
            existingSessionId: sessionId,
            cancellationToken: TestContext.Current.CancellationToken);

        var serverReader2 = new PacketReader(pipes2[C2S].Reader);
        var serverWriter2 = new PacketWriter(pipes2[S2C].Writer);

        byte[] qC2 = ExtractString(
            (await serverReader2.ReadPacketAsync(TestContext.Current.CancellationToken)).Payload, 1);
        var serverKp2 = new Curve25519KeyExchange();
        byte[] qS2 = serverKp2.PublicKey;
        System.Numerics.BigInteger k2 = Endian.BigIntegerFromBigEndian(serverKp2.ComputeSharedSecret(qC2));

        await serverWriter2.WritePacketAsync(PacketType.KexDhReply,
            BuildKexReply(hostKey, qS2, sig), TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys,
            (await serverReader2.ReadPacketAsync(TestContext.Current.CancellationToken)).Type);
        await serverWriter2.WritePacketAsync(PacketType.NewKeys,
            new byte[] { (byte)PacketType.NewKeys }, TestContext.Current.CancellationToken);

        KeyExchange.KexExchangeResult rekeyResult = await rekeyTask;

        // The rekey produces a fresh exchange hash H2, distinct from H1 (the
        // ephemeral keypairs differ → different e/f → different K → different H).
        Assert.NotEqual(firstResult.ExchangeHash, rekeyResult.ExchangeHash);

        // RFC 4253 §7.1: session_id is the FIRST exchange hash and is immutable
        // across rekeys — the rekey must reuse H1 as the session_id, not H2.
        // (This is the invariant the live DockerExecTests rekey variant relies
        // on: real OpenSSH derives post-rekey keys with the original session_id;
        // RunExchangeAsync threads it via existingSessionId.)
        Assert.Equal(firstResult.SessionId, rekeyResult.SessionId);

        // ── Post-rekey encrypted round-trip on the second pipe pair ─────────
        // Mock server derives the post-rekey keys with k2, H2, and the ORIGINAL
        // session_id (H1) — matching RunExchangeAsync's existingSessionId path.
        InstallKeys(serverReader2, neg, k2, rekeyResult.ExchangeHash,
            isOutboundDirection: true, sessionId: sessionId);
        byte[] payload2 = new byte[] { PacketType.ServiceRequest, (byte)'y', 0, 0, 0, 1, (byte)'z' };
        await clientWriter2.WritePacketAsync(PacketType.ServiceRequest, payload2,
            TestContext.Current.CancellationToken);
        RawPacket svc2 = await serverReader2.ReadPacketAsync(TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ServiceRequest, svc2.Type);
        Assert.Equal(payload2, svc2.Payload);
    }
}
