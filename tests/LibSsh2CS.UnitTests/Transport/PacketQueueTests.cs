using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for <see cref="PacketQueue"/>: type-filtered awaits, non-matching
/// packet stashing, inline handling of DISCONNECT/IGNORE/DEBUG/EXT_INFO, and
/// strict-KEX policy enforcement.
/// </summary>
/// <remarks>
/// All tests use cleartext packets (pre-NEWKEYS) so the <see cref="PacketReader"/>
/// underneath the queue needs no cipher/MAC setup. The <see cref="PacketQueue"/>
/// itself is cipher-agnostic — it only inspects <see cref="RawPacket.Type"/> and
/// the payload bytes for inline dispatch.
/// </remarks>
public class PacketQueueTests
{
    // ── WaitForTypeAsync: match returned ───────────────────────────────

    [Fact]
    public async Task WaitForTypeAsync_ReturnsMatchingPacket()
    {
        // Pipe carries one KEXINIT (type 20). WaitForTypeAsync(20) returns it.
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith(kexinit);

        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);

        Assert.Equal(PacketType.KexInit, got.Type);
        Assert.Equal((byte[])[20], got.Payload);
    }

    [Fact]
    public async Task WaitForTypeAsync_FastPath_ReturnsStashedPacket()
    {
        // First wait pulls a non-matching packet and stashes it; second wait
        // for the stashed type returns it from the stash without reading.
        byte[] ignore = BuildCleartextPacket(PacketType.Ignore, [2]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. ignore, .. kexinit]);

        // Wait for KEXINIT — the IGNORE packet is read first, inline-handled
        // (discarded), then KEXINIT is read and returned.
        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, got.Type);
    }

    // ── Non-matching packets stashed for later waiters ─────────────────

    [Fact]
    public async Task WaitForTypeAsync_StashesNonMatching_ForLaterWaiter()
    {
        // A NEWKEYS (21) arrives while we're waiting for KEXINIT (20). The
        // NEWKEYS is stashed; a subsequent WaitForTypeAsync(21) returns it
        // from the stash without a new read.
        byte[] newkeys = BuildCleartextPacket(PacketType.NewKeys, [21]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. newkeys, .. kexinit]);

        // Wait for KEXINIT — NEWKEYS is stashed (not inline-handled; it's a
        // real protocol packet).
        RawPacket kex = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, kex.Type);

        // Now wait for NEWKEYS — should come from the stash, no new read needed.
        // (The pipe is already completed, so a new read would throw SocketDisconnect.)
        RawPacket nk = await q.WaitForTypeAsync(PacketType.NewKeys, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys, nk.Type);
    }

    // ── WaitForTypesAsync: any-of match ────────────────────────────────

    [Fact]
    public async Task WaitForTypesAsync_ReturnsFirstMatchingOfSeveral()
    {
        // Pipe: IGNORE (2), then NEWKEYS (21). WaitForTypesAsync([20, 21])
        // should skip the IGNORE (inline-handled) and return the NEWKEYS.
        byte[] ignore = BuildCleartextPacket(PacketType.Ignore, [2]);
        byte[] newkeys = BuildCleartextPacket(PacketType.NewKeys, [21]);
        PacketQueue q = BuildQueueWith([.. ignore, .. newkeys]);

        RawPacket got = await q.WaitForTypesAsync(
            [PacketType.KexInit, PacketType.NewKeys], TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys, got.Type);
    }

    // ── Inline handling: DISCONNECT / IGNORE / DEBUG / EXT_INFO ────────

    [Fact]
    public async Task WaitForTypeAsync_Disconnect_ThrowsSocketDisconnect()
    {
        // SSH_MSG_DISCONNECT (1) with reason=2, description="bad hostkey".
        // Payload: [1] [00 00 00 02] [00 00 00 0a "bad hostkey"] [00 00 00 00].
        byte[] desc = "bad hostkey"u8.ToArray();
        byte[] discPayload = new byte[1 + 4 + 4 + desc.Length + 4];
        discPayload[0] = PacketType.Disconnect;
        BinaryPrimitives.WriteUInt32BigEndian(discPayload.AsSpan(1, 4), 2u); // reason
        BinaryPrimitives.WriteUInt32BigEndian(discPayload.AsSpan(5, 4), (uint)desc.Length);
        Buffer.BlockCopy(desc, 0, discPayload, 9, desc.Length);
        // lang tag (empty) — already zero-filled.

        byte[] disc = BuildCleartextPacket(PacketType.Disconnect, discPayload);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. disc, .. kexinit]);

        SshException? ex = null;
        try
        {
            await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Contains("bad hostkey", ex.Message);
    }

    [Fact]
    public async Task WaitForTypeAsync_Ignore_SilentlyDiscarded()
    {
        // SSH_MSG_IGNORE (2) is discarded; the subsequent KEXINIT is returned.
        byte[] ignore = BuildCleartextPacket(PacketType.Ignore, [2, 0xAA, 0xBB]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. ignore, .. kexinit]);

        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, got.Type);
    }

    [Fact]
    public async Task WaitForTypeAsync_Debug_SilentlyDiscarded()
    {
        // SSH_MSG_DEBUG (4) is discarded; the subsequent KEXINIT is returned.
        byte[] debug = BuildCleartextPacket(PacketType.Debug, [4, 0x00, 0x00, 0x00, 0x00]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. debug, .. kexinit]);

        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, got.Type);
    }

    [Fact]
    public async Task WaitForTypeAsync_ExtInfo_StashedForLaterRetrieval()
    {
        // SSH_MSG_EXT_INFO (7) is stashed (not discarded); a later
        // WaitForTypeAsync(7) retrieves it. Phase 2 userauth will consume it
        // for server-sig-algs.
        byte[] extInfo = BuildCleartextPacket(PacketType.ExtInfo, [7, 0x00, 0x00, 0x00, 0x00]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. extInfo, .. kexinit]);

        // Wait for KEXINIT — EXT_INFO is stashed inline.
        RawPacket kex = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, kex.Type);

        // Now retrieve the stashed EXT_INFO.
        RawPacket ext = await q.WaitForTypeAsync(PacketType.ExtInfo, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ExtInfo, ext.Type);
    }

    // ── Strict-KEX enforcement (packet.c:715-739) ───────────────────────

    [Fact]
    public async Task WaitForTypeAsync_StrictKex_UnexpectedType_ThrowsSocketDisconnect()
    {
        // During INITIAL_KEX with strict-KEX on, a non-expected packet type
        // triggers a disconnect. Here we wait for KEXINIT (20) but a
        // ChannelOpen (90) arrives — strict-KEX violation.
        byte[] channelOpen = BuildCleartextPacket(PacketType.ChannelOpen, [90]);
        PacketQueue q = BuildQueueWith(channelOpen);
        q.StrictKex = true;
        q.InitialKex = true;

        SshException? ex = null;
        try
        {
            await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Contains("strict KEX violation", ex.Message);
    }

    [Fact]
    public async Task WaitForTypeAsync_StrictKex_ExpectedType_Passes()
    {
        // During INITIAL_KEX with strict-KEX on, the expected type is accepted.
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith(kexinit);
        q.StrictKex = true;
        q.InitialKex = true;

        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, got.Type);
    }

    [Fact]
    public async Task WaitForTypeAsync_StrictKex_Disconnect_IsViolationBeforeInline()
    {
        // (C parity, packet.c:728-739): the strict-KEX unexpected-type
        // check runs BEFORE the per-type exception switch in _libssh2_packet_add,
        // so under strict KEX during INITIAL_KEX even a DISCONNECT is a
        // violation — the server's description never surfaces (the C's
        // fullpacket_required_type != msg check precedes the DISCONNECT case).
        byte[] desc = "server shutdown"u8.ToArray();
        byte[] discPayload = new byte[1 + 4 + 4 + desc.Length + 4];
        discPayload[0] = PacketType.Disconnect;
        BinaryPrimitives.WriteUInt32BigEndian(discPayload.AsSpan(1, 4), 11u); // SSH_DISCONNECT_BY_APPLICATION
        BinaryPrimitives.WriteUInt32BigEndian(discPayload.AsSpan(5, 4), (uint)desc.Length);
        Buffer.BlockCopy(desc, 0, discPayload, 9, desc.Length);
        byte[] disc = BuildCleartextPacket(PacketType.Disconnect, discPayload);

        PacketQueue q = BuildQueueWith(disc);
        q.StrictKex = true;
        q.InitialKex = true;

        SshException? ex = null;
        try
        {
            await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Contains("strict KEX violation", ex.Message);
        Assert.DoesNotContain("server shutdown", ex.Message);
    }

    [Fact]
    public async Task WaitForTypeAsync_StrictKex_Ignore_IsViolationBeforeInline()
    {
        // (C parity, packet.c:728-739): under strict KEX during
        // INITIAL_KEX the unexpected-type check precedes the inline handling
        // switch, so IGNORE is a violation — it is NOT silently discarded
        // (the pre-fix port inline-handled it first).
        byte[] ignore = BuildCleartextPacket(PacketType.Ignore, [2, 0xFF]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. ignore, .. kexinit]);
        q.StrictKex = true;
        q.InitialKex = true;

        SshException? ex = null;
        try
        {
            await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Contains("strict KEX violation", ex.Message);
    }

    [Fact]
    public async Task WaitForTypeAsync_StrictKex_ExtInfo_IsViolationBeforeInline()
    {
        // (C parity): same for EXT_INFO — the pre-fix port stashed it
        // inline before the strict check; the C rejects it like any other
        // non-required type under strict KEX during INITIAL_KEX.
        byte[] extInfo = BuildCleartextPacket(PacketType.ExtInfo, [7, 0x00, 0x00, 0x00, 0x00]);
        byte[] newkeys = BuildCleartextPacket(PacketType.NewKeys, [21]);
        PacketQueue q = BuildQueueWith([.. extInfo, .. newkeys]);
        q.StrictKex = true;
        q.InitialKex = true;

        SshException? ex = null;
        try
        {
            await q.WaitForTypeAsync(PacketType.NewKeys, TestContext.Current.CancellationToken);
        }
        catch (SshException e)
        {
            ex = e;
        }
        Assert.NotNull(ex);
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Contains("strict KEX violation", ex.Message);
    }

    [Fact]
    public async Task WaitForTypeAsync_AfterInitialKex_StrictKexNotEnforced()
    {
        // Once InitialKex is false (post-NEWKEYS), strict-KEX does not enforce
        // the unexpected-type rule — any packet is stashed for later waiters.
        byte[] channelData = BuildCleartextPacket(PacketType.ChannelData, [94, 0x01, 0x02]);
        byte[] kexinit = BuildCleartextPacket(PacketType.KexInit, [20]);
        PacketQueue q = BuildQueueWith([.. channelData, .. kexinit]);
        q.StrictKex = true;
        q.InitialKex = false;  // post-KEX

        // Wait for KEXINIT — ChannelData is stashed (not a violation now).
        RawPacket kex = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, kex.Type);

        // The stashed ChannelData is retrievable.
        RawPacket cd = await q.WaitForTypeAsync(PacketType.ChannelData, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.ChannelData, cd.Type);
    }

    // ── Cancellation ───────────────────────────────────────────────────

    [Fact]
    public async Task WaitForTypeAsync_Cancellation_Propagates()
    {
        // A pipe with no data and the writer NOT completed: ReadPacketAsync
        // blocks on ReadAsync until the token cancels. The cancellation must
        // propagate as OperationCanceledException (not a SocketDisconnect,
        // which is what a completed-empty pipe would produce).
        var pipe = new Pipe();
        var reader = new PacketReader(pipe.Reader);
        var q = new PacketQueue(reader);

        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(100);

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await q.WaitForTypeAsync(PacketType.KexInit, cts.Token));

        // Complete the writer to clean up the pipe.
        await pipe.Writer.CompleteAsync();
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a <see cref="PacketQueue"/> over a <see cref="PacketReader"/>
    /// fed with the given cleartext packet bytes. The pipe writer is completed
    /// so the reader sees EOF after the buffered bytes.
    /// </summary>
    private static PacketQueue BuildQueueWith(byte[] data)
    {
        var pipe = new Pipe();
        pipe.Writer.WriteAsync(data, TestContext.Current.CancellationToken).AsTask().Wait();
        pipe.Writer.Complete();
        var reader = new PacketReader(pipe.Reader);
        return new PacketQueue(reader);
    }

    /// <summary>
    /// Builds a single cleartext SSH packet (length|padlen|payload|padding)
    /// carrying the given payload. The payload's first byte must equal
    /// <paramref name="type"/> (the SSH_MSG_* type byte).
    /// </summary>
    private static byte[] BuildCleartextPacket(int type, byte[] payload)
    {
        if (payload.Length == 0 || payload[0] != type)
        {
            byte[] withType = new byte[payload.Length + 1];
            withType[0] = (byte)type;
            Buffer.BlockCopy(payload, 0, withType, 1, payload.Length);
            payload = withType;
        }

        // blocksize=8 cleartext. packet_length = payload + 1 + padding.
        int withHeader = payload.Length + 1 + 4;
        int padding = 8 - (withHeader % 8);
        if (padding < 4)
        {
            padding += 8;
        }

        int packetLength = payload.Length + 1 + padding;
        byte[] wire = new byte[4 + packetLength];
        BinaryPrimitives.WriteUInt32BigEndian(wire, (uint)packetLength);
        wire[4] = (byte)padding;
        Buffer.BlockCopy(payload, 0, wire, 5, payload.Length);
        return wire;
    }
}
