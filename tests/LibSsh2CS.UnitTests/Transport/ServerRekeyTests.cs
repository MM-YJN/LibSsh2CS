using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Increment 3.4.3 — server-initiated rekey handling in
/// <see cref="PacketQueue"/>. A post-handshake <c>SSH_MSG_KEXINIT</c> from the
/// server is a rekey request (parity with libssh2's <c>packet.c:1355-1388</c>).
/// The queue stashes the server KEXINIT and invokes the
/// <see cref="PacketQueue.RekeyTriggerAsync"/> callback, which the
/// <see cref="SshSession"/> wires to <see cref="SshSession.RekeyAsync"/>.
/// </summary>
/// <remarks>
/// All tests use cleartext packets; the queue's inline-dispatch logic is
/// cipher-agnostic. Tests cover:
/// <list type="bullet">
/// <item>Server KEXINIT post-handshake invokes the callback once.</item>
/// <item>The stashed KEXINIT is retrievable via <see cref="PacketQueue.TryTakeStashed"/>.</item>
/// <item>Initial-KEX (InitialKex=true) KEXINIT falls through to normal stash.</item>
/// <item>Two server KEXINITs without rekey completion → re-entry guard.</item>
/// <item>Callback exception propagates to the channel-op caller.</item>
/// <item>No callback wired → KEXINIT falls through to caller stash.</item>
/// <item>Non-KEXINIT inline types still work (regression: DISCONNECT/IGNORE/EXT_INFO).</item>
/// </list>
/// </remarks>
public class ServerRekeyTests
{
    [Fact]
    public async Task PostHandshake_KexInit_InvokesRekeyCallbackOnce()
    {
        // InitialKex=false + callback wired → a KEXINIT inline-invokes the callback.
        int calls = 0;
        CancellationToken receivedCt = default;
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, [20]));
        q.InitialKex = false;
        q.RekeyTriggerAsync = ct =>
        {
            calls++;
            receivedCt = ct;
            return Task.CompletedTask;
        };

        // Wait for a non-existent packet type — the KEXINIT will be inline-handled
        // (callback fires), then the queue needs another packet. Complete the pipe
        // with a ServiceAccept so the wait returns... actually completing the pipe
        // throws SocketDisconnect, which propagates as the expected end. We catch
        // it and assert the callback fired once.
        SshException? ex = await Assert.ThrowsAsync<SshException>(async () =>
            await q.WaitForTypeAsync(PacketType.ServiceAccept, CancellationToken.None));
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
        Assert.Equal(1, calls);
        Assert.Equal(CancellationToken.None, receivedCt);
    }

    [Fact]
    public async Task PostHandshake_KexInit_StashedBeforeCallbackInvoked()
    {
        // The queue MUST stash the KEXINIT BEFORE invoking the callback so the
        // rekey flow (RekeyAsync → WaitForTypeAsync(KexInit)) retrieves it via
        // the stash fast path. Verify: when the callback runs, TryTakeStashed(20)
        // returns true with the stashed packet.
        byte[] kexPayload = [20, 0xAA, 0xBB, 0xCC];
        bool stashPresentAtCallback = false;
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, kexPayload));
        q.InitialKex = false;
        q.RekeyTriggerAsync = ct =>
        {
            stashPresentAtCallback = q.TryTakeStashed(PacketType.KexInit, out RawPacket p);
            if (stashPresentAtCallback)
            {
                Assert.Equal(kexPayload, p.Payload);
            }

            return Task.CompletedTask;
        };

        // Drive the queue. The callback fires; the subsequent read throws
        // SocketDisconnect (pipe empty).
        await Assert.ThrowsAsync<SshException>(async () =>
            await q.WaitForTypeAsync(PacketType.ServiceAccept, CancellationToken.None));
        Assert.True(stashPresentAtCallback, "KEXINIT must be stashed before the callback runs");
    }

    [Fact]
    public async Task InitialKex_KexInit_DoesNotInvokeCallback()
    {
        // During the initial KEX (InitialKex=true), the server KEXINIT is the
        // normal initial exchange — NOT a rekey. The queue must NOT invoke the
        // callback; the caller (HandshakeAsync) retrieves the KEXINIT via
        // WaitForTypeAsync(KexInit) directly.
        int calls = 0;
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, [20]));
        q.InitialKex = true;   // (default, but explicit for clarity)
        q.RekeyTriggerAsync = ct =>
        {
            calls++;
            return Task.CompletedTask;
        };

        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, got.Type);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task NoCallbackWired_KexInit_FallsThroughToStash()
    {
        // If the callback is null (e.g. test-only queue without SshSession wiring),
        // a post-handshake KEXINIT falls through to the caller's stash path — the
        // caller is responsible for retrieving it later. This matches libssh2's
        // behavior when no session-level rekey handler is installed.
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, [20]));
        q.InitialKex = false;
        q.RekeyTriggerAsync = null;

        // WaitForTypeAsync(20) returns the KEXINIT directly (it's the expected type).
        RawPacket got = await q.WaitForTypeAsync(PacketType.KexInit, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.KexInit, got.Type);
    }

    [Fact]
    public async Task NoCallbackWired_NonMatchingKexInit_StashedForLaterWaiter()
    {
        // When no callback is wired and the caller waits for a non-KexInit type,
        // the KEXINIT should be stashed (not consumed) so a later
        // WaitForTypeAsync(KexInit) can retrieve it.
        PacketQueue q = BuildQueueWith([
            .. BuildCleartextPacket(PacketType.KexInit, [20]),
            .. BuildCleartextPacket(PacketType.NewKeys, [21]),
        ]);
        q.InitialKex = false;
        q.RekeyTriggerAsync = null;

        // Wait for NEWKEYS — the KEXINIT is stashed (not consumed).
        RawPacket nk = await q.WaitForTypeAsync(PacketType.NewKeys, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys, nk.Type);

        // Now wait for KEXINIT — should come from the stash.
        Assert.True(q.TryTakeStashed(PacketType.KexInit, out RawPacket kex));
        Assert.Equal(PacketType.KexInit, kex.Type);
    }

    [Fact]
    public async Task CallbackException_PropagatesToWaiterCaller()
    {
        // An exception from the rekey callback must propagate up through
        // WaitForTypeAsync to the channel-op caller.
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, [20]));
        q.InitialKex = false;
        q.RekeyTriggerAsync = ct => throw new SshException(SshErrorCode.KeyExchangeFailure, "test");

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await q.WaitForTypeAsync(PacketType.ServiceAccept, CancellationToken.None));
        Assert.Equal(SshErrorCode.KeyExchangeFailure, ex.ErrorCode);
        Assert.Contains("test", ex.Message);
    }

    [Fact]
    public async Task CallbackReceivesCallingCancellationToken()
    {
        // The callback's CT must be the same CT the caller passed to
        // WaitForTypeAsync — the channel op's CT propagates through.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        CancellationToken seen = default;
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, [20]));
        q.InitialKex = false;
        q.RekeyTriggerAsync = ct =>
        {
            seen = ct;
            return Task.CompletedTask;
        };

        await Assert.ThrowsAsync<SshException>(async () =>
            await q.WaitForTypeAsync(PacketType.ServiceAccept, cts.Token));
        Assert.Equal(cts.Token, seen);
    }

    [Fact]
    public async Task Disconnect_StillThrows_AfterAsyncConversion()
    {
        // Regression: DISCONNECT must still throw after TryHandleInline →
        // TryHandleInlineAsync conversion.
        byte[] discPayload = new byte[1 + 4 + 4];
        discPayload[0] = PacketType.Disconnect;
        BinaryPrimitives.WriteUInt32BigEndian(discPayload.AsSpan(1, 4), 11);  // reason
        BinaryPrimitives.WriteUInt32BigEndian(discPayload.AsSpan(5, 4), 0);   // empty desc
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.Disconnect, discPayload));

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await q.WaitForTypeAsync(PacketType.ServiceAccept, TestContext.Current.CancellationToken));
        Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
    }

    [Fact]
    public async Task IgnoreAndDebug_StillDiscarded_AfterAsyncConversion()
    {
        // Regression: IGNORE (2) and DEBUG (4) must still be silently discarded.
        PacketQueue q = BuildQueueWith([
            .. BuildCleartextPacket(PacketType.Ignore, [2, 0xAA]),
            .. BuildCleartextPacket(PacketType.Debug, [4, 0, 0, 0, 0]),
            .. BuildCleartextPacket(PacketType.NewKeys, [21]),
        ]);

        // Wait for NEWKEYS — IGNORE and DEBUG are both inline-discarded.
        RawPacket got = await q.WaitForTypeAsync(PacketType.NewKeys, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys, got.Type);
    }

    [Fact]
    public async Task ExtInfo_StillStashed_AfterAsyncConversion()
    {
        // Regression: EXT_INFO (7) must still be stashed (not discarded) for
        // later retrieval by SshSession.
        byte[] extPayload = [7, 0, 0, 0, 0];   // minimal empty-ext-list
        PacketQueue q = BuildQueueWith([
            .. BuildCleartextPacket(PacketType.ExtInfo, extPayload),
            .. BuildCleartextPacket(PacketType.NewKeys, [21]),
        ]);

        RawPacket nk = await q.WaitForTypeAsync(PacketType.NewKeys, TestContext.Current.CancellationToken);
        Assert.Equal(PacketType.NewKeys, nk.Type);

        Assert.True(q.TryTakeStashed(PacketType.ExtInfo, out RawPacket ext));
        Assert.Equal(extPayload, ext.Payload);
    }

    [Fact]
    public async Task WaitForTypesAsync_AlsoInvokesRekeyCallback()
    {
        // The ChannelRouter uses WaitForTypesAsync (not WaitForTypeAsync); the
        // rekey callback must fire from both paths.
        int calls = 0;
        PacketQueue q = BuildQueueWith(BuildCleartextPacket(PacketType.KexInit, [20]));
        q.InitialKex = false;
        q.RekeyTriggerAsync = ct =>
        {
            calls++;
            return Task.CompletedTask;
        };

        await Assert.ThrowsAsync<SshException>(async () =>
            await q.WaitForTypesAsync([PacketType.ChannelSuccess, PacketType.ChannelFailure], CancellationToken.None));
        Assert.Equal(1, calls);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static PacketQueue BuildQueueWith(byte[] data)
    {
        var pipe = new Pipe();
        pipe.Writer.WriteAsync(data, TestContext.Current.CancellationToken).AsTask().Wait();
        pipe.Writer.Complete();
        var reader = new PacketReader(pipe.Reader);
        return new PacketQueue(reader);
    }

    private static byte[] BuildCleartextPacket(int type, byte[] payload)
    {
        if (payload.Length == 0 || payload[0] != type)
        {
            byte[] withType = new byte[payload.Length + 1];
            withType[0] = (byte)type;
            Buffer.BlockCopy(payload, 0, withType, 1, payload.Length);
            payload = withType;
        }

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
