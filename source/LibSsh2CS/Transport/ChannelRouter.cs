using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;

using LibSsh2CS.Util;

namespace LibSsh2CS.Transport;

/// <summary>
/// The channel packet demultiplexer — a managed port of the channel-routing
/// portion of libssh2's <c>_libssh2_packet_add</c> (<c>packet.c:952-1328</c>).
/// Sits between the single-reader <see cref="PacketQueue"/> and the session's
/// open <see cref="SshChannel"/> instances, routing each inbound channel-type
/// packet to the channel whose <see cref="SshChannel.LocalId"/> matches the
/// packet's recipient-channel field.
/// </summary>
/// <remarks>
/// <para>
/// <b>The single-reader problem.</b> The underlying <see cref="PacketQueue"/>
/// reads one transport stream shared by every channel. When any channel calls
/// <see cref="WaitAsync"/> to await its reply (or pump for data), packets for
/// OTHER channels may arrive and must be routed to their buffers rather than
/// stashed. This class is that routing layer: <see cref="WaitAsync"/> pulls
/// packets, routes the channel-async types (93–98), and returns only the reply
/// types the caller asked for.
/// </para>
/// <para>
/// <b>Cooperative pumper model.</b> A cooperative pumper serializes reads
/// from the underlying <see cref="System.IO.Pipelines.PipeReader"/> and allows
/// concurrent <c>await</c>s across channels on the same session while
/// preserving the codebase "no background pump" rule:
/// <list type="bullet">
/// <item>Exactly one task at a time is the <b>active pumper</b>, owning the
/// read+route critical section via <see cref="_pumpLock"/>.</item>
/// <item>All other channel ops that need to wait for state register a
/// <see cref="TaskCompletionSource{TResult}"/> keyed by
/// <see cref="SshChannel.LocalId"/> in <see cref="_signals"/> and
/// <c>await</c> it.</item>
/// <item>When the active pumper routes a packet to a waiting channel, it sets
/// that channel's signal via <see cref="SignalChannel"/>.</item>
/// <item>A channel that wants to pump but can't acquire the lock registers its
/// signal and awaits; a channel that <i>can</i> acquire the lock becomes the
/// pumper.</item>
/// </list>
/// Writes (<see cref="PacketWriter.WritePacketAsync"/>) do <b>not</b> need the
/// pump lock — they go out independently. This is what avoids the deadlock:
/// channel A can be blocked reading while channel B writes successfully,
/// prompting the server to send A's data.
/// </para>
/// <para>
/// <b>Per-channel reply slot.</b> Reply packets (91/92/99/100) carry the
/// recipient channel id at offset 1. The cooperative pumper stashes them in
/// <see cref="_pendingReplies"/> keyed by recipient id and signals the channel,
/// which then retrieves the reply via <see cref="TryTakePendingReply"/>. This
/// fixes a latent bug in the legacy type-only stash where channel A's exec
/// reply could be consumed by channel B's exec wait if both were concurrently
/// pending.
/// </para>
/// <para>
/// <b>Legacy entry points.</b> <see cref="WaitAsync(int[], CancellationToken)"/>
/// and <see cref="PumpOnceAsync(CancellationToken)"/> also acquire the pump lock.
/// Channel operations use <see cref="WaitForStateChangeAsync"/>
/// and <see cref="WaitForReplyAsync"/> for cooperative waiting.
/// </para>
/// <para>
/// <b>Routing table (packet.c:952–1328).</b>
/// <list type="bullet">
/// <item><c>CHANNEL_DATA</c> (94) / <c>CHANNEL_EXTENDED_DATA</c> (95): enforce
/// packet-size + window truncation, reset <c>remote.eof</c>, append to the
/// target channel's stdout/stderr buffer (<c>packet.c:964-1082</c>).</item>
/// <item><c>CHANNEL_WINDOW_ADJUST</c> (93): add the increment to the target
/// channel's outbound window (<c>packet.c:1306-1325</c>).</item>
/// <item><c>CHANNEL_EOF</c> (96): set the target channel's
/// <c>remote.eof</c> (<c>packet.c:1089-1107</c>).</item>
/// <item><c>CHANNEL_CLOSE</c> (97): set <c>remote.close</c> + <c>remote.eof</c>
/// (<c>packet.c:1216-1237</c>).</item>
/// <item><c>CHANNEL_REQUEST</c> (98): parse <c>exit-status</c> /
/// <c>exit-signal</c> into channel state; reply <c>CHANNEL_FAILURE</c> for any
/// request with <c>want_reply=TRUE</c> (<c>packet.c:1117-1209</c>).</item>
/// <item><c>CHANNEL_OPEN_CONFIRMATION</c> (91), <c>CHANNEL_OPEN_FAILURE</c>
/// (92), <c>CHANNEL_SUCCESS</c> (99), <c>CHANNEL_FAILURE</c> (100): NOT routed
/// — returned to the caller of <see cref="WaitAsync"/> as replies.</item>
/// </list>
/// Packets whose recipient channel is not registered are silently dropped
/// (parity <c>packet.c:973-978</c> for DATA, <c>1094-1096</c> for EOF,
/// <c>1221-1226</c> for CLOSE, <c>1314</c> for WINDOW_ADJUST).
/// </para>
/// <para>
/// <b>Queue ownership.</b> Once channels exist, this router is the SOLE reader
/// of <see cref="PacketQueue"/>. <c>UserAuth</c> finished before any channel
/// opens; <c>RekeyAsync</c> must not run concurrently with channel ops
/// (single-consumer contract).
/// </para>
/// </remarks>
internal sealed class ChannelRouter : IDisposable
{
    /// <summary>
    /// The channel-async packet types the router always routes (rather than
    /// returning to the caller). These correspond to the
    /// <c>SSH_MSG_CHANNEL_*</c> messages that are dispatched by recipient
    /// channel id in <c>_libssh2_packet_add</c>.
    /// </summary>
    private static readonly int[] s_channelAsyncTypes =
    {
        PacketType.ChannelWindowAdjust,    // 93
        PacketType.ChannelData,            // 94
        PacketType.ChannelExtendedData,    // 95
        PacketType.ChannelEof,             // 96
        PacketType.ChannelClose,           // 97
        PacketType.ChannelRequest,         // 98
    };

    private readonly PacketQueue _queue;
    private readonly PacketWriter _writer;

    // ── Rekey auto-trigger ──────────────────────────────
    // The threshold policy (set by SshSession after handshake) + a rekey
    // callback. Consulted at the top of WaitAsync/PumpOnceAsync before each
    // packet read; if any per-direction counter (inbound OR outbound, bytes
    // OR packets) OR the elapsed-since-handshake time exceeds the policy, the
    // callback fires. SshSession wires this to SshSession.RekeyAsync; null
    // (pre-handshake) disables the auto-trigger.
    private RekeyPolicy? _rekeyPolicy;
    private Func<CancellationToken, Task>? _rekeyAsyncCallback;

    // ── Global-request state ──────────────────────────────
    //
    // Single-slot plumbing for outbound SSH_MSG_GLOBAL_REQUESTs that have
    // want_reply=TRUE (keepalive with replies, tcpip-forward listen setup,
    // cancel-tcpip-forward, hostkeys-prove-001, etc.). The cooperative pumper
    // completes _globalReplyTcs when it routes an inbound REQUEST_SUCCESS (81)
    // or REQUEST_FAILURE (82). The single-slot semaphore serializes concurrent
    // SendGlobalRequestAsync callers — at most one outstanding want_reply=TRUE
    // request per session at a time. (libssh2 itself has no such restriction
    // in principle, but in practice only one fires at a time; the single-slot
    // model keeps the dispatch path trivial.)
    //
    // Inbound SSH_MSG_GLOBAL_REQUEST (80) from the server is auto-failed with
    // a REQUEST_FAILURE reply (libssh2 parity — the C library does not handle
    // any inbound global request types itself).
    private readonly SemaphoreSlim _globalReplyLock = new(1, 1);
    private TaskCompletionSource<RawPacket>? _globalReplyTcs;

    /// <summary>Registered channels keyed by <see cref="SshChannel.LocalId"/>.</summary>
    private readonly Dictionary<uint, SshChannel> _byLocalId = [];

    /// <summary>
    /// The next local channel id to assign. Sequential from 0, parity with
    /// <c>_libssh2_channel_nextid</c> (<c>channel.c:64-89</c>).
    /// </summary>
    private uint _nextLocalId;

    // ── Cooperative pumper state ────────────────────────
    //
    // The cooperative-pumper machinery: one task at a time is the "active
    // pumper" (holds _pumpLock), other channel ops register a TCS keyed by
    // LocalId and await it. When the pumper routes a packet to a waiting
    // channel, it sets that channel's signal.
    //
    // The contract is "edge-triggered": a signal means "something happened for
    // this channel; re-check your own state". Channels consume the signal and
    // re-check their own buffers/flags after WaitForStateChangeAsync returns.

    /// <summary>
    /// Serializes the active-pumper critical section. Held by exactly one task
    /// at a time while it reads+routes a packet. Other channel ops either
    /// register a TCS in <see cref="_signals"/> and await, or queue at this
    /// semaphore to become the next pumper.
    /// </summary>
    private readonly SemaphoreSlim _pumpLock = new(1, 1);

    /// <summary>
    /// Per-channel "state-changed" signal registry, keyed by
    /// <see cref="SshChannel.LocalId"/>. Each entry is a set of
    /// <see cref="TaskCompletionSource{TResult}"/>s for the tasks currently
    /// awaiting state change on that channel. Multiple waiters per channel are
    /// supported so that the same channel can have, e.g., a <c>ReadAsync</c>
    /// and a <c>WriteAsync</c> outstanding simultaneously (full-duplex).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Multi-waiter design.</b> The original
    /// design used one TCS per channel, which races when the same channel has
    /// a read and a write both parked in <see cref="WaitForStateChangeAsync"/>:
    /// a single <see cref="SignalChannel"/> call can wake only one of them.
    /// The second iteration used a <see cref="ConcurrentQueue{T}"/> per
    /// channel with a drain-and-rebuild removal — but a signal firing during
    /// another waiter's rebuild window could enumerate an empty/partial queue
    /// and silently lose the wake-up for a parked waiter (permanent hang,
    /// caught by the stress tests). The registry is therefore a plain
    /// <see cref="List{T}"/> guarded by a per-channel lock (waiters per
    /// channel are 1–2, so the critical sections are a few instructions):
    /// registration, removal, and signaling are each atomic with respect to
    /// one another, so no signal can be lost to registry mutation.
    /// </para>
    /// <para>
    /// Empty lists are intentionally left in the dictionary (removing them
    /// would race a concurrent <c>GetOrAdd</c> re-attach and re-introduce the
    /// lost-signal window); the growth is bounded by the number of distinct
    /// channel ids and dies with the router.
    /// </para>
    /// </remarks>
    private readonly ConcurrentDictionary<uint, List<TaskCompletionSource<bool>>> _signals = new();

    /// <summary>
    /// Per-channel pending-reply slot, keyed by recipient channel id. The
    /// active pumper stores reply packets (91/92/99/100) here and signals the
    /// channel; <see cref="WaitForReplyAsync"/> consumes them via
    /// <see cref="TryTakePendingReply"/>. Replaces the legacy type-only
    /// stash for reply packets (which conflated replies for different channels).
    /// </summary>
    private readonly ConcurrentDictionary<uint, RawPacket> _pendingReplies = new();

    /// <summary>
    /// The full set of packet types the cooperative pumper routes: channel-async
    /// types (93–98) plus reply types (91, 92, 99, 100) plus the
    /// global-request trio (80, 81, 82) plus inbound
    /// <c>SSH_MSG_CHANNEL_OPEN</c> (90). Used as the type-filter for
    /// <see cref="PacketQueue.WaitForTypesAsync"/> from the cooperative entry
    /// points. The queue stashes any non-matching packet for a legacy waiter.
    /// </summary>
    private static readonly int[] s_routableTypes =
    {
        PacketType.GlobalRequest,               // 80 (inbound from server)
        PacketType.RequestSuccess,              // 81 (reply to outbound GLOBAL_REQUEST)
        PacketType.RequestFailure,              // 82 (reply to outbound GLOBAL_REQUEST)
        PacketType.ChannelOpen,                 // 90 (server-initiated open)
        PacketType.ChannelOpenConfirmation,     // 91
        PacketType.ChannelOpenFailure,          // 92
        PacketType.ChannelWindowAdjust,         // 93
        PacketType.ChannelData,                 // 94
        PacketType.ChannelExtendedData,         // 95
        PacketType.ChannelEof,                  // 96
        PacketType.ChannelClose,                // 97
        PacketType.ChannelRequest,              // 98
        PacketType.ChannelSuccess,              // 99
        PacketType.ChannelFailure,              // 100
    };

    /// <summary>
    /// Constructs a router over the given inbound queue. The
    /// <paramref name="writer"/> is used to send <c>CHANNEL_FAILURE</c> replies
    /// for inbound <c>CHANNEL_REQUEST</c>s with <c>want_reply=TRUE</c>
    /// (<c>packet.c:1196-1205</c>).
    /// </summary>
    public ChannelRouter(PacketQueue queue, PacketWriter writer)
    {
        _queue = queue;
        _writer = writer;
    }

    /// <summary>
    /// Wires the rekey auto-trigger. Called by
    /// <see cref="SshSession.HandshakeAsync(IDuplexPipe, HostKeyVerificationCallback, CancellationToken)"/> after handshake completion.
    /// The router consults <paramref name="policy"/> + the per-direction
    /// counters on <see cref="PacketWriter"/>/<see cref="PacketQueue.Reader"/>
    /// before each pump; if exceeded, invokes <paramref name="rekeyAsyncCallback"/>.
    /// </summary>
    /// <param name="policy">Threshold policy (OpenSSH defaults via
    /// <see cref="RekeyPolicy.Default"/>; <see cref="RekeyPolicy.Never"/> disables).</param>
    /// <param name="rekeyAsyncCallback">A callback that drives
    /// <see cref="SshSession.RekeyAsync"/>. Inherits the calling channel op's
    /// <see cref="CancellationToken"/>.</param>
    public void ConfigureRekeyTrigger(RekeyPolicy policy, Func<CancellationToken, Task> rekeyAsyncCallback)
    {
        _rekeyPolicy = policy;
        _rekeyAsyncCallback = rekeyAsyncCallback;
    }

    // ── Listener lookup seam ───────────────────────────────
    //
    // Set by SshSession after handshake. The router calls this when an
    // inbound SSH_MSG_CHANNEL_OPEN "forwarded-tcpip" arrives (packet.c:65-264)
    // to find the listener that owns the (host, port) the server is forwarding
    // for. Returns null if no listener matches → router sends
    // CHANNEL_OPEN_FAILURE with SSH_OPEN_ADMINISTRATIVELY_PROHIBITED.
    private Func<string, int, SshListener?>? _tryGetListenerCallback;

    /// <summary>
    /// Wires the listener-lookup callback. Called by
    /// <see cref="SshSession.HandshakeAsync(IDuplexPipe, HostKeyVerificationCallback, CancellationToken)"/> (and by tests).
    /// </summary>
    internal void ConfigureListenerLookup(Func<string, int, SshListener?> lookup)
    {
        _tryGetListenerCallback = lookup;
    }

    // ── Global-request send/reply ──────────────────────────

    /// <summary>
    /// Sends an <c>SSH_MSG_GLOBAL_REQUEST</c> (80) and, when
    /// <paramref name="wantReply"/> is <see langword="true"/>, awaits the
    /// peer's <c>REQUEST_SUCCESS</c> (81) or <c>REQUEST_FAILURE</c> (82).
    /// Single-slot serialized: at most one outstanding <c>wantReply=true</c>
    /// global request per session at a time. Used by listener setup
    /// (<c>tcpip-forward</c>), and listener teardown
    /// (<c>cancel-tcpip-forward</c>).
    /// </summary>
    /// <param name="name">The ASCII request name (e.g. <c>"keepalive@libssh2.org"</c>,
    /// <c>"tcpip-forward"</c>, <c>"cancel-tcpip-forward"</c>).</param>
    /// <param name="extra">Type-specific request data appended after the
    /// standard <c>[80][string name][byte want_reply]</c> header. Pass empty
    /// for keepalive and other name-only requests.</param>
    /// <param name="wantReply"><see langword="true"/> to set want_reply=1 and
    /// await the reply; <see langword="false"/> to set want_reply=0 and return
    /// immediately after the send (fire-and-forget).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>When <paramref name="wantReply"/> is <see langword="true"/>:
    /// the inbound reply packet (type 81 for success, type 82 for failure).
    /// When <paramref name="wantReply"/> is <see langword="false"/>: a default
    /// <see cref="RawPacket"/> (the caller ignores it).</returns>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.RequestDenied"/> when the server returns
    /// <c>REQUEST_FAILURE</c> (82). Transport errors from the underlying
    /// <see cref="PacketWriter"/> propagate as-is.</exception>
    internal async Task<RawPacket> SendGlobalRequestAsync(
        string name, ReadOnlyMemory<byte> extra, bool wantReply, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        // Serialize want_reply=TRUE requests so the single-slot TCS dispatch
        // path is unambiguous. want_reply=FALSE requests need not hold the
        // lock across the wait (there is no wait) but holding it across the
        // send avoids interleaving replies with later want_reply=TRUE sends.
        await _globalReplyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] payload = GlobalRequest.BuildPayload(name, extra, wantReply);
            await _writer.WritePacketAsync(PacketType.GlobalRequest, payload, cancellationToken)
                .ConfigureAwait(false);

            if (!wantReply)
            {
                return default;
            }

            // Register a fresh single-slot TCS so the next inbound 81/82
            // (routed by RouteRoutableAsync) completes it. Drive the
            // cooperative pump in a loop until our TCS completes — mirrors the
            // pattern in WaitForReplyAsync but for session-scoped replies
            // (81/82 carry no recipient channel id).
            var tcs = new TaskCompletionSource<RawPacket>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _globalReplyTcs = tcs;

            try
            {
                while (true)
                {
                    // Fast path: TCS already completed (a previous pump cycle
                    // routed our reply). Bail out.
                    if (tcs.Task.IsCompleted)
                    {
                        break;
                    }

                    // Try to become the active pumper (non-blocking — if
                    // another channel op already holds the pump lock, fall
                    // through to await our TCS; they will route the reply).
                    if (await _pumpLock.WaitAsync(0, cancellationToken).ConfigureAwait(false))
                    {
                        try
                        {
                            await PumpOneBatchAsync(s_routableTypes, cancellationToken)
                                .ConfigureAwait(false);
                        }
                        finally
                        {
                            _pumpLock.Release();
                            SignalAllWaiters();
                        }

                        // Loop back: re-check TCS — RouteRoutableAsync may
                        // have completed it during the pump cycle.
                        continue;
                    }

                    // Another task is the pumper. Await our TCS — its
                    // RouteRoutableAsync will complete it when 81/82 arrives.
                    // Cancellation: cancel the TCS so the pump sees a cleared
                    // slot and doesn't deliver a stale reply to the next caller.
                    // Only register when the token can actually fire; the
                    // default/non-cancellable case skips the closure and
                    // registration allocation entirely.
                    using CancellationTokenRegistration registration = cancellationToken.CanBeCanceled
                        ? cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken))
                        : default;
                    await tcs.Task.ConfigureAwait(false);
                    // Loop back: TCS is now completed; the top-of-loop check
                    // breaks out cleanly.
                }

                RawPacket reply = await tcs.Task.ConfigureAwait(false);

                // 82 → RequestDenied. 81 → success (return the packet body so
                // callers can parse type-specific data like the bound port).
                if (reply.Type == PacketType.RequestFailure)
                {
                    throw new SshException(SshErrorCode.RequestDenied,
                        $"Global request '{name}' denied by the server.");
                }

                return reply;
            }
            finally
            {
                // Clear the slot so a late reply (after our own cancellation
                // or timeout) doesn't leak into the next caller. The pump's
                // TrySetResult is a no-op on a cleared reference.
                _globalReplyTcs = null;
            }
        }
        finally
        {
            _globalReplyLock.Release();
        }
    }

    /// <summary>
    /// Sends a bare <c>SSH_MSG_REQUEST_FAILURE</c> (82) to the peer. Used to
    /// auto-fail inbound <c>SSH_MSG_GLOBAL_REQUEST</c> (80) messages from the
    /// server (libssh2 parity — the C library does not handle any inbound
    /// global-request types). Runs inside the cooperative pump critical
    /// section; the write uses the writer's own lock so no deadlock.
    /// </summary>
    private async Task SendRequestFailureAsync(CancellationToken cancellationToken)
    {
        byte[] payload = new byte[1];
        payload[0] = (byte)PacketType.RequestFailure;
        await _writer.WritePacketAsync(PacketType.RequestFailure, payload, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Handles an inbound <c>SSH_MSG_CHANNEL_OPEN</c> (90) from
    /// the server. 1:1 port of <c>packet_queue_listener</c>
    /// (<c>packet.c:65-264</c>). Dispatch:
    /// <list type="bullet">
    /// <item><b>"forwarded-tcpip"</b>: parse the connected (host, port) +
    /// originator (host, port); look up the listener by (connected host, port);
    /// allocate a new <see cref="SshChannel"/>; send
    /// <c>CHANNEL_OPEN_CONFIRMATION</c>; register + enqueue on the listener.</item>
    /// <item><b>Any other channel type</b>: send <c>CHANNEL_OPEN_FAILURE</c>
    /// with <c>SSH_OPEN_UNKNOWN_CHANNEL_TYPE</c> (libssh2 parity — only
    /// forwarded-tcpip is supported inbound).</item>
    /// <item><b>No matching listener</b>: send <c>CHANNEL_OPEN_FAILURE</c>
    /// with <c>SSH_OPEN_ADMINISTRATIVELY_PROHIBITED</c>.</item>
    /// <item><b>Listener queue full</b>: send <c>CHANNEL_OPEN_FAILURE</c>
    /// with <c>SSH_OPEN_RESOURCE_SHORTAGE</c>.</item>
    /// </list>
    /// All work runs under the pump lock; the writer call uses its own lock
    /// so no deadlock.
    /// </summary>
    private async Task HandleInboundChannelOpenAsync(RawPacket pkt, CancellationToken cancellationToken)
    {
        // Parse the standard CHANNEL_OPEN header: [90][string type][u32 sender][u32 window][u32 packet][type-specific]
        var r = new PacketWireReader(new ReadOnlySequence<byte>(pkt.Payload));
        _ = r.ReadByte();                 // type (90)
        string channelType;
        uint senderChannel = 0;
        try
        {
            channelType = r.ReadString();
            // packet.c:95 — sender_channel is parsed immediately after the
            // channel type, before any type-specific dispatch. This way the
            // failure paths (unknown type / no listener) can echo it back in
            // CHANNEL_OPEN_FAILURE.
            if (r.TryReadUInt32BigEndian(out uint sc))
            {
                senderChannel = sc;
            }
        }
        catch (SshException)
        {
            // Truncated packet — refuse without further parsing.
            await SendChannelOpenFailureAsync(0, ChannelConstants.OpenUnknownChannelType,
                "truncated CHANNEL_OPEN", cancellationToken).ConfigureAwait(false);
            return;
        }

        if (channelType != "forwarded-tcpip")
        {
            // packet.c:251-257 — unknown channel type from the client side's
            // perspective; the only inbound open types we support are
            // forwarded-tcpip (TCP forwarding) and forwarded-streamlocal
            // (UNIX socket, OpenSSH extension, deferred).
            await SendChannelOpenFailureAsync(senderChannel, ChannelConstants.OpenUnknownChannelType,
                $"unsupported inbound channel type '{channelType}'", cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        uint initialWindowSize;
        uint maxPacketSize;
        string connectedHost;
        uint connectedPort;
        string originatorHost;
        uint originatorPort;

        try
        {
            initialWindowSize = r.ReadUInt32BigEndian();
            maxPacketSize = r.ReadUInt32BigEndian();
            connectedHost = r.ReadString();
            connectedPort = r.ReadUInt32BigEndian();
            originatorHost = r.ReadString();
            originatorPort = r.ReadUInt32BigEndian();
        }
        catch (SshException)
        {
            await SendChannelOpenFailureAsync(senderChannel, ChannelConstants.OpenUnknownChannelType,
                "truncated forwarded-tcpip body", cancellationToken).ConfigureAwait(false);
            return;
        }

        // packet.c:137-141 — find the matching listener.
        SshListener? listener = _tryGetListenerCallback?.Invoke(connectedHost, (int)connectedPort);
        if (listener is null)
        {
            await SendChannelOpenFailureAsync(senderChannel,
                ChannelConstants.OpenAdministrativelyProhibited,
                "Forward not requested", cancellationToken).ConfigureAwait(false);
            return;
        }

        // packet.c:147-155 — refuse if the queue is at capacity BEFORE
        // allocating the channel or sending any confirmation. The C checks
        // capacity first and answers with SSH_MSG_CHANNEL_OPEN_FAILURE
        // (SSH_OPEN_RESOURCE_SHORTAGE); the channel is only allocated when
        // there is space (packet.c:157-218). Previously the port confirmed
        // first and then disposed the channel inline on overflow — which ran
        // inside the pump critical section and deadlocked the session waiting
        // for a CLOSE reply it could never pump.
        if (!listener.CanAcceptMore())
        {
            // packet.c:147-155 + 251-257: the C answers an over-capacity queue
            // with CHANNEL_OPEN_FAILURE / SSH_OPEN_RESOURCE_SHORTAGE and the
            // FwdNotReq description ("Forward not requested") for every
            // failure code.
            await SendChannelOpenFailureAsync(senderChannel,
                ChannelConstants.OpenResourceShortage,
                "Forward not requested", cancellationToken).ConfigureAwait(false);
            return;
        }

        uint localId = AllocateLocalId();
        var channel = new SshChannel(_writer, this, localId,
            remoteId: senderChannel,
            // Peer-advertised window/packet values used verbatim — 0 stays 0
            // (packet.c:194-199). A 0 initial window is RFC 4254 §5.1-legal:
            // the peer grants capacity via WINDOW_ADJUST and the write path
            // blocks until then. Substituting the 2 MiB/32 KiB defaults
            // previously let WriteAsync send data the peer never granted.
            outboundWindow: initialWindowSize,
            outboundMaxPacket: maxPacketSize,
            inboundWindow: ChannelConstants.WindowDefault,
            inboundMaxPacket: ChannelConstants.PacketDefault);

        // Register BEFORE sending CONFIRMATION so any early channel packet
        // routes correctly (parity with client-side open).
        Register(channel);

        // packet.c:210-216 — CHANNEL_OPEN_CONFIRMATION:
        // [91][u32 recip=peer's sender][u32 sender=our new localId][u32 window][u32 packet]
        byte[] confirmation = SshChannel.BuildChannelOpenConfirmationPayload(
            recipientChannel: senderChannel,
            senderChannel: localId,
            window: ChannelConstants.WindowDefault,
            maxPacket: ChannelConstants.PacketDefault);

        try
        {
            await _writer.WritePacketAsync(PacketType.ChannelOpenConfirmation, confirmation, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SshException)
        {
            // Send failed — unregister and drop. Parity packet.c:226-231.
            Unregister(channel);
            return;
        }

        // packet.c:233-238 — enqueue on the listener. Under the pump-lock
        // serialization the pre-check above is race-free, so this cannot fail;
        // the defensive fallback (no inline dispose — that would deadlock the
        // pump; see above) just unregisters the channel. The peer keeps the
        // confirmed channel for a packet or two, then sees it vanish — an
        // unreachable corner.
        if (!listener.TryEnqueueAccept(channel))
        {
            Unregister(channel);
        }
    }

    /// <summary>
    /// Builds + sends a <c>SSH_MSG_CHANNEL_OPEN_FAILURE</c> payload via the
    /// <see cref="SshChannel.BuildChannelOpenFailurePayload"/> helper.
    /// </summary>
    private async Task SendChannelOpenFailureAsync(
        uint recipientChannel, int reason, string description, CancellationToken cancellationToken)
    {
        byte[] failure = SshChannel.BuildChannelOpenFailurePayload(
            recipientChannel, reason, description, lang: string.Empty);
        await _writer.WritePacketAsync(PacketType.ChannelOpenFailure, failure, cancellationToken)
            .ConfigureAwait(false);
    }

    // ── Registration / id allocation ───────────────────────────────────────

    /// <summary>
    /// Allocates the next local channel id. Parity with
    /// <c>_libssh2_channel_nextid</c> (<c>channel.c:64-89</c>): sequential from
    /// 0, monotonically increasing.
    /// </summary>
    public uint AllocateLocalId()
    {
        uint id = _nextLocalId;
        _nextLocalId++;
        return id;
    }

    /// <summary>
    /// Registers a channel so the router can route inbound packets to it.
    /// Called by <c>SshChannel.OpenAsync</c> BEFORE the <c>CHANNEL_OPEN</c>
    /// packet is sent (parity <c>channel.c:189</c> <c>_libssh2_list_add</c>), so
    /// any early channel packet routes correctly.
    /// </summary>
    public void Register(SshChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _byLocalId[channel.LocalId] = channel;
    }

    /// <summary>
    /// Unregisters a channel. Called by <c>SshChannel.DisposeAsync</c> after
    /// the close handshake (parity <c>channel.c:2873</c>
    /// <c>_libssh2_list_remove</c>). Subsequent packets for this channel are
    /// silently dropped.
    /// </summary>
    /// <remarks>
    /// Also clears the per-channel cooperative-pumper state (<see cref="_signals"/>,
    /// <see cref="_pendingReplies"/>) so a stale TCS or reply doesn't leak. If
    /// a task is currently awaiting this channel's signal, its TCS is canceled
    /// with <see cref="TaskCanceledException"/> — but in practice Unregister is
    /// called by DisposeAsync AFTER all waits have resolved, so this is a
    /// defensive cleanup.
    /// </remarks>
    public void Unregister(SshChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _byLocalId.Remove(channel.LocalId);

        // Cooperative-pumper cleanup. If the channel has registered
        // waiters, cancel them all so any in-flight await wakes up cleanly.
        // In practice Unregister is called by DisposeAsync AFTER all waits have
        // resolved, so this is a defensive cleanup.
        if (_signals.TryRemove(channel.LocalId, out List<TaskCompletionSource<bool>>? waiters))
        {
            lock (waiters)
            {
                foreach (TaskCompletionSource<bool> tcs in waiters)
                {
                    tcs.TrySetCanceled();
                }
            }
        }

        _pendingReplies.TryRemove(channel.LocalId, out _);
    }

    /// <summary>Looks up a registered channel by its local id.</summary>
    internal bool TryGet(uint localId, out SshChannel? channel)
    {
        return _byLocalId.TryGetValue(localId, out channel);
    }

    // ── Cooperative pumper entry points ─────────────────
    //
    // The concurrency-safe API used by SshChannel. Replaces the legacy
    // WaitAsync(int[], ct) / PumpOnceAsync(ct) for multi-channel safety.

    /// <summary>
    /// Waits until <paramref name="channel"/>'s state changes — data arrives,
    /// the outbound window grows, EOF/CLOSE arrives, exit-status/signal arrives,
    /// or any pending reply arrives. Returns <see langword="true"/> when the
    /// signal fires (state changed); throws <see cref="OperationCanceledException"/>
    /// on cancellation. The caller re-checks its own state after this returns
    /// and loops if not yet ready.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Cooperative pumper (lost-wakeup prevention).</b> The TCS is registered
    /// in <see cref="_signals"/> <b>before</b> attempting to acquire
    /// <see cref="_pumpLock"/>. This closes the lost-wakeup window that existed
    /// in the original design (where the TCS was registered only after
    /// the non-blocking lock attempt failed): a pumper routing a packet to this
    /// channel between the failed lock attempt and the TCS registration would
    /// have its signal lost, deadlocking the waiter.
    /// </para>
    /// <para>
    /// After registering, we attempt the pump-lock non-blockingly. If we
    /// acquire it, we drop our TCS (we're not waiting anymore) and pump one
    /// batch of packets (signaling other channels' waiters). If we can't
    /// acquire it, another task is pumping; we await our TCS, which will be
    /// signaled by that pumper when state for this channel arrives.
    /// </para>
    /// <para>
    /// <b>Edge-triggered.</b> The return value is always <see langword="true"/>
    /// on success; the caller is responsible for checking whether the state
    /// change is the one it was waiting for. Spurious wakeups are possible
    /// (e.g. a reply arriving when the caller is waiting for data) — the caller
    /// just loops back to <see cref="WaitForStateChangeAsync"/>.
    /// </para>
    /// <para>
    /// <b>Async-convention compliant.</b> Has a <see cref="CancellationToken"/>
    /// as the last parameter; uses <see cref="Task.ConfigureAwait(bool)"/> on every await.
    /// </para>
    /// </remarks>
    /// <param name="channel">The channel whose state to wait on. Must be
    /// registered via <see cref="Register"/>.</param>
    /// <param name="canProceed">Optional condition predicate (evaluated under
    /// the channel's own synchronization) describing the caller-specific state
    /// it is waiting for — see remarks.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    internal async Task<bool> WaitForStateChangeAsync(
        SshChannel channel, Func<bool>? canProceed, CancellationToken cancellationToken)
    {
        // Register the TCS FIRST so no signal from an active pumper can be
        // lost. The original design attempted the pump-lock before
        // registering, which opened a window where a packet routed to this
        // channel between the failed lock attempt and registration had its
        // signal fire into an empty slot — the channel's data was buffered but
        // the waiter hung forever.
        TaskCompletionSource<bool> tcs = RegisterWaiter(channel.LocalId);
        try
        {
            // Lost-wakeup rescue 1: the awaited state may have
            // arrived BETWEEN the caller's last condition check and this
            // registration — its signal fired into the then-empty slot and is
            // gone. Re-check the condition now (with the TCS registered, any
            // FUTURE signal is caught); if satisfied, return without blocking.
            // Without this, e.g. a WriteAsync that observed a zero window
            // could park forever on a signal that already fired.
            if (canProceed is not null && canProceed())
            {
                return true;
            }

            // Fast path: become the active pumper without blocking. If we can
            // acquire the pump lock immediately, we route one batch of packets
            // (which may signal other channels' waiters) and return. The caller
            // re-checks its own state after we return.
            if (await _pumpLock.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            {
                // We're pumping — drop our TCS so it doesn't get signaled (and
                // so the next wait from this channel gets a fresh slot).
                RemoveWaiter(channel.LocalId, tcs);
                tcs = null!;   // Sentinel: don't double-remove in finally.

                try
                {
                    // Lost-wakeup rescue 2: the awaited state may
                    // have arrived while we were acquiring the pump lock (the
                    // signaling pumper finished its batch in that gap). If it
                    // did, pumping would park us on an EMPTY pipe while
                    // holding the lock — permanently. Re-check first; a
                    // satisfied condition skips the pump entirely.
                    if (canProceed is null || !canProceed())
                    {
                        await PumpOneBatchAsync(s_routableTypes, cancellationToken).ConfigureAwait(false);
                    }

                    return true;
                }
                finally
                {
                    _pumpLock.Release();
                    // Signal all waiters so one of them takes over as the next
                    // pumper. Essential when we're exiting due to cancellation
                    // — without this, the surviving waiters would strand. In
                    // the hot path the wakeup is spurious for most (no state
                    // change), they re-check and re-await.
                    SignalAllWaiters();
                }
            }

            // Another task holds the pump lock. Await our signal — which was
            // registered BEFORE the lock attempt, so we cannot miss a wakeup.
            // Only register when the token can actually fire; the
            // default/non-cancellable case skips the closure and registration
            // allocation entirely.
            using CancellationTokenRegistration registration = cancellationToken.CanBeCanceled
                ? cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken))
                : default;
            await tcs.Task.ConfigureAwait(false);
            return true;
        }
        finally
        {
            // Defensive cleanup: if we registered a TCS and didn't drop it
            // (because we took the await path and were canceled, or the signal
            // raced with our removal), make sure it's gone so the next wait
            // from this channel gets a fresh slot.
            if (tcs is not null)
            {
                RemoveWaiter(channel.LocalId, tcs);
            }
        }
    }

    /// <summary>
    /// Waits for a reply packet of one of <paramref name="replyTypes"/> for
    /// <paramref name="channel"/>. Returns the matched reply (the recipient-id
    /// field of the reply must equal <paramref name="channel"/>'s LocalId).
    /// Replaces the legacy <see cref="WaitAsync(int[], CancellationToken)"/>
    /// for the cooperative-pumper model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Per-channel reply slot.</b> The active pumper stashes reply packets
    /// (91/92/99/100) in <see cref="_pendingReplies"/> keyed by recipient id
    /// and signals the channel. This method loops: check the slot first, then
    /// either pump or await, then loop.
    /// </para>
    /// <para>
    /// This fixes a latent legacy bug where two channels with concurrent
    /// pending requests could have their replies misrouted (the type-only
    /// stash conflated them).
    /// </para>
    /// <para>
    /// <b>Lost-wakeup prevention.</b> Like <see cref="WaitForStateChangeAsync"/>,
    /// the TCS is registered BEFORE the pump-lock attempt so a pumper routing
    /// our reply between the failed lock attempt and registration cannot lose
    /// its signal. The reply ends up in <see cref="_pendingReplies"/>; the top
    /// of the loop re-checks it after each wake.
    /// </para>
    /// </remarks>
    /// <param name="channel">The channel expecting the reply. The reply's
    /// recipient field must match <paramref name="channel"/>'s LocalId.</param>
    /// <param name="replyTypes">The acceptable reply types
    /// (e.g. <c>[CHANNEL_OPEN_CONFIRMATION, CHANNEL_OPEN_FAILURE]</c>).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The matched reply packet.</returns>
    internal async Task<RawPacket> WaitForReplyAsync(
        SshChannel channel, int[] replyTypes, CancellationToken cancellationToken)
    {
        while (true)
        {
            // Fast path: our reply is already in the slot (the active pumper
            // stashed it before we got here).
            if (_pendingReplies.TryRemove(channel.LocalId, out RawPacket pending))
            {
                if (Array.IndexOf(replyTypes, pending.Type) >= 0)
                {
                    return pending;
                }

                // Not our type — re-stash and fall through to pump. Never
                // OVERWRITE — the active pumper may have stashed our correct
                // reply between the TryRemove above and this re-stash (the
                // fast path runs outside the pump lock); the indexer would
                // clobber it and lose the reply permanently (waiter hangs
                // until ReadTimeout). TryAdd leaves a newer entry in place; we
                // then loop back to the top and consume it.
                if (!_pendingReplies.TryAdd(channel.LocalId, pending))
                {
                    continue;
                }
            }

            // Register the TCS BEFORE attempting the pump lock (lost-wakeup
            // fix — see WaitForStateChangeAsync).
            TaskCompletionSource<bool> tcs = RegisterWaiter(channel.LocalId);
            try
            {
                // Lost-wakeup rescue: the reply may have been
                // stashed between the loop-top slot check and this
                // registration (its signal fired into the then-empty slot).
                // Re-check with a TYPE-MATCHED predicate (a plain
                // "slot non-empty" check would busy-spin on a wrong-type
                // stash); if our reply is there, loop back and consume it.
                if (HasMatchingReply(channel.LocalId, replyTypes))
                {
                    continue;
                }

                // Try to become the active pumper.
                if (await _pumpLock.WaitAsync(0, cancellationToken).ConfigureAwait(false))
                {
                    RemoveWaiter(channel.LocalId, tcs);
                    tcs = null!;

                    try
                    {
                        // Lost-wakeup rescue #2: the reply may have arrived
                        // while we were acquiring the lock — re-check before
                        // pumping (an empty pipe would park us holding it).
                        if (!HasMatchingReply(channel.LocalId, replyTypes))
                        {
                            int[] combined = CombineTypes(replyTypes);
                            await PumpOneBatchAsync(combined, cancellationToken).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        _pumpLock.Release();
                        SignalAllWaiters();
                    }

                    // Loop back: re-check slot — our reply may have been routed
                    // by the pump above. If not, we re-register and either pump
                    // again or await our signal.
                    continue;
                }

                // Someone else is the pumper. Await our signal — which was
                // registered BEFORE the lock attempt, so we cannot miss it.
                // Only register when the token can actually fire; the
                // default/non-cancellable case skips the closure and
                // registration allocation entirely.
                using CancellationTokenRegistration registration = cancellationToken.CanBeCanceled
                    ? cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken))
                    : default;
                await tcs.Task.ConfigureAwait(false);
                // Loop back: re-check slot. The reply should be in the slot now
                // (or close to it — loop again if not).
            }
            finally
            {
                if (tcs is not null)
                {
                    RemoveWaiter(channel.LocalId, tcs);
                }
            }
        }
    }

    /// <summary>
    /// Tries to take a pending reply for <paramref name="localId"/> without
    /// blocking. Used by <see cref="SshChannel.SendChannelRequestAsync"/> to
    /// check for an already-arrived reply before awaiting (rare but possible
    /// after a cooperative signal where another pumper routed our reply).
    /// </summary>
    internal bool TryTakePendingReply(uint localId, out RawPacket reply)
    {
        return _pendingReplies.TryRemove(localId, out reply);
    }

    // ── Cooperative-pumper helpers ────────────────────────────────────────

    /// <summary>
    /// True when <see cref="_pendingReplies"/> holds a reply for
    /// <paramref name="localId"/> whose type is one of
    /// <paramref name="replyTypes"/> — the waiter-side predicate for the
    /// lost-wakeup rescues in <see cref="WaitForReplyAsync"/>. Type-matched so
    /// a stashed wrong-type reply does not satisfy it (which would busy-spin).
    /// </summary>
    private bool HasMatchingReply(uint localId, int[] replyTypes)
    {
        return _pendingReplies.TryGetValue(localId, out RawPacket pending)
            && Array.IndexOf(replyTypes, pending.Type) >= 0;
    }

    /// <summary>
    /// Registers a fresh <see cref="TaskCompletionSource{TResult}"/> for
    /// <paramref name="localId"/> in <see cref="_signals"/>. Multiple waiters
    /// per channel are supported (full-duplex read+write on the same channel).
    /// </summary>
    /// <remarks>
    /// The TCS uses <see cref="TaskCreationOptions.RunContinuationsAsynchronously"/>
    /// so the signaling thread (the active pumper) is not hijacked by the
    /// awaiting channel's continuation.
    /// </remarks>
    private TaskCompletionSource<bool> RegisterWaiter(uint localId)
    {
        var tcs = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        List<TaskCompletionSource<bool>> bag = _signals.GetOrAdd(localId, _ => []);
        lock (bag)
        {
            bag.Add(tcs);
        }

        return tcs;
    }

    /// <summary>
    /// Removes a specific TCS from the channel's waiter set. Used by a waiter
    /// when it takes over as the active pumper (no longer awaiting) or when it
    /// is cleaning up after cancellation. No-op if the TCS has already been
    /// removed (defensive).
    /// </summary>
    /// <remarks>
    /// Removal is a single locked <see cref="List{T}.Remove"/> — no
    /// drain-and-rebuild — so a concurrent <see cref="SignalChannel"/> can
    /// never observe the set without a waiter that is still parked.
    /// </remarks>
    private void RemoveWaiter(uint localId, TaskCompletionSource<bool> tcs)
    {
        if (!_signals.TryGetValue(localId, out List<TaskCompletionSource<bool>>? bag))
        {
            return;
        }

        lock (bag)
        {
            bag.Remove(tcs);
        }
    }

    /// <summary>
    /// Pumps exactly one batch of packets: blocking read + drain all
    /// immediately-available packets. Called by the cooperative entry points
    /// (<see cref="WaitForStateChangeAsync"/> / <see cref="WaitForReplyAsync"/>)
    /// when they acquire <see cref="_pumpLock"/>. Performs the rekey
    /// auto-trigger check first, then reads one packet (filtering by
    /// <paramref name="types"/>), routes it, then drains any additional
    /// immediately-buffered packets so multi-packet batches all get routed in
    /// this pump cycle (preventing non-pumping waiters from starving).
    /// </summary>
    /// <remarks>
    /// Caller MUST hold <see cref="_pumpLock"/>. Inline-handled packets
    /// (DISCONNECT/IGNORE/DEBUG/EXT_INFO/server-KEXINIT) are consumed by the
    /// queue's <see cref="PacketQueue.WaitForTypesAsync"/>; only routable
    /// packets (channel-async + reply types) reach here.
    /// </remarks>
    private async Task PumpOneBatchAsync(int[] types, CancellationToken cancellationToken)
    {
        await MaybeRekeyAsync(cancellationToken).ConfigureAwait(false);

        RawPacket pkt = await _queue.WaitForTypesAsync(types, cancellationToken)
            .ConfigureAwait(false);

        await RouteRoutableAsync(pkt, cancellationToken).ConfigureAwait(false);

        // Drain any additional immediately-available packets before yielding
        // the lock. If multiple packets arrived in one batch (typical for the
        // test harness's FeedInbound, or for back-to-back server writes), this
        // ensures ALL of them get routed in this pump cycle — preventing
        // non-pumping waiters from starving when the active pumper's own state
        // changed on the first packet.
        await DrainAvailablePacketsAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Signals that the channel <paramref name="localId"/> has new state.
    /// Called by the active pumper after routing a packet to the channel.
    /// Wakes ALL tasks awaiting <see cref="WaitForStateChangeAsync"/> or
    /// <see cref="WaitForReplyAsync"/> for this channel (multi-waiter support:
    /// a single channel may have, e.g., a read and a write parked
    /// simultaneously). No-op if no task is waiting (the signal is lost — fine,
    /// the channel's next wait will check its own state and either proceed or
    /// register a fresh TCS).
    /// </summary>
    internal void SignalChannel(uint localId)
    {
        if (_signals.TryGetValue(localId, out List<TaskCompletionSource<bool>>? bag))
        {
            // Snapshot + complete under the bag lock so a concurrent
            // RegisterWaiter/RemoveWaiter can never make this enumeration skip
            // a still-parked waiter (lost signal → permanent hang).
            lock (bag)
            {
                foreach (TaskCompletionSource<bool> tcs in bag)
                {
                    tcs.TrySetResult(true);
                }
            }
        }
    }

    /// <summary>
    /// Routes a routable packet (channel-async, channel-reply, or
    /// global-request) to the right consumer.
    /// <list type="bullet">
    /// <item><b>Global request, inbound from server</b> (80): auto-respond
    /// <c>REQUEST_FAILURE</c> when the request carries <c>want_reply=1</c>
    /// (libssh2 parity — the C library does not handle any inbound global
    /// request types itself, and only replies when wanted, packet.c:917-943).
    /// Sends the failure via
    /// <see cref="_writer"/>; the write uses the writer's own lock so no
    /// deadlock with <see cref="_pumpLock"/>.</item>
    /// <item><b>Global-request reply</b> (81/82): complete the session-level
    /// <see cref="_globalReplyTcs"/> so the outstanding
    /// <see cref="SendGlobalRequestAsync"/> caller wakes. The caller
    /// distinguishes success vs failure by inspecting the returned
    /// <see cref="RawPacket.Type"/>. If no caller is waiting (a late reply to
    /// a previously-canceled/timed-out request, or an unsolicited reply), the
    /// packet is dropped.</item>
    /// <item><b>Channel reply</b> (91/92/99/100): stash in per-channel
    /// <see cref="_pendingReplies"/> slot keyed by recipient id, signal the
    /// channel.</item>
    /// <item><b>Channel-async</b> (93–98): dispatch via <see cref="RouteAsync"/>
    /// which mutates the target channel's state + signals.</item>
    /// </list>
    /// </summary>
    private async Task RouteRoutableAsync(RawPacket pkt, CancellationToken cancellationToken)
    {
        // ── global-request dispatch ────────────────────────────
        if (pkt.Type == PacketType.GlobalRequest)
        {
            // Inbound SSH_MSG_GLOBAL_REQUEST (80) from the server. libssh2
            // does not implement any inbound global-request handlers; it
            // auto-fails everything — but ONLY when the request carries
            // want_reply=TRUE (packet.c:917-943: `if(want_reply) { ... send
            // SSH_MSG_REQUEST_FAILURE ... }`; a want_reply=0 request — e.g.
            // OpenSSH's no-more-sessions — gets NO reply). Examples that
            // arrive in practice: hostkeys-00@openssh.com,
            // no-more-sessions@openssh.com, keepalive-prove-001@openssh.com.
            // Failing these is correct — the server will not retry (RFC 4254
            // §4: want_reply only gates whether the server expects a reply,
            // not whether it retries). Previously the failure was sent
            // unconditionally, emitting an unsolicited REQUEST_FAILURE for
            // want_reply=0 requests.
            //
            // Payload layout (type byte included): [80][u32 name-len][name][u8 want_reply].
            bool wantReply = false;
            if (pkt.Payload.Length >= 5)
            {
                uint nameLen = BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4));
                if (nameLen <= pkt.Payload.Length - 6)
                {
                    wantReply = pkt.Payload[5 + (int)nameLen] != 0;
                }
            }

            if (wantReply)
            {
                await SendRequestFailureAsync(cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        if (pkt.Type is PacketType.RequestSuccess or PacketType.RequestFailure)
        {
            // Outbound GLOBAL_REQUEST reply (81/82). Hand it to the
            // outstanding SendGlobalRequestAsync waiter (if any). No channel
            // id at offset 1 — these are session-scoped replies. TrySetResult
            // is thread-safe; a null TCS means no one is waiting (unsolicited
            // or late reply) and the packet is dropped.
            _globalReplyTcs?.TrySetResult(pkt);
            return;
        }

        if (pkt.Type == PacketType.ChannelOpen)
        {
            // Server-initiated CHANNEL_OPEN (packet.c:65-264).
            // Dispatch to the listener registry; construct + confirm or
            // refuse. Runs under the pump lock (this method's caller holds it).
            await HandleInboundChannelOpenAsync(pkt, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (IsReplyType(pkt.Type))
        {
            // Channel-scoped reply packet (91/92/99/100) — stash in per-channel
            // slot, signal the channel.
            uint recip = ReadRecipientId(pkt);
            _pendingReplies[recip] = pkt;
            SignalChannel(recip);
            return;
        }

        // Channel-async packet — RouteAsync dispatches per type and mutates
        // the target channel's state. RouteAsync also calls SignalChannel
        // after the dispatch.
        await RouteAsync(pkt, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Drains any additional immediately-available packets from the queue and
    /// routes them. Called by <see cref="WaitForStateChangeAsync"/> and
    /// <see cref="WaitForReplyAsync"/> after their first blocking read, while
    /// still holding <see cref="_pumpLock"/>. Prevents non-pumping waiters
    /// from starving when multiple packets arrived in one batch (the active
    /// pumper exits after its own state changes; this drain makes sure all
    /// concurrently-queued packets are routed first).
    /// </summary>
    /// <remarks>
    /// Non-blocking: returns as soon as the queue reports no full packet is
    /// buffered. The next pump cycle (whoever wins the lock next) handles
    /// later arrivals.
    /// </remarks>
    private async Task DrainAvailablePacketsAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            RawPacket pkt = await _queue.TryTakeAvailableAsync(cancellationToken)
                .ConfigureAwait(false);
            if (pkt.Payload is null)
            {
                return;
            }

            await RouteRoutableAsync(pkt, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Signals ALL registered waiters across all channels. Called after the
    /// active pumper releases <see cref="_pumpLock"/>. Each woken channel
    /// re-checks its own state:
    /// <list type="bullet">
    /// <item>If state changed (data buffered / EOF / reply arrived), it
    /// completes its <see cref="WaitForStateChangeAsync"/> or
    /// <see cref="WaitForReplyAsync"/> call normally.</item>
    /// <item>If not, it loops back and tries to become the next pumper.</item>
    /// </list>
    /// This is essential for correctness when the active pumper exits due to
    /// cancellation — without it, cancelled pumpers strand other waiters who
    /// would otherwise take over the pump. The cost is some spurious wakeups
    /// in the hot path (a woken channel that finds no state change re-awaits),
    /// but the alternative is deadlock.
    /// </summary>
    private void SignalAllWaiters()
    {
        // Snapshot the values to avoid mutation-during-enumeration issues
        // (channels may re-await and re-register from their continuation).
        // Each bag is completed under its own lock (see
        // SignalChannel) so a concurrent register/remove cannot make the
        // enumeration skip a still-parked waiter.
        foreach (KeyValuePair<uint, List<TaskCompletionSource<bool>>> entry in _signals)
        {
            lock (entry.Value)
            {
                foreach (TaskCompletionSource<bool> tcs in entry.Value)
                {
                    tcs.TrySetResult(true);
                }
            }
        }
    }

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="type"/> is one of the
    /// per-channel reply types (CHANNEL_OPEN_CONFIRMATION/FAILURE,
    /// CHANNEL_SUCCESS/FAILURE). These carry the recipient channel id at
    /// offset 1 and are routed to <see cref="_pendingReplies"/> rather than
    /// dispatched as channel state mutations.
    /// </summary>
    private static bool IsReplyType(int type)
    {
        return type is PacketType.ChannelOpenConfirmation or PacketType.ChannelOpenFailure
            or PacketType.ChannelSuccess or PacketType.ChannelFailure;
    }

    /// <summary>
    /// Reads the recipient channel id (offset 1, BE32) from a packet payload.
    /// All SSH_MSG_CHANNEL_* messages carry it there (RFC 4254 §5). Returns 0
    /// if the payload is too short (the caller should drop the packet
    /// defensively).
    /// </summary>
    private static uint ReadRecipientId(RawPacket pkt)
    {
        if (pkt.Payload.Length < 5)
        {
            return 0;
        }

        return BinaryPrimitives.ReadUInt32BigEndian(pkt.Payload.AsSpan(1, 4));
    }

    // ── The pump (legacy entry points — now pump-lock-guarded) ──

    /// <summary>
    /// <b>Legacy entry point.</b> Reply-wait: pulls packets, routing every
    /// channel-async packet (types 93–98) to its target channel, until a packet
    /// whose type is in <paramref name="replyTypes"/> arrives — which is then
    /// returned. Used only by legacy tests; production code uses
    /// <see cref="WaitForReplyAsync"/> (filters by recipient id, required for
    /// multi-channel safety).
    /// </summary>
    /// <remarks>
    /// This method acquires <see cref="_pumpLock"/> for
    /// the duration of its read loop, so it is safe to call concurrently with
    /// cooperative entry points without corrupting the single-reader
    /// <c>PipeReader</c>. It still does NOT filter replies by recipient id, so
    /// under contention one caller may consume another's reply — use
    /// <see cref="WaitForReplyAsync"/> for new code. Tests using this method
    /// are single-threaded so this limitation does not affect them.
    /// </remarks>
    /// <param name="replyTypes">The reply types the caller is waiting for (e.g.
    /// <c>[CHANNEL_OPEN_CONFIRMATION, CHANNEL_OPEN_FAILURE]</c> for open,
    /// <c>[CHANNEL_SUCCESS, CHANNEL_FAILURE]</c> for exec). Must be non-empty;
    /// use <see cref="PumpOnceAsync"/> for the no-reply pump used by read/write.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The first packet matching <paramref name="replyTypes"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="replyTypes"/> is empty.</exception>
    public async Task<RawPacket> WaitAsync(int[] replyTypes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replyTypes);
        if (replyTypes.Length == 0)
        {
            throw new ArgumentException("replyTypes must be non-empty; use PumpOnceAsync for pump-once.", nameof(replyTypes));
        }

        // Acquire the pump lock for the duration of the read loop so
        // concurrent calls (legacy or cooperative) cannot interleave reads on
        // the single-reader PipeReader. Test-only callers are single-threaded
        // so the lock is uncontended.
        await _pumpLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Combined filter: the caller's reply types ∪ the always-routed channel
            // types. WaitForTypesAsync returns the first packet matching ANY of
            // these; reply types NOT in the set get stashed by the queue for a
            // later waiter (e.g. a stray OPEN_CONFIRMATION during exec is stashed
            // and retrieved by the next open-wait).
            int[] combined = CombineTypes(replyTypes);

            while (true)
            {
                // ── Rekey auto-trigger ─────────────────────
                // Check thresholds before each pump; if exceeded, invoke the rekey
                // callback (drives SshSession.RekeyAsync). Inherits this op's CT.
                // Rekey runs between packets, preserving the single-consumer contract
                // (rekey doesn't interleave with channel reads).
                await MaybeRekeyAsync(cancellationToken).ConfigureAwait(false);

                RawPacket pkt = await _queue.WaitForTypesAsync(combined, cancellationToken)
                    .ConfigureAwait(false);

                // If the caller asked for this type, hand it back.
                if (Array.IndexOf(replyTypes, pkt.Type) >= 0)
                {
                    return pkt;
                }

                // Otherwise it is a channel-async packet — route it. Routing is
                // async because CHANNEL_REQUEST with want_reply=TRUE must send a
                // CHANNEL_FAILURE reply (packet.c:1196-1205) before the next packet
                // is read, preserving wire ordering.
                await RouteAsync(pkt, cancellationToken).ConfigureAwait(false);

                // Reply-wait mode (open/exec/close): keep pumping until the reply arrives.
            }
        }
        finally
        {
            _pumpLock.Release();
            SignalAllWaiters();
        }
    }

    /// <summary>
    /// <b>Legacy entry point.</b> Pump-once: reads and routes exactly one
    /// channel-async packet (types 93–98), then returns. Used only by legacy
    /// tests; production code uses <see cref="WaitForStateChangeAsync"/>.
    /// </summary>
    /// <remarks>
    /// This method acquires <see cref="_pumpLock"/> so it
    /// is safe to call concurrently with cooperative entry points. Test-only
    /// callers are single-threaded so the lock is uncontended.
    /// </remarks>
    public async Task PumpOnceAsync(CancellationToken cancellationToken)
    {
        // Pump-lock-guarded so concurrent calls (legacy or
        // cooperative) cannot interleave reads on the single-reader PipeReader.
        await _pumpLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // ── Rekey auto-trigger ─────────────────────────
            // Same threshold check as WaitAsync — runs before each pump.
            await MaybeRekeyAsync(cancellationToken).ConfigureAwait(false);

            RawPacket pkt = await _queue.WaitForTypesAsync(s_channelAsyncTypes, cancellationToken)
                .ConfigureAwait(false);

            await RouteAsync(pkt, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _pumpLock.Release();
            SignalAllWaiters();
        }
    }

    /// <summary>
    /// Test seam — drives one full cooperative-pump cycle over the
    /// routable type set (including 80/81/82/90). Used by tests that need to
    /// route an inbound SSH_MSG_CHANNEL_OPEN without coupling to a
    /// side-effect-producing wantReply=true global request.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    internal async Task PumpOneBatchForTestAsync(CancellationToken cancellationToken)
    {
        await _pumpLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await PumpOneBatchAsync(s_routableTypes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _pumpLock.Release();
            SignalAllWaiters();
        }
    }

    // ── Rekey auto-trigger helper ──────────────────────

    /// <summary>
    /// Checks the per-direction rekey thresholds (RFC 4253 §9 limits) and the
    /// time-since-last-NEWKEYS interval against the configured
    /// <see cref="RekeyPolicy"/>. If ANY threshold is exceeded, invokes the
    /// rekey callback (which drives <see cref="SshSession.RekeyAsync"/>). Called
    /// at the top of <see cref="WaitAsync"/> and <see cref="PumpOnceAsync"/>
    /// before each packet read.
    /// </summary>
    /// <remarks>
    /// <b>Per-direction max.</b> The trigger fires when EITHER direction's
    /// counter exceeds its threshold (inbound OR outbound, bytes OR packets).
    /// RFC 4253 §9 limits the per-key sequence space; either side hitting the
    /// limit is sufficient reason to rekey.
    /// <para>
    /// <b>No-op without config.</b> If <see cref="ConfigureRekeyTrigger"/> was
    /// not called (pre-handshake, or <see cref="RekeyPolicy.Never"/>), the
    /// check short-circuits. The counters and time source are read directly
    /// from the router's <see cref="PacketWriter"/> + <see cref="PacketQueue.Reader"/>
    /// + <see cref="TimeProvider"/> (the latter via the
    /// <see cref="SshSession.ElapsedSinceHandshake"/> property exposed by the
    /// session that wired the trigger).
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">Inherits the calling channel op's CT.</param>
    private async Task MaybeRekeyAsync(CancellationToken cancellationToken)
    {
        // Short-circuit if the trigger isn't configured (pre-handshake or
        // Never policy). _rekeyAsyncCallback is null when ConfigureRekeyTrigger
        // was never called (the public ChannelRouter ctor for unit tests).
        if (_rekeyAsyncCallback is null || _rekeyPolicy is null)
        {
            return;
        }

        RekeyPolicy policy = _rekeyPolicy;

        // Read the per-direction counters. The reader/writer live on the
        // router's _queue and _writer (the same instances the session created).
        long inbBytes = _queue.Reader.InboundBytes;
        long inbPackets = _queue.Reader.InboundPackets;
        long outBytes = _writer.OutboundBytes;
        long outPackets = _writer.OutboundPackets;

        bool bytesExceeded = inbBytes >= policy.MaxBytes || outBytes >= policy.MaxBytes;
        bool packetsExceeded = inbPackets >= policy.MaxPackets || outPackets >= policy.MaxPackets;

        // Time threshold: only check when configured (TimeSpan.MaxValue disables).
        // ElapsedSinceHandshake is provided by the session that wired the trigger
        // (the router doesn't own a TimeProvider — it asks the session). To avoid
        // a circular dep (router→session), the session exposes the elapsed via a
        // callback set alongside the policy; here we read it via the callback's
        // closure. The callback captures SshSession and reads its property.
        bool timeExceeded = false;
        if (policy.MaxInterval != TimeSpan.MaxValue && _getElapsedSinceHandshake is not null)
        {
            TimeSpan elapsed = _getElapsedSinceHandshake();
            timeExceeded = elapsed >= policy.MaxInterval;
        }

        if (!bytesExceeded && !packetsExceeded && !timeExceeded)
        {
            return;
        }

        // Threshold exceeded — fire the rekey. The callback (SshSession.RekeyAsync)
        // has its own re-entry guard for the case where both trigger paths fire in
        // the same pump cycle (server-initiated KEXINIT inside WaitForTypesAsync
        // fires first; this auto-trigger then short-circuits).
        await _rekeyAsyncCallback(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A callback returning the elapsed time since the last NEWKEYS (or handshake
    /// completion, before the first rekey). Set by <see cref="SshSession"/> alongside
    /// <see cref="ConfigureRekeyTrigger"/>; null disables the time-based trigger.
    /// </summary>
    private Func<TimeSpan>? _getElapsedSinceHandshake;

    /// <summary>
    /// Sets the time-since-handshake accessor. The router
    /// doesn't own a <see cref="TimeProvider"/>; instead the session exposes
    /// its <see cref="SshSession.ElapsedSinceHandshake"/> via this closure.
    /// </summary>
    public void SetElapsedSinceHandshakeAccessor(Func<TimeSpan> accessor)
    {
        _getElapsedSinceHandshake = accessor;
    }

    // ── Routing ────────────────────────────────────────────────────────────

    /// <summary>
    /// Routes a channel-async packet (types 93–98) to the channel whose
    /// <see cref="SshChannel.LocalId"/> matches the packet's recipient-channel
    /// field. Silently drops packets for unregistered channels (parity
    /// <c>packet.c:973-978</c>).
    /// </summary>
    /// <remarks>
    /// After mutating channel state, this method calls
    /// <see cref="SignalChannel"/> for the recipient — waking any task awaiting
    /// <see cref="WaitForStateChangeAsync"/> for this channel. The signal is
    /// edge-triggered (means "state changed"); the woken channel re-checks its
    /// own state and loops if not yet ready.
    /// </remarks>
    private async Task RouteAsync(RawPacket pkt, CancellationToken cancellationToken)
    {
        // The recipient channel id is the 4 bytes after the 1-byte type.
        // All SSH_MSG_CHANNEL_* messages carry it at offset 1 (RFC 4254 §5).
        if (pkt.Payload.Length < 5)
        {
            return;
        }

        uint recipientId = ReadUInt32At(pkt.Payload, 1);
        if (!_byLocalId.TryGetValue(recipientId, out SshChannel? channel))
        {
            // packet.c:973-978 / 1094-1096 / 1221-1226 / 1314: unknown channel — drop.
            return;
        }

        switch (pkt.Type)
        {
            case PacketType.ChannelData:
                channel.DeliverDataPayload(pkt.Payload, isExtended: false);
                break;
            case PacketType.ChannelExtendedData:
                await DeliverExtendedDataPayloadAsync(channel, pkt.Payload, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case PacketType.ChannelWindowAdjust:
                DeliverWindowAdjust(channel, pkt.Payload);
                break;
            case PacketType.ChannelEof:
                channel.DeliverEof();
                break;
            case PacketType.ChannelClose:
                channel.DeliverClose();
                break;
            case PacketType.ChannelRequest:
                await DeliverRequestAsync(channel, pkt.Payload, cancellationToken).ConfigureAwait(false);
                break;
            default:
                // Should not reach here (combined set only includes 93-98 + reply
                // types, and reply types are returned above). Defensive no-op.
                break;
        }

        // Signal any task awaiting this channel's state. No-op if no
        // waiter is registered in _signals (legacy single-channel path).
        SignalChannel(recipientId);
    }

    /// <summary>
    /// Routes a <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> (stderr) packet. Applies
    /// the same packet-size/window truncation as
    /// <see cref="SshChannel.DeliverDataPayload"/>, then either:
    /// <list type="bullet">
    /// <item>Buffers the data via
    /// <see cref="SshChannel.DeliverDataPayload(byte[], bool)"/> when the
    /// channel's <see cref="SshChannel.ExtendedDataMode"/> is
    /// <see cref="SshExtendedDataMode.Normal"/> or <see cref="SshExtendedDataMode.Merge"/>
    /// (parity <c>packet.c:1060-1082</c>); OR</item>
    /// <item>Drops the data and immediately refunds the freed window bytes via
    /// <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> when the mode is
    /// <see cref="SshExtendedDataMode.Ignore"/> (parity <c>packet.c:994-1030</c>).</item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// The truncation arithmetic itself lives on
    /// <see cref="SshChannel"/> under its window lock (atomic with the
    /// read-avail bump / the refund computation), so the router no longer
    /// reads the window counters unlocked.
    /// </remarks>
    private static ValueTask DeliverExtendedDataPayloadAsync(
        SshChannel channel, byte[] payload, CancellationToken cancellationToken)
    {
        if (channel.ExtendedDataMode != SshExtendedDataMode.Ignore)
        {
            // Normal/Merge (the majority): same truncation + buffering
            // invariants as stdout, applied atomically inside the channel.
            channel.DeliverDataPayload(payload, isExtended: true);
            return ValueTask.CompletedTask;
        }

        // IGNORE mode — packet.c:994-1030. The channel computes the same
        // (window-truncated) refund amount atomically; the data is never
        // buffered, so read_avail is untouched and the truncated length is
        // refunded in full.
        uint refund = channel.ComputeIgnoreRefundAmount(payload);
        if (refund > 0)
        {
            // packet.c:1008 + 1022-1025 + channel.c:1925 — refund the freed window
            // to the peer via WINDOW_ADJUST (force=1, bypasses MINADJUST queue).
            return new ValueTask(DeliverExtendedDataRefundAsync(channel, refund, cancellationToken));
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>Slow path of <see cref="DeliverExtendedDataPayloadAsync"/>: refunds ignored data (network IO).</summary>
    private static async Task DeliverExtendedDataRefundAsync(SshChannel channel, uint refund, CancellationToken cancellationToken)
    {
        await channel.RefundInboundWindowAsync(refund, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Parses an inbound <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c>
    /// (<c>[93][u32 recipient][u32 bytestoadd]</c>) and applies it to the
    /// channel's outbound window (parity <c>packet.c:1306-1325</c>).
    /// </summary>
    private static void DeliverWindowAdjust(SshChannel channel, byte[] payload)
    {
        if (payload.Length < 9)
        {
            return;
        }

        uint bytesToAdd = ReadUInt32At(payload, 5);
        channel.DeliverWindowAdjust(bytesToAdd);
    }

    /// <summary>
    /// Parses an inbound <c>SSH_MSG_CHANNEL_REQUEST</c> for
    /// <c>"exit-status"</c> / <c>"exit-signal"</c> into channel state,
    /// and replies <c>CHANNEL_FAILURE</c> if the request has
    /// <c>want_reply=TRUE</c> (parity <c>packet.c:1117-1209</c>).
    /// </summary>
    private async Task DeliverRequestAsync(
        SshChannel channel, byte[] payload, CancellationToken cancellationToken)
    {
        // [98][u32 recipient][string request_type][bool want_reply][type-specific...]
        var r = new PacketWireReader(new ReadOnlySequence<byte>(payload));
        try
        {
            _ = r.ReadByte();                  // type (98)
            _ = r.ReadUInt32BigEndian();       // recipient channel
            string requestType = r.ReadString();
            byte wantReply = r.ReadByte();     // want_reply boolean

            if (requestType == "exit-status")
            {
                // packet.c:1141-1144 — exit_status = u32 after want_reply.
                uint status = r.ReadUInt32BigEndian();
                channel.DeliverExitStatus((int)status);
            }
            else if (requestType == "exit-signal")
            {
                // packet.c:1164-1183 — signal name (without SIG prefix).
                string signal = r.ReadString();
                channel.DeliverExitSignal(signal);
            }

            if (wantReply != 0)
            {
                // packet.c:1196-1205 — reply CHANNEL_FAILURE for any request
                // with want_reply=TRUE that we don't otherwise handle. The
                // recipient is the server's channel id (= channel.RemoteId).
                await SendChannelFailureAsync(channel.RemoteId, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (SshException)
        {
            // Malformed CHANNEL_REQUEST — drop silently (defensive; the C code
            // parses defensively too, gating each field on datalen).
        }
    }

    /// <summary>
    /// Builds and sends <c>[100 CHANNEL_FAILURE][u32 recipientChannelId]</c>.
    /// Used to reply to inbound <c>CHANNEL_REQUEST</c>s with
    /// <c>want_reply=TRUE</c> (<c>packet.c:1196-1205</c>). Awaited inline by
    /// <see cref="DeliverRequestAsync"/> so the reply lands before the next
    /// inbound packet is read (preserving wire ordering).
    /// </summary>
    private async Task SendChannelFailureAsync(uint recipientChannelId, CancellationToken cancellationToken)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelFailure;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannelId);
        await _writer.WritePacketAsync(PacketType.ChannelFailure, payload, cancellationToken)
            .ConfigureAwait(false);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /// <summary>Reads a big-endian uint32 from <paramref name="buf"/> at <paramref name="offset"/>.</summary>
    private static uint ReadUInt32At(byte[] buf, int offset)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offset, 4));
    }

    /// <summary>
    /// Concatenates <paramref name="replyTypes"/> with
    /// <see cref="s_channelAsyncTypes"/> into a new array, memoized per
    /// <paramref name="replyTypes"/> array instance. The channel call sites use
    /// a small fixed set of reply-type arrays; the cache is keyed by reference
    /// because <see cref="WaitForReplyAsync"/> also accepts caller-supplied
    /// arrays. Without the cache, every reply wait allocated the merged array
    /// on each pump-loop iteration.
    /// </summary>
    private static int[] CombineTypes(int[] replyTypes)
        => s_combinedTypes.GetValue(replyTypes, static key =>
        {
            int[] combined = new int[key.Length + s_channelAsyncTypes.Length];
            key.CopyTo(combined, 0);
            s_channelAsyncTypes.CopyTo(combined, key.Length);
            return combined;
        });

    /// <summary>
    /// Memoizes <see cref="CombineTypes"/> results. Reference-keyed: entries
    /// live only as long as the caller-supplied array is reachable, so a
    /// caller passing transient arrays cannot leak or unboundedly grow this.
    /// </summary>
    private static readonly ConditionalWeakTable<int[], int[]> s_combinedTypes = new();

    // ── IDisposable ─────────────────────────────────────

    /// <summary>
    /// Disposes the cooperative-pumper lock. The router's lifetime is owned by
    /// <see cref="SshSession"/>; <see cref="SshSession.DisposeAsync"/> calls
    /// this after disposing the writer + reader.
    /// </summary>
    /// <remarks>
    /// <b>Cancels outstanding waiters first.</b> Disposing
    /// <see cref="_pumpLock"/> directly while waiters are queued in
    /// <see cref="_signals"/> would throw <see cref="ObjectDisposedException"/>
    /// to those waiters' <see cref="TaskCompletionSource{TResult}.Task"/> calls
    /// (or worse, strand them). The fix cancels every registered waiter first
    /// so they throw a clean <see cref="OperationCanceledException"/> that the
    /// channel ops can translate to disposal handling, THEN disposes the lock.
    /// Safe to call multiple times (<see cref="SemaphoreSlim.Dispose()"/> is
    /// idempotent).
    /// </remarks>
    public void Dispose()
    {
        // Cancel every registered waiter so in-flight awaits throw a clean
        // OCE rather than an ObjectDisposedException on the disposed semaphore.
        foreach (KeyValuePair<uint, List<TaskCompletionSource<bool>>> entry in _signals)
        {
            lock (entry.Value)
            {
                foreach (TaskCompletionSource<bool> tcs in entry.Value)
                {
                    tcs.TrySetCanceled();
                }
            }
        }

        _signals.Clear();

        _pumpLock.Dispose();
        _globalReplyLock.Dispose();

        // Cancel any outstanding global-request waiter so its
        // SendGlobalRequestAsync call throws a clean OCE instead of hanging
        // on a TCS that can never be completed (the pump is gone).
        _globalReplyTcs?.TrySetCanceled();
        _globalReplyTcs = null;
    }
}
