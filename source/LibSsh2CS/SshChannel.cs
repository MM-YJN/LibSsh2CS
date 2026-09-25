using System.Buffers;
using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS;

/// <summary>
/// An SSH-2 channel ("session" type) over a <see cref="SshSession"/>. Provides
/// exec, read (stdout), write (stdin), and the close handshake. Mirrors the
/// session-channel slice of libssh2's <c>channel.c</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Window-naming convention (diverges from libssh2 for
/// clarity).</b> libssh2 names the windows <c>local.window_size</c> and
/// <c>remote.window_size</c>, a known footgun — the code itself carries
/// reminders like "REMEMBER local means local as SOURCE of data"
/// (<c>channel.c:2404</c>) and "remote means remote as source of data, NOT
/// remote window" (<c>packet.c:1034</c>). This port uses direction-named fields
/// instead, with the following libssh2 mapping:
/// </para>
/// <list type="table">
/// <listheader><term>C# field</term><description>libssh2 field / semantics</description></listheader>
/// <item><term><c>_outboundWindow</c></term><description><c>local.window_size</c> — bytes we may still SEND. Granted by the peer in <c>CHANNEL_OPEN_CONFIRMATION</c>; decremented on write; refilled when the peer sends <c>WINDOW_ADJUST</c>.</description></item>
/// <item><term><c>_inboundWindow</c></term><description><c>remote.window_size</c> — bytes we've agreed to RECEIVE. Set from our own advertisement (<see cref="ChannelConstants.WindowDefault"/>); decremented on read; refilled when we send <c>WINDOW_ADJUST</c>.</description></item>
/// <item><term><c>_outboundMaxPacket</c></term><description><c>local.packet_size</c> — max payload the peer will accept from us (from <c>CHANNEL_OPEN_CONFIRMATION</c>).</description></item>
/// <item><term><c>_inboundMaxPacket</c></term><description><c>remote.packet_size</c> — max payload we advertised (<see cref="ChannelConstants.PacketDefault"/>).</description></item>
/// </list>
/// <para>
/// <b>Window/counter synchronization.</b>
/// libssh2 is single-threaded, so its window arithmetic needs no locking; this
/// port's cooperative pumper routes inbound deliveries on a different task
/// than the channel's own read/write continuations. All mutations of — and
/// accounting reads on — <c>_readAvail</c>, <c>_inboundWindow</c>,
/// <c>_outboundWindow</c> and the stdout/stderr FIFOs therefore run under the
/// per-channel <c>_windowLock</c> (never held across an <c>await</c>); sends
/// use claim/reserve-first with rollback on failure so the books stay exact
/// across concurrent tasks.
/// </para>
/// <para>
/// <b>Channel ids.</b> <see cref="LocalId"/> is the id WE assigned in
/// <c>CHANNEL_OPEN</c>; the peer addresses us by it. <see cref="RemoteId"/> is
/// the id the peer assigned; we address the peer by it in outbound messages.
/// Parity with <c>channel.local.id</c> / <c>channel.remote.id</c>.
/// </para>
/// <para>
/// Carries the channel state and the internal delivery surface used by
/// <see cref="ChannelRouter"/> to route inbound packets.
/// </para>
/// </remarks>
public sealed class SshChannel : IAsyncDisposable
{
    // ── Back-references extracted from the session at open time ────────────
    // (The channel holds the writer + router directly, not a
    // SshSession back-pointer — channel ops only need outbound write + inbound
    // routing, and this makes the channel unit-testable without a real session.)

    /// <summary>The outbound packet framer (from <see cref="SshSession"/>).</summary>
    private readonly PacketWriter _writer;

    /// <summary>The inbound channel demultiplexer (from <see cref="SshSession"/>).</summary>
    private readonly ChannelRouter _router;

    // ── Identity ───────────────────────────────────────────────────────────

    /// <summary>
    /// The channel id WE assigned in <c>SSH_MSG_CHANNEL_OPEN</c>
    /// (<c>channel.local.id</c>). The peer addresses inbound messages to this id.
    /// </summary>
    public uint LocalId { get; }

    /// <summary>
    /// The channel id the PEER assigned, learned from
    /// <c>SSH_MSG_CHANNEL_OPEN_CONFIRMATION</c> (<c>channel.remote.id</c>). We
    /// address outbound messages to this id. Set in two phases: the constructor
    /// seeds it (0 for the half-open channel during <c>OpenAsync</c>), and
    /// <see cref="ApplyOpenConfirmation"/> sets the real value once the peer's
    /// confirmation arrives.
    /// </summary>
    public uint RemoteId => _remoteId;

    /// <summary>Backing field for <see cref="RemoteId"/> (mutable for two-phase open).</summary>
    private uint _remoteId;

    // ── Cached CHANNEL_REQUEST names (avoid per-request ASCII encoding) ────

    private static readonly byte[] s_envRequestType = "env"u8.ToArray();
    private static readonly byte[] s_ptyReqRequestType = "pty-req"u8.ToArray();
    private static readonly byte[] s_windowChangeRequestType = "window-change"u8.ToArray();
    private static readonly byte[] s_signalRequestType = "signal"u8.ToArray();
    private static readonly byte[] s_authAgentOpenSshRequestType = "auth-agent-req@openssh.com"u8.ToArray();
    private static readonly byte[] s_authAgentRfcRequestType = "auth-agent-req"u8.ToArray();

    // Shared reply-type filters for WaitForReplyAsync. Hoisted so the router's
    // CombineTypes memoization can key on a stable array reference instead of a
    // fresh collection-expression array per call.
    private static readonly int[] s_openReplyTypes =
    {
        PacketType.ChannelOpenConfirmation,
        PacketType.ChannelOpenFailure,
    };

    private static readonly int[] s_successOrFailureReplyTypes =
    {
        PacketType.ChannelSuccess,
        PacketType.ChannelFailure,
    };

    // ── Windows (direction-named) ─────────────────────────────

    /// <summary>libssh2 <c>local.window_size</c> — bytes we may still SEND.</summary>
    private uint _outboundWindow;

    /// <summary>
    /// libssh2 <c>local.packet_size</c> — max payload the peer accepts from us.
    /// Immutable after open; set by <see cref="ApplyOpenConfirmation"/>.
    /// </summary>
    private uint _outboundMaxPacket;

    /// <summary>
    /// libssh2 <c>remote.window_size</c> — bytes we've agreed to RECEIVE.
    /// Decremented at read (<c>channel.c:2222</c>); refilled when we send a
    /// <c>WINDOW_ADJUST</c> (<c>channel.c:1925</c>).
    /// </summary>
    private uint _inboundWindow;

    /// <summary>
    /// libssh2 <c>remote.window_size_initial</c> — the snapshot of
    /// <see cref="_inboundWindow"/> at open, used as the adjust-threshold
    /// baseline (<c>channel.c:2090-2091</c>: adjust when
    /// <c>window &lt; initial*3/4 + buflen</c>). Immutable after open.
    /// </summary>
    private readonly uint _inboundWindowInitial;

    /// <summary>
    /// libssh2 <c>remote.packet_size</c> — max payload we advertised (immutable
    /// after open).
    /// </summary>
    private readonly uint _inboundMaxPacket;

    // ── Inbound buffers (stderr buffered separately, NORMAL mode) ──

    /// <summary>
    /// Zero-copy view into an owned packet payload array: the data body
    /// occupies <c>Buffer[Start .. Start+Length)</c>. Delivery enqueues the
    /// already-owned packet payload via this segment instead of allocating a
    /// second array and copying the body (the previous per-packet double
    /// allocation). <see cref="Buffer"/> retains the leading packet header
    /// bytes before <see cref="Start"/>, which is harmless — the array was
    /// already allocated at that size.
    /// </summary>
    private readonly struct DataSegment(byte[] buffer, int start, int length)
    {
        public readonly byte[] Buffer = buffer;
        public readonly int Start = start;
        public readonly int Length = length;
    }

    /// <summary>FIFO of unread stdout payloads (<c>SSH_MSG_CHANNEL_DATA</c> bodies).</summary>
    private readonly Queue<DataSegment> _stdoutBuffer = new();

    /// <summary>
    /// Read cursor into the front <see cref="_stdoutBuffer"/> entry — bytes of
    /// the head packet already handed to a caller via <c>ReadAsync</c>. Mirrors
    /// libssh2's per-packet <c>data_head</c> (<c>channel.c:2190</c>); resets to 0
    /// when the head packet is fully drained and dequeued.
    /// </summary>
    private int _stdoutHeadOffset;

    /// <summary>
    /// FIFO of unread stderr payloads (<c>SSH_MSG_CHANNEL_EXTENDED_DATA</c>
    /// bodies, data_type_code = <c>SSH_EXTENDED_DATA_STDERR</c>).
    /// <c>ReadStderrAsync</c> drains this buffer.
    /// </summary>
    private readonly Queue<DataSegment> _stderrBuffer = new();

    /// <summary>
    /// Read cursor into the front <see cref="_stderrBuffer"/> entry — bytes of
    /// the head stderr packet already handed to a caller via
    /// <c>ReadStderrAsync</c>. Mirrors <see cref="_stdoutHeadOffset"/>; resets
    /// to 0 when the head packet is fully drained and dequeued.
    /// </summary>
    private int _stderrHeadOffset;

    /// <summary>
    /// How <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> (stderr) is presented to the
    /// caller. Defaults to <see cref="SshExtendedDataMode.Normal"/>. Mutated via
    /// <see cref="SetExtendedDataModeAsync"/>. Read by the router at delivery
    /// time (parity <c>packet.c:994</c>) and by <c>ReadAsync</c>/<c>ReadStderrAsync</c>.
    /// </summary>
    private SshExtendedDataMode _extendedDataMode = SshExtendedDataMode.Normal;

    /// <summary>
    /// libssh2 <c>read_avail</c> — total unread bytes across stdout + stderr
    /// buffers. Incremented at packet-delivery (<c>packet.c:1074</c>);
    /// decremented at read (<c>channel.c:2221</c>). Used by the router's
    /// window-overrun check (<c>packet.c:1047, 1062</c>).
    /// </summary>
    private uint _readAvail;

    /// <summary>
    /// Guards <see cref="_readAvail"/>, <see cref="_inboundWindow"/>,
    /// <see cref="_outboundWindow"/>, <see cref="_outboundMaxPacket"/>,
    /// <see cref="_remoteId"/> and the stdout/stderr FIFOs +
    /// head-offsets. The C reference is single-threaded; this port's
    /// cooperative pumper routes deliveries on a different task than the
    /// channel's own read/write continuations, so every read-modify-write on
    /// those fields must be atomic. The lock is NEVER held across an
    /// <c>await</c> — the only nesting is pump-lock → window-lock (the pumper
    /// delivering), so no deadlock cycle exists.
    /// </summary>
    private readonly object _windowLock = new();

    // ── Remote state flags (libssh2 remote.{eof,close}) ────────────────────

    /// <summary>libssh2 <c>remote.eof</c> — peer sent <c>SSH_MSG_CHANNEL_EOF</c>.</summary>
    private bool _remoteEof;

    /// <summary>libssh2 <c>remote.close</c> — peer sent <c>SSH_MSG_CHANNEL_CLOSE</c>.</summary>
    private bool _remoteClose;

    // ── Local state flags (libssh2 local.{eof,close}) ──────────────────────

    /// <summary>libssh2 <c>local.eof</c> — we have sent <c>SSH_MSG_CHANNEL_EOF</c>
    /// (set by <see cref="DisposeAsync"/>'s implicit EOF, channel.c:2516).</summary>
    private bool _localEof;

    /// <summary>libssh2 <c>local.close</c> — we have sent <c>SSH_MSG_CHANNEL_CLOSE</c>
    /// and observed the peer's CLOSE; the close handshake is complete
    /// (<c>channel.c:2714</c>). Subsequent reads return 0; writes throw.</summary>
    private bool _localClose;

    /// <summary>
    /// Serializes same-channel <c>want_reply</c> request/reply cycles:
    /// SSH replies carry no request id — only the message type — and the
    /// router's per-channel reply slot holds ONE reply, so two concurrent
    /// <c>want_reply</c> requests on the same channel are indistinguishable at
    /// the routing layer (the second reply overwrites the slot; a waiter
    /// consumes the wrong reply or hangs). The C is single-threaded and
    /// serializes inherently; the managed API's full-duplex
    /// concurrency (concurrent reads/writes) is unaffected — only
    /// request/reply cycles on one channel serialize.
    /// </summary>
    private readonly SemaphoreSlim _requestLock = new(1, 1);

    /// <summary>
    /// Atomic dispose-started guard: <c>_localClose</c> is only set at the
    /// END of the teardown, so a plain check-then-set let a concurrent second
    /// disposer re-run the whole teardown (duplicate EOF + CHANNEL_CLOSE on the
    /// wire). The exchange makes exactly one disposer run the teardown, so
    /// a second DisposeAsync is a no-op even under concurrency.
    /// </summary>
    private int _disposeStarted;

    /// <summary>
    /// libssh2 <c>process_state == end</c> — a process (exec/shell/subsystem) has
    /// been started on this channel. Set by <see cref="ExecAsync"/> after the
    /// reply; a second start attempt throws (parity <c>channel.c:1536-1538</c>).
    /// </summary>
    private bool _processStarted;

    // ── Exit info (captured internally) ──

    /// <summary>libssh2 <c>exit_status</c> — set from <c>"exit-status"</c> CHANNEL_REQUEST.</summary>
    private int? _exitStatus;

    /// <summary>libssh2 <c>exit_signal</c> — set from <c>"exit-signal"</c> CHANNEL_REQUEST.</summary>
    private string? _exitSignal;

    // ════════════════════════════════════════════════════════════════════════
    // Construction (internal — channels are created by OpenAsync / tests)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Constructs a channel with the given identity and the peer-advertised
    /// outbound window/packet (from <c>CHANNEL_OPEN_CONFIRMATION</c> offset 9
    /// and 13). The inbound window/packet default to
    /// <see cref="ChannelConstants.WindowDefault"/> /
    /// <see cref="ChannelConstants.PacketDefault"/> (what we advertised).
    /// </summary>
    internal SshChannel(
        PacketWriter writer,
        ChannelRouter router,
        uint localId,
        uint remoteId,
        uint outboundWindow,
        uint outboundMaxPacket,
        uint inboundWindow = ChannelConstants.WindowDefault,
        uint inboundMaxPacket = ChannelConstants.PacketDefault)
    {
        _writer = writer;
        _router = router;
        LocalId = localId;
        _remoteId = remoteId;
        _outboundWindow = outboundWindow;
        _outboundMaxPacket = outboundMaxPacket;
        _inboundWindow = inboundWindow;
        _inboundWindowInitial = inboundWindow;
        _inboundMaxPacket = inboundMaxPacket;
    }

    /// <summary>
    /// Applies the peer-advertised values from
    /// <c>SSH_MSG_CHANNEL_OPEN_CONFIRMATION</c> (parity
    /// <c>channel.c:259-266</c>): <paramref name="remoteId"/> is the server's
    /// channel id (offset 5), <paramref name="outboundWindow"/> is the server's
    /// advertised receive window (offset 9, → libssh2 <c>local.window_size</c>
    /// = our outbound window), <paramref name="outboundMaxPacket"/> is the
    /// server's max-packet (offset 13, → libssh2 <c>local.packet_size</c>).
    /// Called by <see cref="OpenAsync"/> after the confirmation arrives.
    /// </summary>
    internal void ApplyOpenConfirmation(uint remoteId, uint outboundWindow, uint outboundMaxPacket)
    {
        // The channel is routable from the moment it is registered,
        // so the open-confirmation writes take the window lock like every
        // other mutation of these fields.
        lock (_windowLock)
        {
            _remoteId = remoteId;
            _outboundWindow = outboundWindow;
            _outboundMaxPacket = outboundMaxPacket;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Internal state accessors — used by ChannelRouter (routing + enforcement)
    // and by the channel's own read/write/close logic.
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>Current outbound (send) window — libssh2 <c>local.window_size</c>.</summary>
    internal uint OutboundWindow
    {
        get
        {
            lock (_windowLock)
            {
                return _outboundWindow;
            }
        }
    }

    /// <summary>Max payload the peer accepts from us — libssh2 <c>local.packet_size</c>.</summary>
    internal uint OutboundMaxPacket => _outboundMaxPacket;

    /// <summary>Current inbound (receive) window — libssh2 <c>remote.window_size</c>.</summary>
    internal uint InboundWindow
    {
        get
        {
            lock (_windowLock)
            {
                return _inboundWindow;
            }
        }
    }

    /// <summary>Inbound window initial — libssh2 <c>remote.window_size_initial</c> (adjust baseline).</summary>
    internal uint InboundWindowInitial => _inboundWindowInitial;

    /// <summary>Max payload we advertised — libssh2 <c>remote.packet_size</c>.</summary>
    internal uint InboundMaxPacket => _inboundMaxPacket;

    /// <summary>Unread bytes across stdout + stderr buffers — libssh2 <c>read_avail</c>.</summary>
    internal uint ReadAvail
    {
        get
        {
            lock (_windowLock)
            {
                return _readAvail;
            }
        }
    }

    /// <summary>Peer sent EOF — libssh2 <c>remote.eof</c>.</summary>
    internal bool RemoteEof => _remoteEof;

    /// <summary>
    /// True when the inbound window holds no free bytes for the peer's data
    /// (window_size == read_avail — the C's wait_eof window-full condition,
    /// channel.c:2607-2611). Both counters are read atomically under the
    /// window lock so the pair cannot tear.
    /// </summary>
    internal bool IsInboundWindowExhausted
    {
        get
        {
            lock (_windowLock)
            {
                return _inboundWindow <= _readAvail;
            }
        }
    }

    /// <summary>Peer sent CLOSE — libssh2 <c>remote.close</c>.</summary>
    internal bool RemoteClose => _remoteClose;

    /// <summary>We have sent EOF — libssh2 <c>local.eof</c>.</summary>
    internal bool LocalEof => _localEof;

    /// <summary>Close handshake complete — libssh2 <c>local.close</c>.</summary>
    internal bool LocalClose => _localClose;

    /// <summary>Exit status captured from <c>"exit-status"</c> CHANNEL_REQUEST, or null.</summary>
    internal int? ExitStatusInternal => _exitStatus;

    /// <summary>Exit signal captured from <c>"exit-signal"</c> CHANNEL_REQUEST, or null.</summary>
    internal string? ExitSignalInternal => _exitSignal;

    // ════════════════════════════════════════════════════════════════════════
    // Internal delivery surface — called by ChannelRouter when it routes an
    // inbound channel packet to this channel. Mirrors the per-branch mutations
    // in libssh2's _libssh2_packet_add (packet.c:952-1328).
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Enforces the packet-size / window truncation from
    /// <c>packet.c:1037-1069</c> on a delivered <c>SSH_MSG_CHANNEL_DATA</c> /
    /// <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> payload, revokes a prior remote
    /// EOF (<c>packet.c:1060</c>), then buffers the (possibly truncated) body
    /// and bumps <see cref="_readAvail"/> (<c>packet.c:1074</c>) — all as ONE
    /// atomic step under <see cref="_windowLock"/> (the truncation
    /// decision is computed atomically with the read-avail bump, and the FIFO
    /// enqueue cannot race a concurrent reader's dequeue).
    /// </summary>
    /// <param name="payload">The full packet payload (type byte at offset 0).</param>
    /// <param name="isExtended">True for <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c>
    /// (stderr), false for <c>SSH_MSG_CHANNEL_DATA</c> (stdout).</param>
    internal void DeliverDataPayload(byte[] payload, bool isExtended)
    {
        // payload layout (after type byte at [0]):
        //   DATA:          [u32 recipient][u32 datalen][data]
        //   EXTENDED_DATA: [u32 recipient][u32 datatype][u32 datalen][data]
        // data_head: DATA=9, EXTENDED_DATA=13 (packet.c:966, 954).
        int head = isExtended ? 13 : 9;
        if (payload.Length <= head)
        {
            return;
        }

        int dataLen = payload.Length - head;

        lock (_windowLock)
        {
            // packet.c:1037-1046 — peer exceeded its offered packet_size: truncate.
            if ((uint)dataLen > _inboundMaxPacket)
            {
                dataLen = (int)_inboundMaxPacket;
            }

            // packet.c:1047-1058 — window already full of unread data: drop entirely.
            if (_inboundWindow <= _readAvail)
            {
                return;
            }

            // packet.c:1062-1069 — peer sent more than the window allows: truncate.
            if (_readAvail + (uint)dataLen > _inboundWindow)
            {
                dataLen = (int)(_inboundWindow - _readAvail);
            }

            if (dataLen <= 0)
            {
                return;
            }

            // packet.c:1060 — receiving data revokes a prior remote EOF.
            _remoteEof = false;

            // Enqueue a zero-copy view of the already-owned packet payload;
            // the segment's Start skips the 9/13-byte header before the data.
            DataSegment segment = new(payload, head, dataLen);

            // packet.c:1074 — bump read_avail + buffer, atomically.
            _readAvail += (uint)dataLen;
            if (isExtended)
            {
                _stderrBuffer.Enqueue(segment);
            }
            else
            {
                _stdoutBuffer.Enqueue(segment);
            }
        }
    }

    /// <summary>
    /// Computes the byte count the router must refund for an extended-data
    /// payload delivered in <see cref="SshExtendedDataMode.Ignore"/> mode: the
    /// same packet-size / window truncation as
    /// <see cref="DeliverDataPayload"/> (<c>packet.c:994-1030</c>), as a pure
    /// computation under <see cref="_windowLock"/> (no mutation — the drop
    /// branch never buffers, so <c>read_avail</c> is untouched and the full
    /// truncated length is refunded). The subsequent
    /// <see cref="RefundInboundWindowAsync"/> send happens outside the lock.
    /// </summary>
    /// <param name="payload">The full EXTENDED_DATA payload (type byte at
    /// offset 0).</param>
    /// <returns>Bytes to refund via <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c>
    /// (0 = nothing to refund: window already full / empty payload).</returns>
    internal uint ComputeIgnoreRefundAmount(byte[] payload)
    {
        const int Head = 13;   // [type(1)][recip(4)][datatype(4)][datalen(4)]
        if (payload.Length <= Head)
        {
            return 0;
        }

        int dataLen = payload.Length - Head;

        lock (_windowLock)
        {
            // NO packet-size truncation here — the C's EXTENDED_DATA_IGNORE
            // branch (packet.c:994-1030) refunds the window-truncated
            // datalen − 13 and deliberately skips the packet-size truncation
            // (which lives in the normal/buffering branch, packet.c:1037-1046).
            // The pre-fix port truncated to _inboundMaxPacket first and
            // refunded less credit than the peer granted (pathological peers
            // only, but the divergence is real).

            // packet.c:1047-1058 — window already full of unread data: drop silently.
            if (_inboundWindow <= _readAvail)
            {
                return 0;
            }

            // packet.c:1062-1069 / 1003-1006 — peer sent more than the window allows.
            if (_readAvail + (uint)dataLen > _inboundWindow)
            {
                dataLen = (int)(_inboundWindow - _readAvail);
            }

            return dataLen <= 0 ? 0 : (uint)dataLen;
        }
    }

    /// <summary>
    /// Applies an inbound <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c>: adds
    /// <paramref name="bytesToAdd"/> to <see cref="_outboundWindow"/>
    /// (<c>packet.c:1315</c>), unblocking a waiting write.
    /// </summary>
    internal void DeliverWindowAdjust(uint bytesToAdd)
    {
        // packet.c:1315 — channelp->local.window_size += bytestoadd;
        lock (_windowLock)
        {
            _outboundWindow += bytesToAdd;
        }
    }

    /// <summary>
    /// Marks <c>SSH_MSG_CHANNEL_EOF</c> received: sets <c>remote.eof</c>
    /// (<c>packet.c:1103</c>). A subsequent data packet revokes this inside
    /// <see cref="DeliverDataPayload"/> (<c>packet.c:1060</c>).
    /// </summary>
    internal void DeliverEof()
    {
        // packet.c:1103 — channelp->remote.eof = 1;
        // Locked so a waiter's condition predicate is ordered with
        // the write (an unlocked write could leave a lost-wakeup window).
        lock (_windowLock)
        {
            _remoteEof = true;
        }
    }

    /// <summary>
    /// Marks <c>SSH_MSG_CHANNEL_CLOSE</c> received: sets <c>remote.close</c>
    /// and <c>remote.eof</c> (<c>packet.c:1232-1233</c>).
    /// </summary>
    internal void DeliverClose()
    {
        // packet.c:1232-1233 — channelp->remote.close = 1; remote.eof = 1;
        lock (_windowLock)
        {
            _remoteClose = true;
            _remoteEof = true;
        }
    }

    /// <summary>
    /// Records the exit status from a <c>"exit-status"</c>
    /// <c>SSH_MSG_CHANNEL_REQUEST</c> (<c>packet.c:1141-1144</c>).
    /// </summary>
    internal void DeliverExitStatus(int status)
    {
        lock (_windowLock)
        {
            _exitStatus = status;
        }
    }

    /// <summary>
    /// Records the exit signal from a <c>"exit-signal"</c>
    /// <c>SSH_MSG_CHANNEL_REQUEST</c> (<c>packet.c:1169-1183</c>).
    /// </summary>
    internal void DeliverExitSignal(string signal)
    {
        lock (_windowLock)
        {
            _exitSignal = signal;
        }
    }

    /// <summary>
    /// Drains and returns the next unread stdout payload, or null if the buffer
    /// is empty. Used by <c>ReadAsync</c>; exposed internally for
    /// router-delivery verification. Locked — the
    /// pumper may enqueue concurrently. Materializes a tight copy because the
    /// FIFO stores zero-copy segments over the full packet payload.
    /// </summary>
    internal byte[]? TryDequeueStdout()
    {
        lock (_windowLock)
        {
            if (_stdoutBuffer.Count == 0)
            {
                return null;
            }

            DataSegment segment = _stdoutBuffer.Dequeue();
            _stdoutHeadOffset = 0;
            return segment.Buffer.AsSpan(segment.Start, segment.Length).ToArray();
        }
    }

    /// <summary>
    /// Peeks (without removing) the unread stderr payloads as a snapshot.
    /// Exposed internally for router-delivery verification;
    /// <c>ReadStderrAsync</c> drains it. Returns a locked
    /// snapshot rather than a live enumeration over the racy FIFO.
    /// Materializes tight copies because the FIFO stores zero-copy segments.
    /// </summary>
    internal IReadOnlyList<byte[]> PeekStderr()
    {
        lock (_windowLock)
        {
            byte[][] snapshot = new byte[_stderrBuffer.Count][];
            int i = 0;
            foreach (DataSegment segment in _stderrBuffer)
            {
                snapshot[i++] = segment.Buffer.AsSpan(segment.Start, segment.Length).ToArray();
            }

            return snapshot;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Open — _libssh2_channel_open (channel.c:131-350)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Opens a <c>"session"</c>-type channel: allocates a local channel id,
    /// registers the half-open channel, sends <c>SSH_MSG_CHANNEL_OPEN</c>, and
    /// awaits <c>CHANNEL_OPEN_CONFIRMATION</c> / <c>CHANNEL_OPEN_FAILURE</c>.
    /// Mirrors <c>_libssh2_channel_open(..., "session", WINDOW_DEFAULT,
    /// PACKET_DEFAULT, ...)</c> (<c>channel.c:131-350</c>).
    /// </summary>
    /// <param name="writer">The session's outbound packet framer.</param>
    /// <param name="router">The session's channel router (sole reader of the
    /// inbound queue).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The newly opened channel.</returns>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelFailure"/> if the server rejects the
    /// channel open (parity <c>channel.c:285-310</c>).</exception>
    internal static Task<SshChannel> OpenAsync(
        PacketWriter writer, ChannelRouter router, CancellationToken cancellationToken)
        => OpenChannelAsync(
            channelType: "session",
            extra: default,
            writer: writer,
            router: router,
            cancellationToken: cancellationToken);

    /// <summary>
    /// Opens a <c>"direct-tcpip"</c> channel — a client-initiated TCP tunnel
    /// through the SSH server. Mirrors <c>libssh2_channel_direct_tcpip_ex</c>
    /// (<c>channel.c:381-435</c>):
    /// <code>
    /// byte    SSH_MSG_CHANNEL_OPEN (= 90)
    /// string  "direct-tcpip"
    /// u32     sender_channel   (localId)
    /// u32     initial_window_size
    /// u32     max_packet_size
    /// string  host             (the host to connect TO on the server side)
    /// u32     port             (the port to connect TO)
    /// string  originator_address  (typically "127.0.0.1")
    /// u32     originator_port      (typically 0)
    /// </code>
    /// </summary>
    /// <param name="writer">The session's outbound packet framer.</param>
    /// <param name="router">The session's channel router.</param>
    /// <param name="host">The remote host the server should connect to.</param>
    /// <param name="port">The remote port the server should connect to.</param>
    /// <param name="originatorAddress">The originator address to report
    /// (typically <c>"127.0.0.1"</c> or the local socket address). The server
    /// logs this for auditing; it does not affect routing.</param>
    /// <param name="originatorPort">The originator port to report (typically
    /// <c>0</c>).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The newly opened direct-tcpip channel.</returns>
    internal static Task<SshChannel> OpenDirectTcpIpAsync(
        PacketWriter writer, ChannelRouter router,
        string host, int port, string originatorAddress, int originatorPort,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(originatorAddress);

        byte[] extra = BuildDirectTcpIpExtra(host, port, originatorAddress, originatorPort);
        return OpenChannelAsync(
            channelType: "direct-tcpip",
            extra: extra,
            writer: writer,
            router: router,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Opens a <c>"direct-streamlocal@openssh.com"</c> channel — a
    /// client-initiated UNIX-domain-socket tunnel through the SSH server
    /// (OpenSSH extension). Mirrors <c>libssh2_channel_direct_streamlocal_ex</c>
    /// (<c>channel.c:462-513</c>):
    /// <code>
    /// byte    SSH_MSG_CHANNEL_OPEN (= 90)
    /// string  "direct-streamlocal@openssh.com"
    /// u32     sender_channel   (localId)
    /// u32     initial_window_size
    /// u32     max_packet_size
    /// string  socket_path      (the UNIX socket path to connect TO)
    /// string  originator_address  (typically "127.0.0.1")
    /// u32     originator_port      (typically 0)
    /// </code>
    /// </summary>
    /// <remarks>
    /// Unlike <c>direct-tcpip</c>, the OpenSSH streamlocal extension has no
    /// port field after <c>socket_path</c> — the wire layout is
    /// <c>[socket_path][originator_address][originator_port]</c>.
    /// </remarks>
    internal static Task<SshChannel> OpenDirectStreamLocalAsync(
        PacketWriter writer, ChannelRouter router,
        string socketPath, string originatorAddress, int originatorPort,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        ArgumentNullException.ThrowIfNull(originatorAddress);

        byte[] extra = BuildDirectStreamLocalExtra(socketPath, originatorAddress, originatorPort);
        return OpenChannelAsync(
            channelType: "direct-streamlocal@openssh.com",
            extra: extra,
            writer: writer,
            router: router,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Shared core of every <c>SSH_MSG_CHANNEL_OPEN</c> flow: allocate a local
    /// id, register the half-open channel, send the OPEN payload, await the
    /// reply, parse the CONFIRMATION (or throw on FAILURE). Shared by
    /// <see cref="OpenAsync"/> and the direct-tcpip / direct-streamlocal factories.
    /// </summary>
    private static async Task<SshChannel> OpenChannelAsync(
        string channelType, ReadOnlyMemory<byte> extra,
        PacketWriter writer, ChannelRouter router, CancellationToken cancellationToken)
    {
        uint localId = router.AllocateLocalId();

        // Construct the half-open channel with placeholder outbound values
        // (remoteId=0, window=0, maxPacket=0); ApplyOpenConfirmation fills them
        // once the peer's confirmation arrives.
        var channel = new SshChannel(writer, router, localId,
            remoteId: 0, outboundWindow: 0, outboundMaxPacket: 0);

        // Register BEFORE sending (parity channel.c:189 _libssh2_list_add) so
        // any early channel packet routes to this channel.
        router.Register(channel);

        byte[] payload = BuildChannelOpenPayload(
            channelType: channelType,
            localId: localId,
            window: ChannelConstants.WindowDefault,
            packet: ChannelConstants.PacketDefault,
            extra: extra);
        try
        {
            await writer.WritePacketAsync(PacketType.ChannelOpen, payload, cancellationToken)
                .ConfigureAwait(false);

            // Use the cooperative-pumper WaitForReplyAsync (filters
            // by recipient id, pump-lock-guarded) instead of the legacy
            // unguarded WaitAsync. Concurrent OpenSessionAsync calls on the
            // same session previously raced on the single-reader PipeReader and
            // could consume each other's OPEN_CONFIRMATION/FAILURE (the legacy
            // WaitAsync returns the first reply of the right type regardless of
            // recipient id).
            RawPacket reply = await router.WaitForReplyAsync(
                channel, s_openReplyTypes, cancellationToken).ConfigureAwait(false);

            if (reply.Type == PacketType.ChannelOpenConfirmation)
            {
                // channel.c:259-266 — parse remote.id (offset 5), local.window_size
                // (offset 9, → outbound), local.packet_size (offset 13, → outbound max).
                ParseOpenConfirmation(reply.Payload,
                    out uint remoteId, out uint outboundWindow, out uint outboundMaxPacket);
                channel.ApplyOpenConfirmation(remoteId, outboundWindow, outboundMaxPacket);
                return channel;
            }

            // CHANNEL_OPEN_FAILURE — channel.c:285-310. Parse reason + description.
            ParseOpenFailure(reply.Payload, out int reason, out string description);
            throw new SshException(SshErrorCode.ChannelFailure,
                MapOpenFailureMessage(reason, description));
        }
        catch
        {
            // On any failure (write error, server rejection, or cancellation),
            // unregister the half-open channel so the router drops stray packets
            // for it (parity channel.c:323-346 cleanup path).
            router.Unregister(channel);
            throw;
        }
    }

    /// <summary>
    /// Builds the <c>direct-tcpip</c> extra-data block appended after the
    /// standard CHANNEL_OPEN header. Parity with <c>channel.c:407-410</c>:
    /// <c>[string host][u32 port][string shost][u32 sport]</c>.
    /// </summary>
    private static byte[] BuildDirectTcpIpExtra(string host, int port, string shost, int sport)
    {
        byte[] hostBytes = Encoding.UTF8.GetBytes(host);
        byte[] shostBytes = Encoding.UTF8.GetBytes(shost);
        byte[] extra = new byte[4 + hostBytes.Length + 4 + 4 + shostBytes.Length + 4];
        int o = 0;
        WriteString(extra, ref o, hostBytes);
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), port);
        o += 4;
        WriteString(extra, ref o, shostBytes);
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), sport);
        return extra;
    }

    /// <summary>
    /// Builds the <c>direct-streamlocal@openssh.com</c> extra-data block
    /// appended after the standard CHANNEL_OPEN header. Parity with
    /// <c>channel.c:486-488</c>:
    /// <c>[string socket_path][string shost][u32 sport]</c>.
    /// </summary>
    /// <remarks>
    /// Unlike direct-tcpip, there is NO port field after <c>socket_path</c>
    /// — the OpenSSH streamlocal extension drops it (a UNIX socket path is
    /// sufficient). This divergence from <c>channel_direct_tcpip</c> is the
    /// only wire-format difference between the two factories.
    /// </remarks>
    private static byte[] BuildDirectStreamLocalExtra(string socketPath, string shost, int sport)
    {
        byte[] pathBytes = Encoding.UTF8.GetBytes(socketPath);
        byte[] shostBytes = Encoding.UTF8.GetBytes(shost);
        byte[] extra = new byte[4 + pathBytes.Length + 4 + shostBytes.Length + 4];
        int o = 0;
        WriteString(extra, ref o, pathBytes);
        WriteString(extra, ref o, shostBytes);
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), sport);
        return extra;
    }

    // ── Open packet builders / parsers ─────────────────────────────────────

    /// <summary>
    /// Builds the <c>SSH_MSG_CHANNEL_OPEN</c> payload for the given channel
    /// type
    /// (parity with <c>_libssh2_channel_open</c>'s wire-layout at
    /// <c>channel.c:199-209</c>):
    /// <code>
    /// byte    SSH_MSG_CHANNEL_OPEN (= 90)
    /// string  channel_type          (e.g. "session", "direct-tcpip", "direct-streamlocal@openssh.com")
    /// u32     sender_channel        (localId — the id WE assigned)
    /// u32     initial_window_size   (WINDOW_DEFAULT = 2 MiB)
    /// u32     max_packet_size       (PACKET_DEFAULT = 32 KiB)
    /// byte[]  extra                 (type-specific fields appended after the standard block)
    /// </code>
    /// </summary>
    /// <remarks>
    /// Used by <see cref="OpenAsync"/> (channel type "session"), by
    /// direct-tcpip / direct-streamlocal factories, and (read-only, on the
    /// parsing side) by server-initiated channel-open dispatch.
    /// </remarks>
    /// <param name="channelType">ASCII channel type (e.g. <c>"session"</c>,
    /// <c>"direct-tcpip"</c>, <c>"direct-streamlocal@openssh.com"</c>).</param>
    /// <param name="localId">The locally-assigned channel id.</param>
    /// <param name="window">The initial inbound window to advertise.</param>
    /// <param name="packet">The max packet size to advertise.</param>
    /// <param name="extra">Optional type-specific fields appended after the
    /// standard 1+4+type+4+4+4 header. Pass empty for plain "session" channels.</param>
    internal static byte[] BuildChannelOpenPayload(
        string channelType, uint localId, uint window, uint packet, ReadOnlyMemory<byte> extra)
    {
        byte[] typeBytes = Encoding.ASCII.GetBytes(channelType);
        byte[] payload = new byte[1 + 4 + typeBytes.Length + 4 + 4 + 4 + extra.Length];
        int o = 0;
        payload[o++] = (byte)PacketType.ChannelOpen;
        WriteString(payload, ref o, typeBytes);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), localId);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), window);
        o += 4;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), packet);
        o += 4;
        if (!extra.IsEmpty)
        {
            extra.Span.CopyTo(payload.AsSpan(o, extra.Length));
        }

        return payload;
    }

    /// <summary>
    /// Builds a <c>SSH_MSG_CHANNEL_OPEN_CONFIRMATION</c> payload
    /// (<c>packet.c:210-216</c>):
    /// <code>
    /// byte    SSH_MSG_CHANNEL_OPEN_CONFIRMATION (= 91)
    /// u32     recipient_channel   (the peer's sender_channel from their OPEN)
    /// u32     sender_channel      (the local id WE just allocated for the new channel)
    /// u32     initial_window_size (our advertised inbound window)
    /// u32     max_packet_size     (our advertised max packet)
    /// </code>
    /// Total: 17 bytes. Used to accept an inbound
    /// <c>"forwarded-tcpip"</c> channel open from the server.
    /// </summary>
    internal static byte[] BuildChannelOpenConfirmationPayload(
        uint recipientChannel, uint senderChannel, uint window, uint maxPacket)
    {
        byte[] payload = new byte[17];
        payload[0] = (byte)PacketType.ChannelOpenConfirmation;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), senderChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), window);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(13, 4), maxPacket);
        return payload;
    }

    /// <summary>
    /// Builds a <c>SSH_MSG_CHANNEL_OPEN_FAILURE</c> payload
    /// (<c>channel.c:253-257</c>):
    /// <code>
    /// byte    SSH_MSG_CHANNEL_OPEN_FAILURE (= 92)
    /// u32     recipient_channel   (the peer's sender_channel from their OPEN)
    /// u32     reason_code         (one of the SSH_OPEN_* constants in ChannelConstants)
    /// string  description         (human-readable UTF-8 reason)
    /// string   language           (RFC 3066 language tag, ASCII — usually empty)
    /// </code>
    /// Used to reject an inbound <c>"forwarded-tcpip"</c> channel
    /// open when no listener matches or the listener queue is full.
    /// </summary>
    internal static byte[] BuildChannelOpenFailurePayload(
        uint recipientChannel, int reason, string description, string lang = "")
    {
        byte[] descBytes = Encoding.UTF8.GetBytes(description ?? string.Empty);
        byte[] langBytes = Encoding.ASCII.GetBytes(lang ?? string.Empty);
        byte[] payload = new byte[1 + 4 + 4 + 4 + descBytes.Length + 4 + langBytes.Length];
        int o = 0;
        payload[o++] = (byte)PacketType.ChannelOpenFailure;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), recipientChannel);
        o += 4;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(o, 4), reason);
        o += 4;
        WriteString(payload, ref o, descBytes);
        WriteString(payload, ref o, langBytes);
        return payload;
    }

    /// <summary>
    /// Parses <c>SSH_MSG_CHANNEL_OPEN_CONFIRMATION</c>
    /// (<c>channel.c:251-266</c>):
    /// <c>[91][u32 recip=localId][u32 sender=remoteId][u32 window][u32 maxPacket]</c>.
    /// </summary>
    private static void ParseOpenConfirmation(byte[] payload,
        out uint remoteId, out uint outboundWindow, out uint outboundMaxPacket)
    {
        if (payload.Length < 17)
        {
            throw new SshException(SshErrorCode.Proto, "truncated CHANNEL_OPEN_CONFIRMATION");
        }

        // Skip type(1) + recip(4); sender=remoteId at offset 5, window at 9, packet at 13.
        remoteId = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4));
        outboundWindow = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(9, 4));
        outboundMaxPacket = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(13, 4));
    }

    /// <summary>
    /// Parses <c>SSH_MSG_CHANNEL_OPEN_FAILURE</c>:
    /// <c>[92][u32 recip][u32 reason][string desc][string lang]</c>.
    /// </summary>
    private static void ParseOpenFailure(byte[] payload, out int reason, out string description)
    {
        // Fall back to a generic message if malformed (parity channel.c:306-308 default).
        reason = 0;
        description = string.Empty;
        if (payload.Length < 1 + 4 + 4)
        {
            return;
        }

        var r = new Util.PacketWireReader(new ReadOnlySequence<byte>(payload));
        try
        {
            _ = r.ReadByte();                 // type (92)
            _ = r.ReadUInt32BigEndian();      // recipient channel
            reason = (int)r.ReadUInt32BigEndian();
            description = r.ReadString();     // human-readable description
        }
        catch (SshException)
        {
            // Truncated — keep the generic fallback.
        }
    }

    /// <summary>
    /// Maps an <c>SSH_OPEN_*</c> reason code (<c>libssh2_priv.h:1183-1186</c>)
    /// to the libssh2 error message text (parity <c>channel.c:289-308</c>).
    /// </summary>
    private static string MapOpenFailureMessage(int reason, string description) => reason switch
    {
        ChannelConstants.OpenAdministrativelyProhibited
            => $"Channel open failure (administratively prohibited){Suffix(description)}",
        ChannelConstants.OpenConnectFailed
            => $"Channel open failure (connect failed){Suffix(description)}",
        ChannelConstants.OpenUnknownChannelType
            => $"Channel open failure (unknown channel type){Suffix(description)}",
        ChannelConstants.OpenResourceShortage
            => $"Channel open failure (resource shortage){Suffix(description)}",
        _ => $"Channel open failure{Suffix(description)}",
    };

    /// <summary>Formats the optional server-supplied description suffix.</summary>
    private static string Suffix(string description)
        => string.IsNullOrEmpty(description) ? string.Empty : $": {description}";

    /// <summary>Writes an SSH string (BE32 length + bytes) and advances the offset.</summary>
    private static void WriteString(Span<byte> buf, ref int offset, ReadOnlySpan<byte> bytes)
    {
        BinaryPrimitives.WriteInt32BigEndian(buf.Slice(offset, 4), bytes.Length);
        offset += 4;
        bytes.CopyTo(buf.Slice(offset));
        offset += bytes.Length;
    }

    /// <summary>Writes a big-endian int32 and advances the offset.</summary>
    private static void WriteInt32(Span<byte> buf, ref int offset, int value)
    {
        BinaryPrimitives.WriteInt32BigEndian(buf.Slice(offset, 4), value);
        offset += 4;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Process startup: exec / shell / subsystem
    // — _libssh2_channel_process_startup (channel.c:1526-1626)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Requests execution of <paramref name="command"/> on the remote side:
    /// sends <c>SSH_MSG_CHANNEL_REQUEST "exec"</c> with <c>want_reply=TRUE</c>
    /// and awaits <c>CHANNEL_SUCCESS</c> / <c>CHANNEL_FAILURE</c>. Mirrors
    /// <c>libssh2_channel_exec</c> → <c>_libssh2_channel_process_startup(channel,
    /// "exec", 4, command, len)</c> (<c>channel.c:1526-1626</c>).
    /// </summary>
    /// <param name="command">The command line to execute (UTF-8).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="InvalidOperationException">Thrown if a process has
    /// already been started on this channel (a channel runs at most one
    /// exec/shell/subsystem — parity <c>channel.c:1536-1538</c>).</exception>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> if the server returns
    /// <c>SSH_MSG_CHANNEL_FAILURE</c> (parity <c>channel.c:1623-1625</c>).</exception>
    public Task ExecAsync(string command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        return ProcessStartupAsync("exec", Encoding.UTF8.GetBytes(command), cancellationToken);
    }

    /// <summary>
    /// Requests an interactive shell on the remote side: sends
    /// <c>SSH_MSG_CHANNEL_REQUEST "shell"</c> with <c>want_reply=TRUE</c> and no
    /// message. Mirrors <c>libssh2_channel_shell</c>
    /// → <c>_libssh2_channel_process_startup(channel, "shell", 5, NULL, 0)</c>
    /// (<c>channel.c:1526-1626</c>). A channel runs at most one
    /// exec/shell/subsystem — calling this after another process-startup on the
    /// same channel throws (parity <c>channel.c:1536-1538</c>).
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task ShellAsync(CancellationToken cancellationToken = default)
        => ProcessStartupAsync("shell", message: null, cancellationToken);

    /// <summary>
    /// Requests a subsystem on the remote side (e.g. <c>"sftp"</c>): sends
    /// <c>SSH_MSG_CHANNEL_REQUEST "subsystem"</c> with <c>want_reply=TRUE</c>
    /// and the subsystem name as the message. Mirrors
    /// <c>libssh2_channel_subsystem</c>
    /// → <c>_libssh2_channel_process_startup(channel, "subsystem", 9,
    /// subsystem, len)</c> (<c>channel.c:1526-1626</c>).
    /// </summary>
    /// <param name="subsystem">The subsystem name (UTF-8, e.g.
    /// <c>"sftp"</c>).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task SubsystemAsync(string subsystem, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subsystem);
        return ProcessStartupAsync("subsystem", Encoding.UTF8.GetBytes(subsystem), cancellationToken);
    }

    /// <summary>
    /// The shared <c>_libssh2_channel_process_startup</c> core
    /// (<c>channel.c:1526-1626</c>): builds the CHANNEL_REQUEST payload
    /// <c>[98][u32 remote.id][string request][0x01 want_reply][u32 message_len?
    /// ][message?]</c>, sends it, awaits <c>CHANNEL_SUCCESS</c> /
    /// <c>CHANNEL_FAILURE</c>, and marks the channel non-reusable on either
    /// outcome. <paramref name="message"/> is <c>null</c> for shell (no
    /// trailing length+bytes); non-null for exec/subsystem (carries the
    /// command / subsystem name).
    /// </summary>
    /// <param name="request">The request type name (<c>"exec"</c> /
    /// <c>"shell"</c> / <c>"subsystem"</c>). ASCII; the request-name length is
    /// implicit in the wire string.</param>
    /// <param name="message">The optional message body (command / subsystem
    /// name, UTF-8). <c>null</c> for shell.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="InvalidOperationException">A process has already been
    /// started on this channel (<c>channel.c:1536-1538</c>).</exception>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> if the server returns
    /// <c>SSH_MSG_CHANNEL_FAILURE</c> (<c>channel.c:1623-1625</c>).</exception>
    private async Task ProcessStartupAsync(
        string request, byte[]? message, CancellationToken cancellationToken)
    {
        // channel.c:1536-1538 — process_state == end → BAD_USE.
        if (_processStarted)
        {
            throw new InvalidOperationException(
                "Channel can not be reused: a process has already been started on it.");
        }

        // Serialize same-channel want_reply cycles (see _requestLock) —
        // exec/shell/subsystem share the reply slot with SetEnvAsync & co.
        await _requestLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] payload = BuildProcessStartupPayload(RemoteId, request, message);
            await _writer.WritePacketAsync(PacketType.ChannelRequest, payload, cancellationToken)
                .ConfigureAwait(false);

            // channel.c:1603-1605 — requirev([SUCCESS, FAILURE]) filtered by the
            // channel id. WaitForReplyAsync routes interleaved channel-async packets
            // AND distinguishes our reply from another channel's by recipient id
            // (cooperative pumper).
            RawPacket reply = await _router.WaitForReplyAsync(
                this, s_successOrFailureReplyTypes, cancellationToken)
                .ConfigureAwait(false);

            // channel.c:1617 — process_state = end (set on BOTH success and failure,
            // before the branch). Marks the channel non-reusable for any process.
            _processStarted = true;

            if (reply.Type == PacketType.ChannelSuccess)
            {
                return;
            }

            // channel.c:1623-1625 — CHANNEL_FAILURE → CHANNEL_REQUEST_DENIED.
            string detail = message is null ? request : $"{request}: {Encoding.UTF8.GetString(message)}";
            throw new SshException(SshErrorCode.ChannelRequestDenied,
                $"Channel {request} request denied by server for: {detail}");
        }
        finally
        {
            _requestLock.Release();
        }
    }

    // ── Process-startup packet builder ─────────────────────────────────────

    /// <summary>
    /// Builds the <c>SSH_MSG_CHANNEL_REQUEST</c> payload for exec/shell/subsystem
    /// (<c>channel.c:1563-1569</c>):
    /// <c>[98][u32 remote.id][string request][0x01 want_reply][u32 message_len? ][message?]</c>.
    /// When <paramref name="message"/> is <c>null</c> (shell), no length+bytes
    /// are appended; otherwise (exec/subsystem) the 4-byte length + UTF-8 body
    /// follow the want_reply byte.
    /// </summary>
    private static byte[] BuildProcessStartupPayload(uint remoteId, string request, byte[]? message)
    {
        byte[] req = Encoding.ASCII.GetBytes(request);
        int messageLenField = message is null ? 0 : 4 + message.Length;
        byte[] payload = new byte[1 + 4 + 4 + req.Length + 1 + messageLenField];
        int o = 0;
        payload[o++] = (byte)PacketType.ChannelRequest;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), remoteId);
        o += 4;
        WriteString(payload, ref o, req);
        payload[o++] = 0x01;   // want_reply = TRUE (channel.c:1566)
        if (message is not null)
        {
            WriteString(payload, ref o, message);
        }

        return payload;
    }

    // ════════════════════════════════════════════════════════════════════════
    // SetEnv — channel_setenv (channel.c:883-984)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sets a remote environment variable prior to starting a process
    /// (exec/shell/subsystem): sends <c>SSH_MSG_CHANNEL_REQUEST "env"</c> with
    /// <c>want_reply=TRUE</c> and awaits <c>CHANNEL_SUCCESS</c> /
    /// <c>CHANNEL_FAILURE</c>. Mirrors <c>libssh2_channel_setenv_ex</c>
    /// → <c>channel_setenv</c> (<c>channel.c:883-984</c>). Must be called BEFORE
    /// <see cref="ExecAsync"/>/<see cref="ShellAsync"/>/<see cref="SubsystemAsync"/>
    /// — OpenSSH applies the env list when the process starts.
    /// </summary>
    /// <param name="name">The variable name (UTF-8).</param>
    /// <param name="value">The variable value (UTF-8).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> if the server returns
    /// <c>SSH_MSG_CHANNEL_FAILURE</c> (<c>channel.c:981-983</c>).</exception>
    public Task SetEnvAsync(string name, string value, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);

        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);

        return SendChannelRequestAsync(
            requestType: "env",
            requestTypeBytes: s_envRequestType,
            wantReply: true,
            extraLength: 4 + nameBytes.Length + 4 + valueBytes.Length,
            writeExtra: extra =>
            {
                int o = 0;
                WriteString(extra, ref o, nameBytes);
                WriteString(extra, ref o, valueBytes);
            },
            cancellationToken: cancellationToken);
    }

    // ════════════════════════════════════════════════════════════════════════
    // PTY request + window-change
    //   channel_request_pty       (channel.c:1011-1110)
    //   channel_request_pty_size  (channel.c:1289-1345)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Requests a pseudo-terminal on the channel: sends
    /// <c>SSH_MSG_CHANNEL_REQUEST "pty-req"</c> with <c>want_reply=TRUE</c> and
    /// awaits <c>CHANNEL_SUCCESS</c> / <c>CHANNEL_FAILURE</c>. Mirrors
    /// <c>libssh2_channel_request_pty_ex</c> → <c>channel_request_pty</c>
    /// (<c>channel.c:1011-1110</c>). Must be called BEFORE
    /// <see cref="ShellAsync"/>/<see cref="ExecAsync"/>/<see cref="SubsystemAsync"/>.
    /// </summary>
    /// <param name="term">The <c>TERM</c> environment variable value (e.g.
    /// <c>"vt100"</c>, <c>"xterm"</c>). ASCII.</param>
    /// <param name="width">Terminal width, in columns.</param>
    /// <param name="height">Terminal height, in rows.</param>
    /// <param name="widthPx">Terminal width, in pixels (0 if unknown).</param>
    /// <param name="heightPx">Terminal height, in pixels (0 if unknown).</param>
    /// <param name="terminalModes">Encoded terminal modes (RFC 4254 §8), or
    /// <c>null</c> for no mode overrides. Caller is responsible for the
    /// <c>name=value</c> byte encoding + trailing <c>0</c> terminator.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.Inval"/> if <paramref name="term"/> +
    /// <paramref name="terminalModes"/> together exceed 256 bytes (parity
    /// <c>channel.c:1027-1030</c>).</exception>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> if the server returns
    /// <c>SSH_MSG_CHANNEL_FAILURE</c>.</exception>
    public Task RequestPtyAsync(
        string term,
        int width,
        int height,
        int widthPx = 0,
        int heightPx = 0,
        byte[]? terminalModes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(term);

        byte[] termBytes = Encoding.ASCII.GetBytes(term);
        byte[] modesBytes = terminalModes ?? [];

        // channel.c:1027-1030 — term_len + modes_len > 256 → INVAL. The C
        // channel->reqPTY_packet is a fixed 256-byte buffer; we mirror the cap.
        if (termBytes.Length + modesBytes.Length > 256)
        {
            throw new SshException(SshErrorCode.Inval,
                "term + terminal-modes lengths too large (max 256 bytes).");
        }

        return SendChannelRequestAsync(
            requestType: "pty-req",
            requestTypeBytes: s_ptyReqRequestType,
            wantReply: true,
            extraLength: (4 + termBytes.Length) + 16 + (4 + modesBytes.Length),
            writeExtra: extra =>
            {
                int o = 0;
                WriteString(extra, ref o, termBytes);
                WriteInt32(extra, ref o, width);
                WriteInt32(extra, ref o, height);
                WriteInt32(extra, ref o, widthPx);
                WriteInt32(extra, ref o, heightPx);
                WriteString(extra, ref o, modesBytes);
            },
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Sends a <c>window-change</c> request to update the PTY dimensions on an
    /// already-started process: <c>SSH_MSG_CHANNEL_REQUEST "window-change"</c>
    /// with <c>want_reply=FALSE</c> (fire-and-forget per RFC 4254 §6.7). Mirrors
    /// <c>libssh2_channel_request_pty_size_ex</c>
    /// → <c>channel_request_pty_size</c> (<c>channel.c:1289-1345</c>).
    /// </summary>
    /// <param name="width">New terminal width, in columns.</param>
    /// <param name="height">New terminal height, in rows.</param>
    /// <param name="widthPx">New terminal width, in pixels (0 if unknown).</param>
    /// <param name="heightPx">New terminal height, in pixels (0 if unknown).</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task RequestPtyWindowSizeAsync(
        int width,
        int height,
        int widthPx = 0,
        int heightPx = 0,
        CancellationToken cancellationToken = default)
    {
        return SendChannelRequestAsync(
            requestType: "window-change",
            requestTypeBytes: s_windowChangeRequestType,
            wantReply: false,
            extraLength: 16,
            writeExtra: extra =>
            {
                int o = 0;
                WriteInt32(extra, ref o, width);
                WriteInt32(extra, ref o, height);
                WriteInt32(extra, ref o, widthPx);
                WriteInt32(extra, ref o, heightPx);
            },
            cancellationToken: cancellationToken);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Signal
    //   channel_signal (channel.c:3007-3060) → libssh2_channel_signal_ex
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Delivers a signal to the remote process/service: sends
    /// <c>SSH_MSG_CHANNEL_REQUEST "signal"</c> with <c>want_reply=FALSE</c>
    /// (fire-and-forget per RFC 4254 §6.9). Mirrors
    /// <c>libssh2_channel_signal_ex</c> → <c>channel_signal</c>
    /// (<c>channel.c:3007-3060</c>).
    /// </summary>
    /// <param name="signal">One of the standard POSIX signals. Mapped to its
    /// wire name via <see cref="SshSignalExtensions.ToWireName"/>.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task SignalAsync(SshSignal signal, CancellationToken cancellationToken = default)
        => SignalAsync(signal.ToWireName(), cancellationToken);

    /// <summary>
    /// Delivers a signal to the remote process/service: sends
    /// <c>SSH_MSG_CHANNEL_REQUEST "signal"</c> with <c>want_reply=FALSE</c>
    /// (fire-and-forget per RFC 4254 §6.9). Mirrors
    /// <c>libssh2_channel_signal_ex</c> → <c>channel_signal</c>
    /// (<c>channel.c:3007-3060</c>). Use this overload for signal names outside
    /// <see cref="SshSignal"/> (e.g. server-specific extensions).
    /// </summary>
    /// <param name="signalName">Signal name without the <c>"SIG"</c> prefix
    /// (e.g. <c>"TERM"</c>, <c>"KILL"</c>, <c>"INT"</c>). ASCII. RFC 4254 §6.9
    /// references RFC 4254 §6.10 for the canonical list.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task SignalAsync(string signalName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signalName);

        byte[] sigBytes = Encoding.ASCII.GetBytes(signalName);
        return SendChannelRequestAsync(
            requestType: "signal",
            requestTypeBytes: s_signalRequestType,
            wantReply: false,
            extraLength: 4 + sigBytes.Length,
            writeExtra: extra =>
            {
                int o = 0;
                WriteString(extra, ref o, sigBytes);
            },
            cancellationToken: cancellationToken);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Auth-agent forwarding request
    //   channel_request_auth_agent      (channel.c:1113-1211) — single attempt
    //   libssh2_channel_request_auth_agent (channel.c:1222-1265) — fallback wrapper
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Requests that the server enable ssh-agent forwarding on this channel:
    /// sends <c>SSH_MSG_CHANNEL_REQUEST "auth-agent-req@openssh.com"</c> with
    /// <c>want_reply=TRUE</c> and awaits <c>CHANNEL_SUCCESS</c> /
    /// <c>CHANNEL_FAILURE</c>. On denial, retries with the RFC-draft name
    /// <c>"auth-agent-req"</c>. Mirrors <c>libssh2_channel_request_auth_agent</c>
    /// (<c>channel.c:1222-1265</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Fallback semantics (parity with <c>channel.c:1231-1258</c>).</b>
    /// The RFC draft specifies <c>"auth-agent-req"</c>, but most servers expect
    /// the OpenSSH extension name <c>"auth-agent-req@openssh.com"</c>; the C
    /// library tries the OpenSSH variant first and falls back to the RFC name
    /// on denial. This port preserves that behavior exactly: only
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> triggers the fallback —
    /// transport/protocol errors propagate without retry (matching the C
    /// <c>!= EAGAIN</c> filter, which in practice fires only on
    /// <c>CHANNEL_REQUEST_DENIED</c> for this code path).
    /// </para>
    /// <para>
    /// <b>Channel-side request only.</b> This asks the server to set up an
    /// agent-forwarding listener; actually <i>using</i> the forwarded agent
    /// over the resulting <c>SSH_MSG_CHANNEL_DATA</c> stream requires the
    /// <c>SshAgent</c> infrastructure. Calling this method without
    /// the agent infrastructure merely results in the server preparing a
    /// listener that the client never reads.
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> if the server denies
    /// both request-name variants.</exception>
    public async Task RequestAuthAgentAsync(CancellationToken cancellationToken = default)
    {
        // channel.c:1235-1246 — try the OpenSSH variant first.
        try
        {
            await SendChannelRequestAsync(
                requestType: "auth-agent-req@openssh.com",
                requestTypeBytes: s_authAgentOpenSshRequestType,
                wantReply: true,
                extraLength: 0,
                writeExtra: static _ => { },
                cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.ChannelRequestDenied)
        {
            // Fall through to the RFC-draft variant (channel.c:1248-1258).
        }

        // channel.c:1248-1258 — fall back to the RFC-draft name.
        await SendChannelRequestAsync(
            requestType: "auth-agent-req",
            requestTypeBytes: s_authAgentRfcRequestType,
            wantReply: true,
            extraLength: 0,
            writeExtra: static _ => { },
            cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Extended-data mode
    //   libssh2_channel_handle_extended_data2 (channel.c:2027-2039)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// The current extended-data (stderr) handling mode. Read-only property;
    /// mutated via <see cref="SetExtendedDataModeAsync"/>. See
    /// <see cref="ExtendedDataMode"/> for the semantics of each value.
    /// </summary>
    public SshExtendedDataMode ExtendedDataMode => _extendedDataMode;

    /// <summary>
    /// Sets how subsequent <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> (stderr) packets
    /// are handled. Mirrors <c>libssh2_channel_handle_extended_data2</c>
    /// (<c>channel.c:2027-2039</c>). When transitioning to
    /// <see cref="SshExtendedDataMode.Ignore"/>, any already-buffered stderr is
    /// flushed and its bytes are refunded to the peer's send window (parity
    /// intent of <c>channel.c:2010-2016</c>; the C path is unreachable due to a
    /// state-machine bug).
    /// </summary>
    /// <remarks>
    /// Subsequent EXTENDED_DATA packets arriving in <see cref="SshExtendedDataMode.Ignore"/>
    /// are dropped at delivery time by the <see cref="ChannelRouter"/>
    /// (parity <c>packet.c:994-1030</c>) and refunded immediately. Set the mode
    /// BEFORE starting a process (<see cref="ExecAsync"/> /
    /// <see cref="ShellAsync"/> / <see cref="SubsystemAsync"/>) when possible.
    /// </remarks>
    /// <param name="mode">The new mode.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public async Task SetExtendedDataModeAsync(
        SshExtendedDataMode mode, CancellationToken cancellationToken = default)
    {
        SshExtendedDataMode previous = _extendedDataMode;
        _extendedDataMode = mode;

        // Transitioning INTO Ignore: flush already-buffered stderr + refund.
        if (mode == SshExtendedDataMode.Ignore && previous != SshExtendedDataMode.Ignore)
        {
            await FlushStderrBufferAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Drops all buffered stderr, decrements <see cref="_readAvail"/> by the
    /// freed byte count, and sends a <c>WINDOW_ADJUST</c> for those bytes
    /// (parity <c>_libssh2_channel_flush(EXTENDED_DATA)</c>,
    /// <c>channel.c:1669-1758</c>). Used by <see cref="SetExtendedDataModeAsync"/>
    /// when transitioning to <see cref="SshExtendedDataMode.Ignore"/>.
    /// </summary>
    private async Task FlushStderrBufferAsync(CancellationToken cancellationToken)
    {
        uint freedBytes;
        lock (_windowLock)
        {
            if (_stderrBuffer.Count == 0)
            {
                return;
            }

            freedBytes = 0;
            while (_stderrBuffer.Count > 0)
            {
                freedBytes += (uint)_stderrBuffer.Dequeue().Length;
            }

            _stderrHeadOffset = 0;

            // channel.c:1744 — read_avail -= flushed_bytes (floor at 0).
            if (freedBytes >= _readAvail)
            {
                _readAvail = 0;
            }
            else
            {
                _readAvail -= freedBytes;
            }
        }

        // channel.c:1745 + 1022-1025 — refund the freed window to the peer.
        if (freedBytes > 0)
        {
            await RefundInboundWindowAsync(freedBytes, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Refunds <paramref name="bytes"/> of inbound window to the peer by
    /// sending a <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> (parity
    /// <c>packet.c:1022-1025</c>, force=1 — no MINADJUST queueing). The peer
    /// is informed it can send <paramref name="bytes"/> more data.
    /// </summary>
    /// <remarks>
    /// <b>Divergence from the C.</b> The C brackets this send with a
    /// net-zero <c>remote.window_size -= bytes</c> (<c>packet.c:1008</c>) /
    /// <c>+= bytes</c> (<c>channel.c:1925</c>) pair. In single-threaded C the
    /// transient dip is invisible; here it would be observable by the
    /// concurrent pumper's truncation check (and a send failure would corrupt
    /// the books), so the net-zero pair is elided — the local window value is
    /// unchanged across the refund, which is the C's steady-state result.
    /// </remarks>
    /// <param name="bytes">The byte count to refund.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    internal async Task RefundInboundWindowAsync(uint bytes, CancellationToken cancellationToken)
    {
        // packet.c:1022-1025 — force=1, bypasses MINADJUST queue.
        await SendWindowAdjustAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    // ── Shared CHANNEL_REQUEST send+wait helper ───────────────────────────

    /// <summary>
    /// Writes the type-specific CHANNEL_REQUEST fields (after the want_reply
    /// byte) into a destination span of exactly the precomputed extra length.
    /// </summary>
    private delegate void ExtraWriter(Span<byte> destination);

    /// <summary>
    /// Builds and sends a <c>SSH_MSG_CHANNEL_REQUEST</c> with the common
    /// header <c>[98][u32 remote.id][string request_type][bool want_reply]</c>,
    /// then any type-specific extra fields appended by <paramref name="writeExtra"/>.
    /// When <paramref name="wantReply"/> is <c>true</c>, awaits
    /// <c>CHANNEL_SUCCESS</c>/<c>CHANNEL_FAILURE</c>; a FAILURE reply throws
    /// <see cref="SshErrorCode.ChannelRequestDenied"/>. When <c>false</c>, the
    /// method returns as soon as the request is sent (fire-and-forget per
    /// RFC 4254 §4 — used by <c>window-change</c>).
    /// </summary>
    /// <param name="requestType">The request type name for error messages
    /// (ASCII, e.g. <c>"env"</c>, <c>"pty-req"</c>, <c>"window-change"</c>).</param>
    /// <param name="requestTypeBytes">The pre-encoded ASCII request-type
    /// bytes (cached per request kind to avoid per-call encoding).</param>
    /// <param name="wantReply">If <c>true</c>, send want_reply=TRUE and wait
    /// for SUCCESS/FAILURE; if <c>false</c>, send want_reply=FALSE and return
    /// immediately after send.</param>
    /// <param name="extraLength">The exact byte count of the type-specific
    /// fields written by <paramref name="writeExtra"/>.</param>
    /// <param name="writeExtra">Callback that writes the type-specific fields
    /// (after the want_reply byte) into a span of exactly
    /// <paramref name="extraLength"/> bytes. ASCII/UTF-8 strings go via the
    /// <see cref="WriteString(Span{byte}, ref int, ReadOnlySpan{byte})"/> helper.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelRequestDenied"/> when
    /// <paramref name="wantReply"/><c>=true</c> and the server returns
    /// <c>SSH_MSG_CHANNEL_FAILURE</c>.</exception>
    private async Task SendChannelRequestAsync(
        string requestType,
        byte[] requestTypeBytes,
        bool wantReply,
        int extraLength,
        ExtraWriter writeExtra,
        CancellationToken cancellationToken)
    {
        // channel.c:2362-2365 (parity with WriteDataAsync guard) — refuse any
        // CHANNEL_REQUEST after the close handshake. Applies uniformly to
        // exec/shell/subsystem/setenv/pty/window-change/signal/auth-agent.
        if (_localClose)
        {
            throw new SshException(SshErrorCode.ChannelClosed,
                $"Cannot send '{requestType}' request: this channel has already been closed.");
        }

        // Serialize same-channel want_reply cycles (see _requestLock).
        // The lock is held from BEFORE the write until the reply is consumed
        // (or, for want_reply=false, just the write), so at most one reply per
        // channel is in flight and the router's single reply slot is never
        // ambiguous. Reads/writes are unaffected (full-duplex stays concurrent).
        await _requestLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Compute the exact size once and fill a single array; avoids the
            // List<byte> growth, per-field byte[4] temporaries, and ToArray copy.
            int total = 1 + 4 + (4 + requestTypeBytes.Length) + 1 + extraLength;
            byte[] payload = new byte[total];
            int o = 0;
            payload[o++] = (byte)PacketType.ChannelRequest;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(o, 4), RemoteId);
            o += 4;
            WriteString(payload, ref o, requestTypeBytes);
            payload[o++] = wantReply ? (byte)1 : (byte)0;
            writeExtra(payload.AsSpan(o, extraLength));

            await _writer.WritePacketAsync(PacketType.ChannelRequest, payload, cancellationToken)
                .ConfigureAwait(false);

            if (!wantReply)
            {
                return;
            }

            RawPacket reply = await _router.WaitForReplyAsync(
                this, s_successOrFailureReplyTypes, cancellationToken)
                .ConfigureAwait(false);

            if (reply.Type != PacketType.ChannelSuccess)
            {
                throw new SshException(SshErrorCode.ChannelRequestDenied,
                    $"Channel '{requestType}' request denied by server.");
            }
        }
        finally
        {
            _requestLock.Release();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Read stdout — _libssh2_channel_read (channel.c:2071-2225)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Reads stdout from the channel into <paramref name="buffer"/>. Returns the
    /// number of bytes read (may be less than <paramref name="buffer"/> if less
    /// data is immediately available — like <see cref="Stream.ReadAsync(byte[], int, int, CancellationToken)"/>), or 0
    /// if the peer has signalled <c>SSH_MSG_CHANNEL_EOF</c> /
    /// <c>SSH_MSG_CHANNEL_CLOSE</c> and no buffered data remains.
    /// </summary>
    /// <remarks>
    /// <b>Inbound window maintenance is automatic.</b> Before reading, if the
    /// inbound window has dropped below <c>initial*3/4 + buffer.Length</c>, a
    /// <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> is sent to refill it (parity
    /// <c>channel.c:2089-2107</c>). Callers never manage the receive window.
    /// </remarks>
    /// <param name="buffer">Destination buffer.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>Bytes read (0 only on peer EOF/CLOSE with empty buffer).</returns>
    public async Task<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Zero-length read: complete immediately with 0 (.NET Stream contract).
        // The C reference likewise never blocks on an empty buffer
        // (channel.c:2119 — the copy loop `bytes_read < buflen` cannot run, and
        // the !bytes_read branch returns 0/EAGAIN).
        // The previous code entered the wait loop and hung until peer EOF/CLOSE
        // while silently draining inbound data into the FIFOs.
        if (buffer.IsEmpty)
        {
            return 0;
        }

        // channel.c:2089-2107 — expand the receiving window first if too narrow.
        await EnsureInboundWindowAsync(buffer.Length, cancellationToken).ConfigureAwait(false);

        // channel.c:2118-2205 — drain whatever is already buffered.
        int bytesRead = DrainAndAccountStdout(buffer);

        if (bytesRead == 0)
        {
            // channel.c:2207-2218 — nothing buffered. Block on the transport
            // (pump+route one packet at a time) until data arrives or eof/close.
            while (!_remoteEof && !_remoteClose)
            {
                // channel.c:2111-2113 — drain incoming flow (routes DATA /
                // WINDOW_ADJUST / EOF / CLOSE / REQUEST to this or other channels).
                await _router.WaitForStateChangeAsync(this, HasStdoutDataOrEof, cancellationToken)
                    .ConfigureAwait(false);
                bytesRead = DrainAndAccountStdout(buffer);

                if (bytesRead > 0)
                {
                    break;
                }
            }
        }

        return bytesRead;
    }

    /// <summary>
    /// Reads stderr from the channel into <paramref name="buffer"/>. Returns the
    /// number of bytes read (may be less than <paramref name="buffer"/> if less
    /// data is immediately available — like <see cref="Stream.ReadAsync(byte[], int, int, CancellationToken)"/>), or 0
    /// if the peer has signalled <c>SSH_MSG_CHANNEL_EOF</c> /
    /// <c>SSH_MSG_CHANNEL_CLOSE</c> and no buffered data remains. Mirrors
    /// <c>_libssh2_channel_read</c> with <c>stream_id=SSH_EXTENDED_DATA_STDERR</c>
    /// (<c>channel.c:2071-2225</c>).
    /// </summary>
    /// <remarks>
    /// In <see cref="SshExtendedDataMode.Ignore"/> mode, always returns 0 (stderr
    /// is dropped at delivery by the router). In <see cref="SshExtendedDataMode.Merge"/>
    /// mode, applications typically read via <see cref="ReadAsync"/> instead —
    /// this method still works and drains the stderr buffer exclusively.
    /// </remarks>
    /// <param name="buffer">Destination buffer.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>Bytes read (0 only on peer EOF/CLOSE with empty buffer, or in
    /// Ignore mode).</returns>
    public async Task<int> ReadStderrAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Ignore mode: stderr is dropped at delivery; never buffered.
        if (_extendedDataMode == SshExtendedDataMode.Ignore)
        {
            return 0;
        }

        // Zero-length read: complete immediately with 0 (.NET Stream contract;
        // same reasoning as ReadAsync).
        if (buffer.IsEmpty)
        {
            return 0;
        }

        // channel.c:2089-2107 — expand the receiving window first if too narrow.
        await EnsureInboundWindowAsync(buffer.Length, cancellationToken).ConfigureAwait(false);

        int bytesRead = DrainAndAccountStderr(buffer);

        if (bytesRead == 0)
        {
            while (!_remoteEof && !_remoteClose)
            {
                await _router.WaitForStateChangeAsync(this, HasStderrDataOrEof, cancellationToken)
                    .ConfigureAwait(false);
                bytesRead = DrainAndAccountStderr(buffer);
                if (bytesRead > 0)
                {
                    break;
                }
            }
        }

        return bytesRead;
    }

    /// <summary>
    /// Drains buffered stdout (plus the MERGE-mode stderr tail) into
    /// <paramref name="dest"/> and applies the read accounting
    /// (<c>channel.c:2221-2222</c>: <c>_readAvail -=</c> /
    /// <c>_inboundWindow -=</c>) in the SAME critical section — the
    /// pumper's delivery-side bookkeeping can never interleave between the
    /// drain and the decrements.
    /// </summary>
    private int DrainAndAccountStdout(Memory<byte> dest)
    {
        lock (_windowLock)
        {
            int bytesRead = DrainStdoutInto(dest.Span);

            // channel.c:2155-2166 — MERGE mode: EXTENDED_DATA (stderr) is also
            // returned via stream_id=0 reads. Drained AFTER stdout (divergence
            // from libssh2's arrival-order preservation).
            if (_extendedDataMode == SshExtendedDataMode.Merge && bytesRead < dest.Length)
            {
                bytesRead += DrainStderrInto(dest.Span.Slice(bytesRead));
            }

            if (bytesRead > 0)
            {
                // channel.c:2221-2222 — read_avail -= bytes_read; remote.window_size -= bytes_read.
                _readAvail -= (uint)bytesRead;
                _inboundWindow -= (uint)bytesRead;
            }

            return bytesRead;
        }
    }

    /// <summary>
    /// Stderr counterpart of <see cref="DrainAndAccountStdout"/>: drains the
    /// stderr FIFO and applies the same read accounting under
    /// <see cref="_windowLock"/>.
    /// </summary>
    private int DrainAndAccountStderr(Memory<byte> dest)
    {
        lock (_windowLock)
        {
            int bytesRead = DrainStderrInto(dest.Span);

            if (bytesRead > 0)
            {
                // channel.c:2221-2222 — read_avail -= bytes_read; remote.window_size -= bytes_read.
                _readAvail -= (uint)bytesRead;
                _inboundWindow -= (uint)bytesRead;
            }

            return bytesRead;
        }
    }

    // ── Wait predicates (lost-wakeup rescues) ─────────────────────
    //
    // Each blocking loop on this channel passes one of these to
    // ChannelRouter.WaitForStateChangeAsync, which re-checks the predicate
    // after registering its signal (and again after acquiring the pump lock).
    // This closes the check-then-wait window: a state change applied between
    // the caller's own last check and the signal registration would otherwise
    // fire its signal into an empty slot and park the caller forever (e.g. a
    // WINDOW_ADJUST routed just after WriteAsync observed a zero window).

    /// <summary>Stdout data is buffered (or MERGE stderr tail), or EOF/CLOSE.</summary>
    private bool HasStdoutDataOrEof()
    {
        lock (_windowLock)
        {
            return _stdoutBuffer.Count > 0
                || (_extendedDataMode == SshExtendedDataMode.Merge && _stderrBuffer.Count > 0)
                || _remoteEof
                || _remoteClose;
        }
    }

    /// <summary>Stderr data is buffered, or EOF/CLOSE arrived.</summary>
    private bool HasStderrDataOrEof()
    {
        lock (_windowLock)
        {
            return _stderrBuffer.Count > 0 || _remoteEof || _remoteClose;
        }
    }

    /// <summary>The outbound window has credit.</summary>
    private bool HasOutboundCredit()
    {
        lock (_windowLock)
        {
            return _outboundWindow != 0;
        }
    }

    /// <summary>The peer sent <c>SSH_MSG_CHANNEL_EOF</c>.</summary>
    private bool IsRemoteEofSet()
    {
        lock (_windowLock)
        {
            return _remoteEof;
        }
    }

    /// <summary>The peer sent <c>SSH_MSG_CHANNEL_CLOSE</c>.</summary>
    private bool IsRemoteCloseSet()
    {
        lock (_windowLock)
        {
            return _remoteClose;
        }
    }

    /// <summary>Exit info was captured, or the channel closed.</summary>
    private bool HasExitInfoOrClosed()
    {
        lock (_windowLock)
        {
            return _exitStatus.HasValue || _exitSignal is not null || _remoteClose;
        }
    }

    /// <summary>
    /// Sends a <c>SSH_MSG_CHANNEL_WINDOW_ADJUST</c> if the inbound window has
    /// dropped below <c>initial*3/4 + <paramref name="buflen"/></c> (parity
    /// <c>channel.c:2089-2107</c>). The adjustment refills the window to
    /// <c>initial + buflen</c>, floored to <see cref="ChannelConstants.MinAdjust"/>
    /// (<c>channel.c:2093-2096</c>).
    /// </summary>
    /// <remarks>
    /// <b>Claim-first adjustment.</b> The threshold check, the adjustment
    /// computation, and the <c>_inboundWindow +=</c> bump happen atomically
    /// under <see cref="_windowLock"/> BEFORE the send. Two concurrent readers
    /// on one channel therefore cannot both observe the same shortfall and
    /// double-adjust; the second claim sees the first claim's refreshed window.
    /// If the send fails, the claim is rolled back so the books stay exact.
    /// </remarks>
    private ValueTask EnsureInboundWindowAsync(int buflen, CancellationToken cancellationToken)
    {
        lock (_windowLock)
        {
            // channel.c:2090-2091 — remote.window_size < initial/4*3 + buflen.
            // An adequate window is the majority case; the WINDOW_ADJUST send
            // (network IO) is confined to the slow path.
            if (_inboundWindow >= _inboundWindowInitial / 4 * 3 + (uint)buflen)
            {
                return ValueTask.CompletedTask;
            }
        }

        return new ValueTask(EnsureInboundWindowSlowAsync(buflen, cancellationToken));
    }

    /// <summary>Slow path of <see cref="EnsureInboundWindowAsync"/>: sends a WINDOW_ADJUST packet (network IO).</summary>
    private async Task EnsureInboundWindowSlowAsync(int buflen, CancellationToken cancellationToken)
    {
        uint adjustment;
        lock (_windowLock)
        {
            // channel.c:2093-2094 — adjustment = initial + buflen - window.
            adjustment = _inboundWindowInitial + (uint)buflen - _inboundWindow;
            if (adjustment < ChannelConstants.MinAdjust)
            {
                // channel.c:2095-2096 — floor to MINADJUST.
                adjustment = ChannelConstants.MinAdjust;
            }

            // channel.c:1925 — channelp->remote.window_size += adjustment
            // (claimed up front; rolled back if the send below fails).
            _inboundWindow += adjustment;
        }

        try
        {
            await SendWindowAdjustAsync(adjustment, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            lock (_windowLock)
            {
                _inboundWindow -= adjustment;
            }

            throw;
        }
    }

    /// <summary>
    /// Sends <c>[93 CHANNEL_WINDOW_ADJUST][u32 remote.id][u32 adjustment]</c>
    /// (parity <c>channel.c:1900-1912</c>).
    /// </summary>
    private Task SendWindowAdjustAsync(uint adjustment, CancellationToken cancellationToken)
        => _writer.WriteWindowAdjustPacketAsync(RemoteId, adjustment, cancellationToken);

    /// <summary>
    /// Copies as many unread stdout bytes as fit into <paramref name="dest"/>,
    /// consuming them from <see cref="_stdoutBuffer"/> (advancing
    /// <see cref="_stdoutHeadOffset"/> across packet boundaries). Mirrors the
    /// per-packet copy loop in <c>_libssh2_channel_read</c>
    /// (<c>channel.c:2118-2205</c>).
    /// </summary>
    /// <returns>Bytes copied (0 if the buffer was empty).</returns>
    private int DrainStdoutInto(Span<byte> dest)
    {
        int total = 0;
        while (total < dest.Length && _stdoutBuffer.Count > 0)
        {
            DataSegment front = _stdoutBuffer.Peek();
            int available = front.Length - _stdoutHeadOffset;
            int toCopy = Math.Min(available, dest.Length - total);
            front.Buffer.AsSpan(front.Start + _stdoutHeadOffset, toCopy)
                .CopyTo(dest.Slice(total, toCopy));
            _stdoutHeadOffset += toCopy;
            total += toCopy;

            if (_stdoutHeadOffset >= front.Length)
            {
                _stdoutBuffer.Dequeue();
                _stdoutHeadOffset = 0;
            }
        }

        return total;
    }

    /// <summary>
    /// Same as <see cref="DrainStdoutInto"/> but for the stderr FIFO
    /// (<see cref="_stderrBuffer"/> / <see cref="_stderrHeadOffset"/>). Used by
    /// <see cref="ReadStderrAsync"/> and by <see cref="ReadAsync"/> in
    /// <see cref="SshExtendedDataMode.Merge"/> mode.
    /// </summary>
    private int DrainStderrInto(Span<byte> dest)
    {
        int total = 0;
        while (total < dest.Length && _stderrBuffer.Count > 0)
        {
            DataSegment front = _stderrBuffer.Peek();
            int available = front.Length - _stderrHeadOffset;
            int toCopy = Math.Min(available, dest.Length - total);
            front.Buffer.AsSpan(front.Start + _stderrHeadOffset, toCopy)
                .CopyTo(dest.Slice(total, toCopy));
            _stderrHeadOffset += toCopy;
            total += toCopy;

            if (_stderrHeadOffset >= front.Length)
            {
                _stderrBuffer.Dequeue();
                _stderrHeadOffset = 0;
            }
        }

        return total;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Write stdout — _libssh2_channel_write (channel.c:2336-2468)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Writes <paramref name="data"/> (stdin) to the channel, splitting it across
    /// as many <c>SSH_MSG_CHANNEL_DATA</c> packets as the peer's window and max
    /// packet size require. Blocks (pumping the transport for
    /// <c>WINDOW_ADJUST</c>s) when the outbound window is exhausted. Returns when
    /// all of <paramref name="data"/> has been sent.
    /// </summary>
    /// <remarks>
    /// <b>Outbound window maintenance is automatic.</b> Each sent chunk
    /// decrements <c>_outboundWindow</c> (libssh2 <c>local.window_size</c>,
    /// <c>channel.c:2448</c>); when it reaches 0 the method pumps the transport
    /// until the peer's <c>WINDOW_ADJUST</c> (<c>packet.c:1306-1325</c>) refills
    /// it. Callers never manage the send window. Per-chunk size is capped at
    /// <see cref="ChannelConstants.WriteChunkCap"/> (32700), the peer's max
    /// packet, and the current window (parity <c>channel.c:2351, 2405, 2413</c>).
    /// </remarks>
    /// <param name="data">The bytes to send.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => WriteDataAsync(streamId: 0, data, cancellationToken);

    /// <summary>
    /// Writes <paramref name="data"/> as stderr
    /// (<c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> with
    /// <c>data_type_code=SSH_EXTENDED_DATA_STDERR</c>). Mirrors
    /// <c>_libssh2_channel_write</c> with <c>stream_id=SSH_EXTENDED_DATA_STDERR</c>
    /// (<c>channel.c:2336-2468</c>; <c>channel.c:2397-2401</c> emits
    /// <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c> + a <c>[u32 data_type_code]</c> field
    /// when <c>stream_id != 0</c>). Same window/max-packet chunking as
    /// <see cref="WriteAsync"/>. Note that RFC 4254 §5.2 only specifies extended
    /// data for server→client on session channels — most servers ignore this.
    /// </summary>
    /// <param name="data">The bytes to send as stderr.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public Task WriteStderrAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => WriteDataAsync(streamId: ChannelConstants.StreamIdStderr, data, cancellationToken);

    /// <summary>
    /// The shared <c>_libssh2_channel_write</c> core
    /// (<c>channel.c:2336-2468</c>): splits <paramref name="data"/> across as
    /// many <c>SSH_MSG_CHANNEL_DATA</c> / <c>SSH_MSG_CHANNEL_EXTENDED_DATA</c>
    /// packets as the peer's window and max-packet size require, pumping the
    /// transport for <c>WINDOW_ADJUST</c>s when the outbound window is
    /// exhausted. When <paramref name="streamId"/> is non-zero, each packet is
    /// <c>EXTENDED_DATA</c> with the <c>[u32 data_type_code]</c> field set to
    /// <paramref name="streamId"/> (parity <c>channel.c:2397-2401</c>); else it
    /// is plain <c>CHANNEL_DATA</c>.
    /// </summary>
    /// <param name="streamId">0 for stdout (<c>SSH_MSG_CHANNEL_DATA</c>); non-zero
    /// for extended data (e.g. <see cref="ChannelConstants.StreamIdStderr"/> = 1).</param>
    /// <param name="data">The bytes to send.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="SshException"><see cref="SshErrorCode.ChannelClosed"/>
    /// if the close handshake has completed; <see cref="SshErrorCode.ChannelEofSent"/>
    /// if <see cref="SendEofAsync"/> has been called.</exception>
    private async Task WriteDataAsync(
        int streamId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        // channel.c:2362-2370 — refuse writes after close / EOF.
        if (_localClose)
        {
            throw new SshException(SshErrorCode.ChannelClosed,
                "Cannot write: this channel has already been closed.");
        }

        if (_localEof)
        {
            throw new SshException(SshErrorCode.ChannelEofSent,
                "Cannot write: EOF has already been sent; data might be ignored by the peer.");
        }

        // A post-open channel always has a non-zero max packet; reaching here
        // with zero means the channel was not opened (programming error).
        if (_outboundMaxPacket == 0)
        {
            throw new InvalidOperationException("Cannot write: channel is not open.");
        }

        // channel.c:2476-2485 — the blocking wrapper loops _libssh2_channel_write
        // until the whole buffer is sent. Each iteration sends at most one packet
        // (capped by window/packet-size) and decrements the outbound window.
        int offset = 0;
        while (offset < data.Length)
        {
            // channel.c:2383-2393 — if the outbound window is exhausted, drain the
            // incoming flow to pick up a pending WINDOW_ADJUST. PumpOnce may route
            // a non-ADJUST packet (e.g. DATA for another channel), so loop until
            // OUR window is non-zero.
            int chunk;
            while (true)
            {
                // Reserve-first write: the chunk computation and the
                // window decrement are one atomic step under _windowLock — a
                // WINDOW_ADJUST routed by the pumper between computing the
                // chunk and decrementing can no longer be lost, and a send
                // failure rolls the reservation back so the books stay exact.
                lock (_windowLock)
                {
                    if (_outboundWindow == 0)
                    {
                        chunk = 0;
                    }
                    else
                    {
                        // channel.c:2351 — per-call cap (32K-ish, RFC 4253 §6.1 conservative).
                        chunk = Math.Min(data.Length - offset, ChannelConstants.WriteChunkCap);
                        // channel.c:2405,2413 — do not exceed the peer's window or max packet.
                        chunk = (int)Math.Min(chunk, _outboundWindow);
                        chunk = (int)Math.Min(chunk, _outboundMaxPacket);

                        // channel.c:2448 — local.window_size -= bufwrite (reserved).
                        _outboundWindow -= (uint)chunk;
                    }
                }

                if (chunk > 0)
                {
                    break;
                }

                // channel.c:2374-2376 — drain incoming flow.
                await _router.WaitForStateChangeAsync(this, HasOutboundCredit, cancellationToken)
                    .ConfigureAwait(false);
            }

            // channel.c:2397-2399, 2423 — send the CHANNEL_DATA or
            // EXTENDED_DATA packet (the type and presence of the data_type_code
            // field depend on stream_id). The writer frames the short header
            // directly into its reused frame buffer, so no intermediate
            // payload array is allocated (or copied) per chunk.
            try
            {
                await _writer.WriteChannelDataPacketAsync(
                    streamId, RemoteId, data.Slice(offset, chunk), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch
            {
                // Send failed — give the reserved window back.
                lock (_windowLock)
                {
                    _outboundWindow += (uint)chunk;
                }

                throw;
            }

            offset += chunk;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Close — _libssh2_channel_close (channel.c:2646-2727)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Closes the channel: sends <c>SSH_MSG_CHANNEL_EOF</c> (if not already
    /// sent), then <c>SSH_MSG_CHANNEL_CLOSE</c>, and waits for the peer's
    /// <c>SSH_MSG_CHANNEL_CLOSE</c>. Mirrors <c>_libssh2_channel_close</c>
    /// (<c>channel.c:2646-2727</c>) and the cleanup half of
    /// <c>_libssh2_channel_free</c> (<c>channel.c:2825-2888</c>: unregisters the
    /// channel so stray packets are dropped).
    /// </summary>
    /// <remarks>
    /// The EOF send happens <i>inside</i> close (matching
    /// <c>channel.c:2658-2667</c>), so callers do not need a separate
    /// <c>SendEofAsync</c> call; libssh2's <c>_libssh2_channel_close</c> always sends
    /// EOF-if-not-sent first. Idempotent: a second <see cref="DisposeAsync"/> is
    /// a no-op (<c>channel.c:2651-2656</c>).
    /// </remarks>
    public async ValueTask DisposeAsync()
    {
        // Atomic dispose-started guard (see _disposeStarted) — a second
        // concurrent disposer must not re-run the teardown. The _localClose
        // check below alone is insufficient: it is only set at the END of the
        // teardown, so a plain check-then-set let both disposers through.
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            return;
        }

        if (_localClose)
        {
            // channel.c:2651-2656 — already closed; act like we sent another close.
            return;
        }

        // channel.c:2658-2667 — send EOF if we haven't already (best-effort:
        // an EOF-send failure proceeds to CLOSE anyway, parity channel.c:2664-2665).
        // SendEofAsync is now idempotent and owns the _localEof flag.
        if (!_localEof)
        {
            try
            {
                await SendEofAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (SshException)
            {
                // "Unable to send EOF, but closing channel anyway" (channel.c:2664-2665).
                // Mark _localEof anyway so the close path doesn't retry — parity
                // with the C fall-through that sets local.eof regardless.
                _localEof = true;
            }
        }

        // channel.c:2676-2684 — send CHANNEL_CLOSE (best-effort on send error;
        // skip the wait and fall through, parity channel.c:2691-2697).
        bool closeSent = true;
        try
        {
            await SendCloseAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (SshException)
        {
            closeSent = false;
        }

        // channel.c:2703-2708 — wait for the peer's CHANNEL_CLOSE. Only when we
        // successfully sent our own CLOSE; otherwise the peer may never reply.
        // IAsyncDisposable.DisposeAsync has no CancellationToken; use None (the
        // close handshake is not user-cancellable — parity with libssh2).
        if (closeSent)
        {
            while (!_remoteClose)
            {
                try
                {
                    await _router.WaitForStateChangeAsync(this, IsRemoteCloseSet, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (SshException)
                {
                    // Transport gone (SocketDisconnect) — stop waiting.
                    break;
                }
            }
        }

        // channel.c:2714 — local.close = 1 (the handshake is complete, or we
        // gave up waiting).
        _localClose = true;

        // channel.c:2857-2873 — unregister so subsequent packets for this channel
        // are dropped (the router no longer knows it).
        _router.Unregister(this);

        // Release the request-serialization semaphore. Same pattern as
        // PacketWriter's _writeLock: new request cycles after dispose fail fast
        // on the _localClose guard before reaching the lock; a request that
        // checked _localClose just before the dispose parked on the lock stays
        // parked until its token cancels (the teardown above waits for no
        // in-flight request — acceptable, mirroring the C's single-threaded
        // close, where no concurrent request can exist).
        _requestLock.Dispose();
    }

    // ── EOF / CLOSE public surface ──────────────────────
    //   channel_send_eof    (channel.c:2495-2519)
    //   libssh2_channel_eof (channel.c:2543-2578)
    //   channel_wait_eof    (channel.c:2585-2627)
    //   channel_wait_closed (channel.c:2751-2788)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Sends <c>[96 SSH_MSG_CHANNEL_EOF][u32 remote.id]</c> to the peer
    /// (parity <c>libssh2_channel_send_eof</c> → <c>channel_send_eof</c>,
    /// <c>channel.c:2495-2519</c>) and sets <see cref="_localEof"/>
    /// (<c>channel.c:2516</c>). Idempotent: subsequent calls are no-ops if EOF
    /// has already been sent. After EOF, further
    /// <see cref="WriteAsync"/>/<see cref="WriteStderrAsync"/> calls throw
    /// <see cref="SshErrorCode.ChannelEofSent"/>.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public async Task SendEofAsync(CancellationToken cancellationToken = default)
    {
        // Idempotent — parity with channel.c:2516 (local.eof set on first success).
        if (_localEof)
        {
            return;
        }

        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelEof;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), RemoteId);
        await _writer.WritePacketAsync(PacketType.ChannelEof, payload, cancellationToken)
            .ConfigureAwait(false);

        // channel.c:2516 — local.eof = 1 (set only after the send succeeds).
        _localEof = true;
    }

    /// <summary>
    /// Whether the channel is at EOF from the peer's perspective. Returns
    /// <c>true</c> only when the peer has sent <c>SSH_MSG_CHANNEL_EOF</c> AND no
    /// unread stdout/stderr data remains in the local buffers. Mirrors
    /// <c>libssh2_channel_eof</c> (<c>channel.c:2543-2578</c>): the C walks the
    /// session packet list to mask EOF when buffered data exists; this port
    /// checks the per-channel FIFOs directly.
    /// </summary>
    public bool IsEof
    {
        // Locked — the FIFO counts are read concurrently with the
        // pumper's deliveries.
        get
        {
            lock (_windowLock)
            {
                return _remoteEof && _stdoutBuffer.Count == 0 && _stderrBuffer.Count == 0;
            }
        }
    }

    /// <summary>
    /// Blocks (pumping the transport) until the peer sends
    /// <c>SSH_MSG_CHANNEL_EOF</c>. Mirrors <c>libssh2_channel_wait_eof</c> →
    /// <c>channel_wait_eof</c> (<c>channel.c:2585-2627</c>). Returns immediately
    /// if <see cref="_remoteEof"/> is already set.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    public async Task WaitEofAsync(CancellationToken cancellationToken = default)
    {
        // channel.c:2602-2622 — while !remote.eof, read more packets.
        while (!_remoteEof)
        {
            // With the receive window exhausted (window_size ==
            // read_avail), the peer can never deliver the EOF — its data
            // credit is gone — so the C returns CHANNEL_WINDOW_FULL here
            // (channel.c:2607-2611). The pre-fix port blocked until the peer
            // EOF/CLOSE or cancellation: a wait for a packet that cannot
            // arrive.
            if (IsInboundWindowExhausted)
            {
                throw new SshException(SshErrorCode.ChannelWindowFull,
                    "Receiving channel window has been exhausted");
            }

            await _router.WaitForStateChangeAsync(this, IsRemoteEofSet, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Blocks (pumping the transport) until the peer sends
    /// <c>SSH_MSG_CHANNEL_CLOSE</c>. Mirrors <c>libssh2_channel_wait_closed</c>
    /// → <c>channel_wait_closed</c> (<c>channel.c:2751-2788</c>). Throws if the
    /// peer has not yet sent EOF (parity <c>channel.c:2756-2760</c>) — the close
    /// handshake only makes sense after EOF. The caller is expected to have
    /// called <see cref="SendEofAsync"/> and observed <see cref="WaitEofAsync"/>
    /// complete; <see cref="DisposeAsync"/> does all of this internally and is
    /// the more common entry point.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <exception cref="SshException">Thrown with <see cref="SshErrorCode.Inval"/>
    /// if <see cref="_remoteEof"/> is not set (parity <c>channel.c:2756-2760</c>).</exception>
    public async Task WaitClosedAsync(CancellationToken cancellationToken = default)
    {
        // channel.c:2756-2760 — !remote.eof → INVAL.
        if (!_remoteEof)
        {
            throw new SshException(SshErrorCode.Inval,
                "WaitClosedAsync invoked when channel is not in EOF state; " +
                "await WaitEofAsync first.");
        }

        // channel.c:2774-2783 — while !remote.close, read more packets.
        while (!_remoteClose)
        {
            await _router.WaitForStateChangeAsync(this, IsRemoteCloseSet, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    // ── Exit info ───────────────────────────────────────
    //   libssh2_channel_get_exit_status (channel.c:1788-1795)
    //   libssh2_channel_get_exit_signal (channel.c:1807-1858)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// The captured exit signal name (without the <c>SIG</c> prefix), or
    /// <c>null</c> if the process has not been killed by a signal. Set by the
    /// router from a <c>"exit-signal"</c> <c>SSH_MSG_CHANNEL_REQUEST</c>
    /// (<c>packet.c:1164-1183</c>); never blocks. Mirrors
    /// <c>libssh2_channel_get_exit_signal</c>'s signal-name output parameter
    /// (<c>channel.c:1807-1858</c>).
    /// </summary>
    public string? ExitSignal => _exitSignal;

    /// <summary>
    /// Waits for the process to terminate and returns its exit status. Pumps
    /// the transport until a <c>"exit-status"</c> or <c>"exit-signal"</c>
    /// <c>SSH_MSG_CHANNEL_REQUEST</c> arrives (captured internally by the
    /// router), or the peer sends
    /// <c>SSH_MSG_CHANNEL_CLOSE</c> (status defaults to 0). Returns immediately
    /// if the status/signal has already been captured.
    /// </summary>
    /// <remarks>
    /// <b>Diverges from libssh2.</b> The C <c>libssh2_channel_get_exit_status</c>
    /// (<c>channel.c:1788-1795</c>) is a non-blocking field read that returns 0
    /// when no status has arrived — the caller is expected to have called
    /// <c>libssh2_channel_wait_eof</c> first. This async version pumps the
    /// transport internally, matching the C#
    /// "async = await, never call .Result" contract; callers don't need to
    /// pre-wait. The returned value matches libssh2's semantics: 0 when the
    /// process exited cleanly or no status was captured.
    /// </remarks>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The process exit status (0 if none captured before channel
    /// close).</returns>
    public async Task<int> GetExitStatusAsync(CancellationToken cancellationToken = default)
    {
        // Pump until exit info arrives OR the channel closes (defensive: a peer
        // that closes without sending exit-status would otherwise hang).
        while (!_exitStatus.HasValue && _exitSignal is null && !_remoteClose)
        {
            await _router.WaitForStateChangeAsync(this, HasExitInfoOrClosed, cancellationToken)
                .ConfigureAwait(false);
        }

        return _exitStatus ?? 0;
    }

    // ── EOF / CLOSE senders (internal) ─────────────────────────────────────

    /// <summary>
    /// Sends <c>[97 SSH_MSG_CHANNEL_CLOSE][u32 remote.id]</c> (parity
    /// <c>channel.c:2676-2677</c>).
    /// </summary>
    private async Task SendCloseAsync(CancellationToken cancellationToken)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelClose;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), RemoteId);
        await _writer.WritePacketAsync(PacketType.ChannelClose, payload, cancellationToken)
            .ConfigureAwait(false);
    }
}
