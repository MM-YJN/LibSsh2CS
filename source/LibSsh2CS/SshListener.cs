using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;

using LibSsh2CS.Transport;

namespace LibSsh2CS;

/// <summary>
/// A remote TCP port forward listener. Mirrors libssh2's
/// <c>LIBSSH2_LISTENER</c> + <c>libssh2_channel_forward_listen_ex</c> /
/// <c>libssh2_channel_forward_cancel</c> / <c>libssh2_channel_forward_accept</c>
/// (<c>channel.c:541-874</c>). The listener holds a queue of incoming
/// <c>"forwarded-tcpip"</c> channels (populated by
/// <see cref="ChannelRouter"/> when the server sends a
/// <c>SSH_MSG_CHANNEL_OPEN "forwarded-tcpip"</c> for this listener's
/// <c>(host, port)</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Lifecycle.</b> Create via <see cref="SshSession.ListenForwardAsync"/>.
/// Callers <see cref="AcceptAsync">accept</see> incoming channels from the
/// queue; <see cref="DisposeAsync"/> sends
/// <c>cancel-tcpip-forward</c> to the server, drains the queue (disposing
/// each queued channel), and unregisters from the session.
/// </para>
/// <para>
/// <b>Handle base.</b> <see cref="IAsyncDisposable"/> (not
/// <see cref="IDisposable"/>) because <see cref="DisposeAsync"/> performs
/// network I/O (sending <c>cancel-tcpip-forward</c>). This matches
/// <see cref="SshSession"/> /
/// <see cref="SshChannel"/> / <see cref="Agent.SshAgent"/>.
/// </para>
/// <para>
/// <b>Bound port.</b> When the caller passes <c>port=0</c> to
/// <see cref="SshSession.ListenForwardAsync(string?, int, int, CancellationToken)"/>,
/// the server assigns a port and returns it in the <c>REQUEST_SUCCESS</c>
/// body (a u32). <see cref="BoundPort"/> exposes this server-assigned value.
/// </para>
/// </remarks>
public sealed class SshListener : IAsyncDisposable
{
    // Back-reference to the owning session — used to send cancel-tcpip-forward
    // on Dispose and to look up the writer/router when constructing inbound
    // channels. Stored weakly? No — libssh2 keeps a strong ref
    // (listener->session) and the listener is unregistered from the session
    // on Dispose, so the cycle is broken by explicit teardown.
    private readonly SshSession _session;
    private readonly string _host;
    private readonly int _port;       // set from reply body when caller passes 0
    private readonly int _queueMaxSize;

    private readonly ConcurrentQueue<SshChannel> _acceptQueue = new();
    // SemaphoreSlim(0, int.MaxValue): counts the number of unconsumed
    // TryEnqueueAccept signals. Each Enqueue releases 1; each AcceptAsync
    // consumes 1 via WaitAsync. The unbounded max lets TryEnqueueAccept
    // Release() up to QueueMaxSize times without overflow; the queue itself
    // enforces QueueMaxSize. Dispose() releases once per parked AcceptAsync
    // waiter (tracked by _acceptWaiters under _acceptGate) so every waiter
    // observes IsDisposed instead of hanging forever on a disposed semaphore.
    private readonly SemaphoreSlim _acceptSignal = new(0, int.MaxValue);
    private readonly object _acceptGate = new();
    private int _acceptWaiters;
    private bool _disposed;

    /// <summary>
    /// Internal constructor — listeners are created exclusively by
    /// <see cref="SshSession.ListenForwardAsync"/>. The <paramref name="port"/>
    /// passed here is the EFFECTIVE port (already replaced with the server-
    /// assigned port from the reply body when the caller originally passed 0).
    /// </summary>
    internal SshListener(SshSession session, string host, int port, int queueMaxSize)
    {
        _session = session;
        _host = host;
        _port = port;
        _queueMaxSize = queueMaxSize;
    }

    /// <summary>The host the listener is bound to on the server side.</summary>
    public string Host => _host;

    /// <summary>
    /// The port the listener is bound to. When the caller passed
    /// <c>port=0</c> to <see cref="SshSession.ListenForwardAsync(string?, int, int, CancellationToken)"/>,
    /// this is the server-assigned port (parsed from the
    /// <c>REQUEST_SUCCESS</c> body).
    /// </summary>
    public int BoundPort => _port;

    /// <summary>
    /// The maximum number of un-Accept()ed channels that may be queued before
    /// the router starts refusing inbound <c>"forwarded-tcpip"</c> opens with
    /// <c>SSH_OPEN_RESOURCE_SHORTAGE</c> (parity <c>packet.c:147-155</c>).
    /// </summary>
    public int QueueMaxSize => _queueMaxSize;

    /// <summary>Number of channels currently waiting in the accept queue.</summary>
    public int QueuedCount => _acceptQueue.Count;

    /// <summary>True after <see cref="DisposeAsync"/> has been called.</summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Returns <c>true</c> if the accept queue has room for one more channel.
    /// <c>queueMaxSize == 0</c> means unlimited (parity with packet.c:147-148's
    /// <c>queue_maxsize &amp;&amp; queue_maxsize &lt;= queue_size</c> guard — the
    /// C idiom where 0 disables the limit).
    /// </summary>
    internal bool CanAcceptMore()
        => _queueMaxSize == 0 || _acceptQueue.Count < _queueMaxSize;

    /// <summary>
    /// Enqueues an incoming <c>"forwarded-tcpip"</c> channel for the next
    /// AcceptAsync call. Internal — called by <see cref="ChannelRouter"/>'s
    /// inbound-dispatch path (parity <c>packet.c:233-238</c>).
    /// </summary>
    /// <remarks>
    /// Returns false (and leaves the channel un-enqueued) when the queue is at
    /// <see cref="QueueMaxSize"/> (and the limit is non-zero); the router
    /// refuses the inbound open with <c>SSH_OPEN_RESOURCE_SHORTAGE</c> BEFORE
    /// sending a confirmation (parity with the C's pre-allocation capacity
    /// check at packet.c:147-155).
    /// </remarks>
    internal bool TryEnqueueAccept(SshChannel channel)
    {
        // Guard against the dispose/dispatch race: DisposeAsync unregisters
        // from the session before disposing the semaphore, but a router
        // dispatch already in flight can still reach us.
        if (_disposed || !CanAcceptMore())
        {
            return false;
        }

        _acceptQueue.Enqueue(channel);
        // Release one waiter in AcceptAsync (if any). SemaphoreSlim.Release
        // throws if the count would exceed the initial count (1) — that does
        // NOT happen here because we use WaitAsync(0)/try-pattern in Accept.
        // Instead we use a no-block release that simply signals "state
        // changed".
        _acceptSignal.Release();
        return true;
    }

    /// <summary>
    /// Accepts the next incoming <c>"forwarded-tcpip"</c> channel from the
    /// queue. Mirrors <c>libssh2_channel_forward_accept</c>
    /// (<c>channel.c:822-856</c>). Blocks if the queue is empty until either
    /// a channel arrives (via <see cref="TryEnqueueAccept"/>) or the
    /// cancellation token fires.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    /// <returns>The next incoming channel from the queue.</returns>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.ChannelUnknown"/> if the listener is disposed
    /// while waiting.</exception>
    public async Task<SshChannel> AcceptAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (_acceptQueue.TryDequeue(out SshChannel? channel))
            {
                return channel;
            }

            if (_disposed)
            {
                throw new SshException(SshErrorCode.ChannelUnknown,
                    "Listener was disposed while waiting for an incoming channel.");
            }

            // Park until TryEnqueueAccept signals. The semaphore counts up by
            // 1 per enqueued channel; we consume 1 per dequeue attempt. We
            // use WaitAsync() — if the queue already has a backlog, this
            // returns immediately. The waiter count and the WaitAsync
            // registration are done under _acceptGate so DisposeAsync can
            // atomically mark _disposed and release every parked waiter
            // without racing a new waiter into a disposed semaphore.
            Task waitTask;
            lock (_acceptGate)
            {
                if (_disposed)
                {
                    throw new SshException(SshErrorCode.ChannelUnknown,
                        "Listener was disposed while waiting for an incoming channel.");
                }

                _acceptWaiters++;
                try
                {
                    waitTask = _acceptSignal.WaitAsync(cancellationToken);
                }
                catch
                {
                    _acceptWaiters--;
                    throw;
                }
            }

            try
            {
                await waitTask.ConfigureAwait(false);
            }
            finally
            {
                lock (_acceptGate)
                {
                    _acceptWaiters--;
                }
            }
        }
    }

    /// <summary>
    /// Stops the listener: sends <c>SSH_MSG_GLOBAL_REQUEST "cancel-tcpip-forward"</c>
    /// with <c>want_reply=0</c>, drains the accept queue (disposing each
    /// queued channel), and unregisters from the session. Mirrors
    /// <c>_libssh2_channel_forward_cancel</c> (<c>channel.c:718-798</c>).
    /// Safe to call multiple times — subsequent calls are no-ops.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        lock (_acceptGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            // Wake every parked AcceptAsync waiter so they observe IsDisposed.
            // A single Release would leave all but one parked forever on a
            // disposed SemaphoreSlim.
            for (int i = 0; i < _acceptWaiters; i++)
            {
                _acceptSignal.Release();
            }
        }

        // Unregister from the session FIRST so the router can no longer
        // dispatch inbound opens into this listener — previously the registry
        // entry outlived the semaphore (disposed below), so a racing inbound
        // open could Release a disposed SemaphoreSlim from inside the pump. TryEnqueueAccept also guards _disposed.
        _session.UnregisterListener(this);

        // Send cancel-tcpip-forward (channel.c:743-749). want_reply=0 —
        // fire-and-forget per libssh2. UTF-8 encode (the C sends raw bytes).
        byte[] hostBytes = Encoding.UTF8.GetBytes(_host);
        byte[] extra = new byte[4 + hostBytes.Length + 4];
        int o = 0;
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), hostBytes.Length);
        o += 4;
        Buffer.BlockCopy(hostBytes, 0, extra, o, hostBytes.Length);
        o += hostBytes.Length;
        BinaryPrimitives.WriteInt32BigEndian(extra.AsSpan(o, 4), _port);

        try
        {
            await _session.SendGlobalRequestAsync(
                name: "cancel-tcpip-forward",
                extra: extra,
                wantReply: false,
                cancellationToken: CancellationToken.None).ConfigureAwait(false);
        }
        catch (SshException)
        {
            // Parity channel.c:770-774 — even if the send fails, the listener
            // is still torn down locally (queue drained + unregistered).
        }

        // Drain + dispose queued channels (channel.c:780-789).
        while (_acceptQueue.TryDequeue(out SshChannel? ch))
        {
            try
            {
                await ch.DisposeAsync().ConfigureAwait(false);
            }
            catch (SshException) { }
        }

        _acceptSignal.Dispose();
    }
}
