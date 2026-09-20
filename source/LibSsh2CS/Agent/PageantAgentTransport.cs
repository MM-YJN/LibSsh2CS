// Translated from the Pageant client code in libssh2 src/agent.c.
// See LICENSE and THIRD-PARTY-NOTICES.md for project and upstream terms.
/*
 * Code to talk to Pageant was taken from PuTTY.
 *
 * Portions copyright Robert de Bath, Joris van Rantwijk, Delian
 * Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas
 * Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa,
 * Markus Kuhn, Colin Watson, and CORE SDI S.A.
 */

using System.Buffers;
using System.Runtime.Versioning;

namespace LibSsh2CS.Agent;

/// <summary>
/// SSH agent transport over PuTTY's Pageant window protocol on Windows. Parity
/// with <c>agent_ops_pageant</c> (<c>agent.c:426-430</c>), the first backend in
/// <c>supported_backends[]</c> on Windows (<c>agent.c:436-440</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Transport shape.</b> Pageant is not a stream: there is no connection to
/// hold open, and each request is a complete round trip through
/// <c>WM_COPYDATA</c> and a per-thread file mapping (see
/// <see cref="PageantWindowChannel"/>). <see cref="ConnectAsync"/> therefore only
/// checks that a Pageant window exists, and <see cref="DisconnectAsync"/> only
/// clears that state — there is nothing to close.
/// </para>
/// <para>
/// <b>Size limit.</b> A request payload is limited to
/// <see cref="PageantIpc.MaxPayloadLength"/> (8188) bytes, and a
/// response is rejected unless it is between 1 and 8188 bytes; both bounds keep
/// the shared mapping from being overrun in either direction.
/// </para>
/// <para>
/// <b>Blocking and cancellation.</b> The native send runs on a thread-pool
/// thread, never on the caller's thread (which may be a UI thread that must
/// keep pumping messages). The send itself cannot be interrupted — Pageant
/// holds a reference to the shared mapping until its window procedure
/// returns — so a timeout (<see cref="DefaultTransactionTimeout"/>) or a
/// cancellation releases the waiting caller only: the worker keeps the
/// request, the mapping, and the message data alive until the native send
/// returns, then releases them, and its response is discarded. Pageant may
/// still act on the request it already received and the transaction is not
/// retried automatically. Only one native send is outstanding across all
/// transports, including reconnects and separate agents: a later request waits
/// for that worker to return — bounded by the same timeout — instead of
/// starting a second send, so repeated retries against a
/// Pageant that never answers cannot pile up workers, mappings, or pinned
/// message data. The timeout therefore bounds the caller, not the worker: a
/// Pageant that never returns can retain one worker and one mapping
/// until its window procedure returns or its process exits — the price of
/// never handing the receiver memory that is no longer valid.
/// </para>
/// <para>
/// <b>Discovery.</b> The window is looked up again on every transaction, so a
/// Pageant that restarts mid-session is picked up without reconnecting
/// (<c>agent.c:362-364</c>).
/// </para>
/// </remarks>
internal sealed class PageantAgentTransport : IAgentTransport
{
    /// <summary>
    /// How long a transaction waits — for an earlier request to finish and for
    /// Pageant to answer it — before its caller is released: five minutes.
    /// Pageant shows confirmation and passphrase prompts on its window thread,
    /// so the wait is generous; it is finite so a caller cannot be parked
    /// forever, and it bounds only the caller — the request itself stays alive
    /// until Pageant is done with it.
    /// </summary>
    internal static TimeSpan DefaultTransactionTimeout => TimeSpan.FromMinutes(5);

    private readonly IPageantWindowChannel _channel;
    private readonly TimeSpan _transactTimeout;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Admits one native round trip across all transports, including replacement
    /// transports created by reconnecting or by another SshAgent. An abandoned
    /// worker keeps the slot until its uninterruptible native send returns.
    /// </summary>
    // This shared gate outlives individual transports and must not be disposed:
    // queued callers and abandoned workers still need to acquire/release it.
    // AvailableWaitHandle is never used, so it owns no unmanaged resources.
    private static readonly SemaphoreSlim s_nativeRequestGate = new(1, 1);

    private bool _connected;
    private bool _disposed;

    /// <summary>
    /// Creates a transport bound to the real Pageant window. No native API is
    /// called until <see cref="ConnectAsync"/>; the Windows check happens in
    /// <see cref="TryCreate"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public PageantAgentTransport()
        : this(new PageantWindowChannel(), DefaultTransactionTimeout)
    {
    }

    /// <summary>
    /// Creates a transport over an explicit channel, using
    /// <see cref="DefaultTransactionTimeout"/>. Used by tests to drive
    /// failure, cancellation, and cleanup paths without a running Pageant.
    /// </summary>
    /// <param name="channel">The Pageant request surface to use.</param>
    internal PageantAgentTransport(IPageantWindowChannel channel)
        : this(channel, DefaultTransactionTimeout)
    {
    }

    /// <summary>
    /// Creates a transport over an explicit channel and transaction timeout.
    /// Used by tests that need the caller's bound to elapse quickly instead of
    /// waiting minutes for a peer that never answers.
    /// </summary>
    /// <param name="channel">The Pageant request surface to use.</param>
    /// <param name="transactTimeout">
    /// How long a transaction waits for an earlier request to finish and for
    /// Pageant to answer it.
    /// </param>
    /// <param name="timeProvider">Clock used for the transaction deadline.</param>
    internal PageantAgentTransport(
        IPageantWindowChannel channel, TimeSpan transactTimeout, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(transactTimeout, TimeSpan.Zero);

        _channel = channel;
        _transactTimeout = transactTimeout;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Returns a Pageant transport on Windows and <c>null</c> everywhere else,
    /// following the registry's factory convention (a <c>null</c> factory
    /// result means "this backend does not exist on this platform").
    /// </summary>
    internal static PageantAgentTransport? TryCreate()
        => OperatingSystem.IsWindows() ? new PageantAgentTransport() : null;

    /// <inheritdoc/>
    public Task ConnectAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (_connected)
        {
            throw new InvalidOperationException("PageantAgentTransport is already connected");
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (_channel.FindWindow() == 0)
        {
            // agent_connect_pageant returns LIBSSH2_ERROR_AGENT_PROTOCOL with
            // this message when no Pageant window is present (agent.c:343-346).
            throw new SshException(SshErrorCode.AgentProtocol, "failed connecting agent");
        }

        _connected = true;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public async Task TransactAsync(
        ReadOnlyMemory<byte> request,
        IBufferWriter<byte> responseWriter,
        CancellationToken cancellationToken)
    {
        // One deadline covers both queueing and the native response wait.
        using var deadline = new CancellationTokenSource(_transactTimeout, _timeProvider);
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, deadline.Token);
        CancellationToken waitToken = waitCancellation.Token;

        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(responseWriter);
        ThrowIfNotConnected();
        ThrowIfRequestTooLong(request.Length);

        cancellationToken.ThrowIfCancellationRequested();

        // Only one native round trip may be outstanding, because a send cannot
        // be interrupted and Pageant reaches for the same mapping until its
        // window procedure returns. A request that follows an abandoned
        // (timed-out or canceled) worker therefore waits for that worker to
        // return instead of starting a second send — which is what keeps a
        // Pageant that never answers from accumulating workers, mappings, and
        // pinned message data while callers keep retrying.
        await AcquireNativeRequestSlotAsync(waitToken, cancellationToken).ConfigureAwait(false);

        try
        {
            // Re-check what another caller may have changed while this request
            // waited for the slot.
            ThrowIfDisposed();
            ThrowIfNotConnected();
            ThrowIfRequestTooLong(request.Length);
            cancellationToken.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested)
            {
                throw CreateTimeoutException();
            }
        }
        catch
        {
            // No worker was started, so the slot is this caller's to return.
            s_nativeRequestGate.Release();
            throw;
        }

        // The caller's payload may be pooled storage that is released as soon
        // as this method returns, and a timeout or cancellation returns before
        // the worker is done — so the worker gets its own copy.
        byte[] payload = request.ToArray();

        // The native round trip owns the mapping and the message data until it
        // returns, so the worker outlives a caller that stopped waiting: a
        // timeout or cancellation abandons the wait, never the call. The
        // receiver can reach the request only while the send is running, so
        // the worker must not be interrupted — and the slot it holds is handed
        // on when the send returns, not when its caller stops waiting.
        Task<byte[]> worker = Task.Run(() => _channel.Transact(payload), CancellationToken.None);
        _ = worker.ContinueWith(
            static (completedWorker, state) =>
            {
                // Observe a late fault so an abandoned worker cannot surface as
                // an unobserved task exception, then admit the next request.
                _ = completedWorker.Exception;
                ((SemaphoreSlim)state!).Release();
            },
            s_nativeRequestGate,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

        byte[] response;
        try
        {
            response = await worker.WaitAsync(waitToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The worker keeps the request and its slot until the native send
            // returns; only this caller stops waiting.
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            // The caller's bound elapsed while the request is already in
            // Pageant's hands. The worker keeps running (and keeps the
            // receiver-visible state alive) until the native send returns, so
            // only the wait is abandoned; a late response is discarded.
            throw CreateTimeoutException();
        }

        // Cancellation that arrived while the worker was running is observed
        // here, before the caller sees any part of the response.
        cancellationToken.ThrowIfCancellationRequested();

        responseWriter.Write(response);
    }

    /// <summary>
    /// Waits for the previous native round trip to finish, if one is still
    /// outstanding, so only one <c>WM_COPYDATA</c> send is ever in flight.
    /// Waiting out the transaction timeout fails the caller instead of parking
    /// it behind a Pageant that never answers.
    /// </summary>
    private async Task AcquireNativeRequestSlotAsync(
        CancellationToken waitToken, CancellationToken cancellationToken)
    {
        try
        {
            await s_nativeRequestGate.WaitAsync(waitToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
        catch (OperationCanceledException)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"an earlier pageant request is still outstanding after {(long)_transactTimeout.TotalMilliseconds} ms",
                new TimeoutException());
        }
    }

    private SshException CreateTimeoutException()
        => new(SshErrorCode.AgentProtocol,
            $"pageant did not answer within {(long)_transactTimeout.TotalMilliseconds} ms",
            new TimeoutException());

    private void ThrowIfNotConnected()
    {
        if (!_connected)
        {
            throw new InvalidOperationException("Transport not connected");
        }
    }

    /// <summary>
    /// Enforces the bound the request shares with Pageant's mapping:
    /// <c>agent_transact_pageant</c> returns <c>LIBSSH2_ERROR_INVAL</c> for
    /// <c>4 + request_len &gt; PAGEANT_MAX_MSGLEN</c> (<c>agent.c:357-360</c>).
    /// </summary>
    private static void ThrowIfRequestTooLong(int requestLength)
    {
        if (requestLength > PageantIpc.MaxPayloadLength)
        {
            throw new SshException(SshErrorCode.Inval,
                $"Agent request too long ({requestLength + sizeof(uint)} > {PageantIpc.MaxMessageLength})");
        }
    }

    /// <inheritdoc/>
    public Task DisconnectAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        // agent_disconnect_pageant only resets the handle (agent.c:420-424):
        // Pageant holds no per-client state, so a later connect simply finds
        // the window again.
        _connected = false;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        // No unmanaged state is held between transactions, so an in-flight
        // worker keeps the mapping it created and releases it on its own — and
        // the native-request slot with it. A caller already queued behind that
        // worker never starts a send: it observes the disposed state when the
        // slot is granted.
        _disposed = true;
        _connected = false;
        return ValueTask.CompletedTask;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
