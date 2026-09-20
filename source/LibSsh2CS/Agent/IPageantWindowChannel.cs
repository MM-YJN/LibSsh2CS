namespace LibSsh2CS.Agent;

/// <summary>
/// The native Pageant request surface used by <see cref="PageantAgentTransport"/>.
/// This is the seam between the managed agent protocol and the Windows
/// window-message mechanism, and the only place <see cref="PageantIpc"/> is
/// reached from.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the seam exists.</b> The transport owns everything that can be
/// checked without Windows — payload size limits, error mapping, cancellation
/// and connection state — so those rules stay unit-testable on every platform.
/// Everything that genuinely needs Windows (window discovery, shared memory,
/// <c>WM_COPYDATA</c>) lives behind this interface. The IPC integration tests
/// additionally use the window class and title constructor arguments of
/// <see cref="PageantWindowChannel"/> to point the real implementation at a
/// purpose-built test window, so they never touch the developer's Pageant.
/// </para>
/// <para>
/// <b>Calling convention.</b> <see cref="Transact"/> is deliberately
/// synchronous and completion-bound: the underlying native send blocks until
/// the receiver's window procedure has processed the message (or the window is
/// gone), and it cannot be interrupted. Callers must run it off any thread that
/// has to stay responsive — <see cref="PageantAgentTransport"/> does so through
/// the thread pool and bounds only its own wait — and must treat an abandoned
/// in-flight call as still executing until it returns on its own: it owns the
/// mapping and the message data until then, and Pageant may still read them.
/// Only one call may be outstanding at a time, so a caller that follows an
/// abandoned one waits for it to return instead of starting another.
/// </para>
/// </remarks>
internal interface IPageantWindowChannel
{
    /// <summary>
    /// Returns the Pageant window handle, or <c>0</c> when Pageant is not
    /// running. Called both at connect time and before every transaction,
    /// matching <c>agent_transact_pageant</c>'s rediscovery
    /// (<c>agent.c:362</c>) so a restarted Pageant is picked up.
    /// </summary>
    nint FindWindow();

    /// <summary>
    /// Performs one blocking request/response round trip through Pageant's
    /// shared mapping: create the mapping named after the calling thread, write
    /// <c>[4-byte big-endian length][payload]</c>, send <c>WM_COPYDATA</c>, read
    /// the response length and payload back, then release the mapping. The send
    /// returns only after the receiver's window procedure has finished with the
    /// request; the mapping is released only then, because Pageant may still be
    /// reading it.
    /// </summary>
    /// <param name="requestPayload">
    /// The agent request payload (message type byte + body). The length prefix
    /// is added by the implementation, because the prefix is part of the
    /// mapping layout Pageant expects.
    /// </param>
    /// <returns>The response payload without its length prefix.</returns>
    /// <exception cref="SshException">
    /// Thrown with <see cref="SshErrorCode.AgentProtocol"/> when Pageant is
    /// missing, rejects the request, or returns an unusable response, and with
    /// <see cref="SshErrorCode.Inval"/> when the payload cannot fit the
    /// mapping.
    /// </exception>
    byte[] Transact(ReadOnlyMemory<byte> requestPayload);
}
