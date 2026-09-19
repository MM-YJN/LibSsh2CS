using System.Buffers;

namespace LibSsh2CS.Agent;

/// <summary>
/// The byte-transport abstraction underlying <see cref="SshAgent"/>.
/// Implementations provide a single request/response round-trip over a
/// backend-specific transport (Unix domain socket today; Windows Pageant and
/// Windows OpenSSH named-pipe later). Parity with libssh2's <c>agent_ops</c>
/// vtable (<c>agent.c:130-146</c>): <c>connect</c> / <c>transact</c> /
/// <c>disconnect</c>.
/// </summary>
/// <remarks>
/// <para>
/// The agent SSH protocol payload (4-byte length prefix + message body, types
/// 11/12/13/14) is <b>identical across all backends</b>. Only the byte transport
/// differs. This is why the abstraction lives at the transport level (not the
/// full agent level) — every backend implements the same 3-method surface and
/// the protocol logic centralizes in <see cref="SshAgent"/> + <see cref="AgentProtocol"/>.
/// </para>
/// <para>
/// <b>Pageant caveat.</b> The Windows Pageant backend is request/response via
/// <c>WM_COPYDATA</c> + file mapping — not a stream. Modeling the abstraction
/// as <c>TransactAsync(request) → response</c> (rather than as
/// <c>System.IO.Pipelines.IDuplexPipe</c>) accommodates Pageant honestly:
/// each backend may batch the entire round-trip internally if it cannot honor
/// streaming read/write.
/// </para>
/// <para>
/// <b>Concurrency.</b> Implementations are not required to be internally
/// synchronized — <see cref="SshAgent"/> serializes every transaction via a
/// <see cref="SemaphoreSlim"/> (matching libssh2's single-socket assumption).
/// </para>
/// </remarks>
internal interface IAgentTransport : IAsyncDisposable
{
    /// <summary>
    /// Connects to the backend. Throws <see cref="SshException"/> with
    /// <see cref="SshErrorCode.AgentProtocol"/> (or a more specific code) on
    /// failure. Mirrors <c>agent_ops.connect</c>.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    Task ConnectAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Sends a complete request payload and reads back the complete response
    /// payload. The payloads <b>exclude</b> the 4-byte length prefix — the
    /// transport implementation adds/strips it (parity with
    /// <c>agent_transact_func</c>). Throws <see cref="SshException"/> on
    /// I/O or protocol error.
    /// </summary>
    /// <param name="request">The full request payload (e.g. message type byte + body).</param>
    /// <param name="responseWriter">The writer to which the full response payload is written.</param>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    Task TransactAsync(
        ReadOnlyMemory<byte> request,
        IBufferWriter<byte> responseWriter,
        CancellationToken cancellationToken);

    /// <summary>
    /// Closes the backend connection gracefully. Mirrors <c>agent_ops.disconnect</c>.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation.</param>
    Task DisconnectAsync(CancellationToken cancellationToken);
}
