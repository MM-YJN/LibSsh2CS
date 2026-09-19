using System.Buffers;
using System.Buffers.Binary;
using System.Net.Sockets;

namespace LibSsh2CS.Agent;

/// <summary>
/// SSH agent transport over a POSIX Unix domain socket
/// (<c>$SSH_AUTH_SOCK</c>). Parity with <c>agent_ops_unix</c>
/// (<c>agent.c:172-325</c>). The socket is the only SSH agent backend in
/// use; Windows Pageant and Windows OpenSSH named-pipe backends
/// are deferred (they will implement <see cref="IAgentTransport"/> when added).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire framing.</b> Every agent request/response is
/// <c>[4-byte BE length][payload]</c>. The transport adds the length prefix
/// on writes and strips it on reads — callers hand <see cref="TransactAsync"/>
/// the payload only. Mirrors <c>agent_transact_unix</c> (<c>agent.c:238-306</c>).
/// </para>
/// <para>
/// <b>Socket lifecycle.</b> <see cref="ConnectAsync"/> resolves the socket path
/// (<see cref="_socketPathOverride"/> or <c>$SSH_AUTH_SOCK</c>) and connects a
/// <see cref="Socket"/>. <see cref="DisconnectAsync"/> closes it. A failed
/// connect leaves the transport reusable (the failed socket is disposed and
/// <c>_socket</c> is cleared); a disposed instance cannot be reconnected.
/// </para>
/// <para>
/// <b>Unix domain socket endpoint.</b> <see cref="UnixDomainSocketEndPoint"/>
/// is BCL (in-box for <c>net10.0</c>, AOT-clean). The mock backend used in
/// tests also implements <see cref="IAgentTransport"/> directly, so the Unix
/// socket path is exercised only by the live Docker test.
/// </para>
/// </remarks>
internal sealed class UnixSocketAgentTransport : IAgentTransport
{
    /// <summary>
    /// Maximum agent message size (256 KiB). Defensive bound — OpenSSH's agent
    /// has a hard cap of 256 KiB (<c>ssh-agent.c</c> MAX_MESSAGE_LENGTH).
    /// </summary>
    private const int MaxMessageLength = 256 * 1024;

    private readonly string? _socketPathOverride;
    private Socket? _socket;
    private bool _disposed;

    /// <summary>
    /// Creates a transport that resolves the socket path from
    /// <c>SSH_AUTH_SOCK</c> at <see cref="ConnectAsync"/> time. Matches the
    /// default <c>new SshAgent()</c> code path.
    /// </summary>
    public UnixSocketAgentTransport()
    {
        // Path resolved at ConnectAsync time so the env var is read fresh.
    }

    /// <summary>
    /// Creates a transport bound to an explicit socket path. Used when the
    /// caller passes <c>new SshAgent(socketPath)</c> or sets
    /// <see cref="SshAgent.IdentityPath"/>.
    /// </summary>
    /// <param name="socketPath">The Unix socket path (typically <c>$SSH_AUTH_SOCK</c>).</param>
    public UnixSocketAgentTransport(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        if (socketPath.Length == 0)
        {
            throw new ArgumentException("Socket path must not be empty", nameof(socketPath));
        }

        _socketPathOverride = socketPath;
    }

    /// <inheritdoc/>
    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        if (_socket is not null)
        {
            throw new InvalidOperationException("UnixSocketAgentTransport is already connected");
        }

        string path = ResolveSocketPath();
        cancellationToken.ThrowIfCancellationRequested();

        Socket socket;
        try
        {
            var endpoint = new UnixDomainSocketEndPoint(path);
            socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Unspecified);
        }
        catch (SocketException ex)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Failed to create Unix domain socket for '{path}'", ex);
        }

        try
        {
            // Socket.ConnectAsync is cancelable on .NET 5+ and is the proper async
            // (non-blocking) connect. Honors the cancellation token.
            await ConnectSocketAsync(socket, path, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Never leave a failed/cancelled socket assigned. The C closes
            // the fd on failure and libssh2_agent_connect can be called again.
            socket.Dispose();
            _socket = null;
            throw;
        }

        // Assign only after a successful connect so a retry after failure is
        // not blocked by a stale non-null _socket.
        _socket = socket;
    }

    private static async Task ConnectSocketAsync(Socket socket, string path, CancellationToken cancellationToken)
    {
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Failed to connect to SSH agent at '{path}' (SocketErrorCode={ex.SocketErrorCode})", ex);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task TransactAsync(
        ReadOnlyMemory<byte> request,
        IBufferWriter<byte> responseWriter,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        Socket socket = _socket ?? throw new InvalidOperationException("Transport not connected");

        // ── Write phase: [4-byte BE length][payload] ────────────────────────
        if (request.Length + 4 > MaxMessageLength)
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                $"Agent request too long ({request.Length + 4} > {MaxMessageLength})");
        }

        byte[] lengthBuffer = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            // Send the length prefix and the payload. Use Socket.SendAsync (the
            // cancelable async API) on the combined buffer for one syscall.

            BinaryPrimitives.WriteInt32BigEndian(lengthBuffer, request.Length);

            await SendAllAsync(socket, lengthBuffer.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
            await SendAllAsync(socket, request, cancellationToken).ConfigureAwait(false);

            // ── Read phase: [4-byte BE length][payload] ─────────────────────────

            await ReadExactAsync(socket, lengthBuffer.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
            uint responseLength = BinaryPrimitives.ReadUInt32BigEndian(lengthBuffer);

            if (responseLength == 0)
            {
                throw new SshException(SshErrorCode.AgentProtocol,
                    "Agent returned empty response (missing message-type byte)");
            }

            if (responseLength > MaxMessageLength)
            {
                throw new SshException(SshErrorCode.AgentProtocol,
                    $"Agent response too long ({responseLength} > {MaxMessageLength})");
            }

            await ReadExactAsync(socket, responseWriter, (int)responseLength, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ObjectDisposedException ex)
        {
            // The owning SshAgent may dispose the transport under an
            // in-flight transaction; surface it through the port's error
            // contract (SocketRecv) instead of the raw BCL exception.
            throw new SshException(SshErrorCode.SocketRecv,
                "SSH agent transport disposed during transaction", ex);
        }
        catch (OperationCanceledException)
        {
            // Cancellation can leave the socket holding a partially
            // written request or a partially consumed response — its framing
            // is corrupted and no retry is safe. Poison the connection (close
            // + clear) so the next transaction fails fast with "Transport not
            // connected" (reconnect required) instead of misparsing replies or
            // hanging. Managed-only: the C has no cancellation concept.
            Poison();
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(lengthBuffer);
        }
    }

    /// <summary>
    /// Closes and clears the socket: used when a cancelled transaction
    /// leaves the stream in an unknown framing state. The transport stays
    /// usable — <see cref="ConnectAsync"/> can reconnect.
    /// </summary>
    private void Poison()
    {
        Socket? socket = _socket;
        _socket = null;
        socket?.Dispose();
    }

    /// <inheritdoc/>
    public Task DisconnectAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        Socket? socket = _socket;
        if (socket is null)
        {
            return Task.CompletedTask;
        }

        // Graceful shutdown then close — parity with agent_disconnect_unix's
        // _libssh2_closesocket(agent->fd) (which is just a hard close).
        try
        {
            socket.Shutdown(SocketShutdown.Both);
        }
        catch (SocketException)
        {
            // Peer may have closed first; ignore.
        }
        finally
        {
            socket.Close();
            _socket = null;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }

        _disposed = true;
        Socket? socket = _socket;
        _socket = null;
        socket?.Dispose();
        return ValueTask.CompletedTask;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private string ResolveSocketPath()
    {
        if (_socketPathOverride is not null)
        {
            return _socketPathOverride;
        }

        string? env = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        if (string.IsNullOrEmpty(env))
        {
            throw new SshException(SshErrorCode.AgentProtocol,
                "SSH_AUTH_SOCK environment variable is not set; cannot find SSH agent");
        }

        return env;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Sends the entire buffer, looping until all bytes are written. Throws
    /// <see cref="SshException"/> on socket error or peer-closed connection.
    /// </summary>
    private static async Task SendAllAsync(Socket socket, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        int totalSent = 0;
        while (totalSent < buffer.Length)
        {
            int sent = await socket.SendAsync(buffer.Slice(totalSent), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (sent == 0)
            {
                throw new SshException(SshErrorCode.SocketSend,
                    "SSH agent closed the connection during send");
            }

            totalSent += sent;
        }
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes, looping until the buffer
    /// is full. Throws <see cref="SshException"/> on socket error or
    /// premature EOF.
    /// </summary>
    [Obsolete("TODO: Optimize")]
    private static async Task<byte[]> ReadExactAsync(Socket socket, int count, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[count];
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await socket.ReceiveAsync(buffer.AsMemory(totalRead), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshException(SshErrorCode.SocketRecv,
                    $"SSH agent closed the connection (read {totalRead} of {count} expected bytes)");
            }

            totalRead += read;
        }

        return buffer;
    }

    /// <summary>
    /// Reads exactly <paramref name="buffer.Length"/> bytes, looping until the buffer
    /// is full. Throws <see cref="SshException"/> on socket error or
    /// premature EOF.
    /// </summary>
    private static async Task ReadExactAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = await socket.ReceiveAsync(buffer.Slice(totalRead), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshException(SshErrorCode.SocketRecv,
                    $"SSH agent closed the connection (read {totalRead} of {buffer.Length} expected bytes)");
            }

            totalRead += read;
        }
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes, looping until the buffer
    /// is full. Throws <see cref="SshException"/> on socket error or
    /// premature EOF.
    /// </summary>
    private static async Task ReadExactAsync(Socket socket, IBufferWriter<byte> buffer, int count, CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            // GetMemory(minimumSize) returns the ENTIRE remaining span of
            // the current ≥16 KiB pool segment; handing the whole span to one
            // ReceiveAsync let a peer that over-delivered past the declared
            // response length over-read (read > count - totalRead): the loop
            // exited over-full, the extra bytes were consumed and lost, and the
            // NEXT transaction read response tail bytes as its length prefix
            // (framing desync). Slice to exactly the declared remainder so the
            // receive cannot exceed it.
            Memory<byte> memory = buffer.GetMemory(count - totalRead)[..(count - totalRead)];
            int read = await socket.ReceiveAsync(memory, SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshException(SshErrorCode.SocketRecv,
                    $"SSH agent closed the connection (read {totalRead} of {count} expected bytes)");
            }

            buffer.Advance(read);
            totalRead += read;
        }
    }
}
