using System.Buffers;
using System.Buffers.Binary;
using System.Net.Sockets;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Loopback tests for <see cref="UnixSocketAgentTransport"/> over a real POSIX
/// Unix domain socket pair (listener + client). The peer is a scripted mini-
/// agent that responds to one transaction per test.
/// </summary>
/// <remarks>
/// <para>
/// Each test creates a <see cref="Socket"/> bound to a unique temp path,
/// accepts one connection, and serves a single transaction. The transport
/// under test connects to the listener and sends one request. The peer
/// receives the request, writes a canned response, and tears down.
/// </para>
/// <para>
/// <b>Unix-only.</b> Unix domain sockets are also available on modern Windows
/// (Win10 1803+); these tests run on whatever the test host supports. Linux
/// CI is the primary target.
/// </para>
/// </remarks>
public class UnixSocketAgentTransportTests
{
    // ════════════════════════════════════════════════════════════════════════
    // Connect / Disconnect
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Connect_NoSSHAuthSockEnv_Throws()
    {
        // Clear SSH_AUTH_SOCK if set in the test environment.
        string? saved = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", null);
        try
        {
            await using var transport = new UnixSocketAgentTransport();
            SshException ex = await Assert.ThrowsAsync<SshException>(() => transport.ConnectAsync(CancellationToken.None));
            Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
            Assert.Contains("SSH_AUTH_SOCK", ex.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", saved);
        }
    }

    [Fact]
    public async Task Connect_NonExistentPath_Throws()
    {
        string badPath = Path.Combine(Path.GetTempPath(), $"libssh2cs-no-such-{Guid.NewGuid():N}.sock");
        Assert.False(File.Exists(badPath));

        var transport = new UnixSocketAgentTransport(badPath);
        await using UnixSocketAgentTransport _ = transport;
        SshException ex = await Assert.ThrowsAsync<SshException>(() => transport.ConnectAsync(CancellationToken.None));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains(badPath, ex.Message);
    }

    [Fact]
    public async Task Connect_ExplicitPath_Connects()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string path = Path.Combine(Path.GetTempPath(), $"libssh2cs-listener-{Guid.NewGuid():N}.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen(1);

        try
        {
            var transport = new UnixSocketAgentTransport(path);
            await using UnixSocketAgentTransport _ = transport;
            await transport.ConnectAsync(cancellationToken);

            // Accept the connection on the listener side so cleanup is clean.
            using Socket serverSide = await listener.AcceptAsync(cancellationToken);
            Assert.True(serverSide.Connected);
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    [Fact]
    public async Task Connect_FailedConnect_CanRetryWithNewListener()
    {
        // a failed connect must not leave _socket assigned. Otherwise the
        // second connect throws InvalidOperationException and the transport is
        // permanently bricked (and the failed socket leaks).
        string path = Path.Combine(Path.GetTempPath(), $"libssh2cs-retry-{Guid.NewGuid():N}.sock");
        var transport = new UnixSocketAgentTransport(path);
        await using UnixSocketAgentTransport _ = transport;

        SshException first = await Assert.ThrowsAsync<SshException>(
            () => transport.ConnectAsync(CancellationToken.None));
        Assert.Equal(SshErrorCode.AgentProtocol, first.ErrorCode);

        // Now make the same path connectable and verify a retry succeeds.
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen(1);

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(
                TestContext.Current.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            while (!File.Exists(path) && !cts.IsCancellationRequested)
            {
                await Task.Delay(10, cts.Token).ConfigureAwait(false);
            }

            await transport.ConnectAsync(cts.Token);
            using Socket serverSide = await listener.AcceptAsync(cts.Token);
            Assert.True(serverSide.Connected);
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    [Fact]
    public async Task Connect_AlreadyConnected_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            var transport = new UnixSocketAgentTransport(path);
            await using UnixSocketAgentTransport _ = transport;
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            await Assert.ThrowsAsync<InvalidOperationException>(() => transport.ConnectAsync(cancellationToken));
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    [Fact]
    public void Connect_EmptyPath_Throws()
    {
        Assert.Throws<ArgumentException>(() => new UnixSocketAgentTransport(""));
    }

    [Fact]
    public void Connect_NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new UnixSocketAgentTransport(null!));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Transact
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Transact_SmallPayload_RoundTrips()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            // Drive the peer in the background: read request, write response.
            byte[] request = [11];  // MsgRequestIdentities
            byte[] response = [12, 0, 0, 0, 0];  // empty identities-answer

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
#pragma warning disable CA2025 // CA2025: Do not pass 'IDisposable' instances into unawaited tasks
            Task peerTask = ServeOneTransaction(server, response, cts.Token);
#pragma warning restore CA2025
            try
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cts.Token);
                Assert.Equal(response, writer.WrittenSpan.ToArray());
            }
            finally
            {
                await peerTask;
            }
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    [Fact]
    public async Task Transact_LargePayload_RoundTrips()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            // 4096-byte request payload, 4096-byte response payload.
            byte[] request = new byte[4096];
            byte[] response = new byte[4096];
            new Random(42).NextBytes(request);
            new Random(43).NextBytes(response);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
#pragma warning disable CA2025 // CA2025: Do not pass 'IDisposable' instances into unawaited tasks
            Task peerTask = ServeOneTransaction(server, response, cts.Token);
#pragma warning restore CA2025
            try
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cts.Token);
                Assert.Equal(response, writer.WrittenSpan.ToArray());
            }
            finally
            {
                await peerTask;
            }
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    /// <summary>
    /// Partial reads: the peer sends the 4-byte length and the payload in
    /// multiple small chunks. The transport's read loop must accumulate.
    /// </summary>
    [Fact]
    public async Task Transact_PartialReads_AreAccumulated()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            // 64-byte response, sent in 1-byte chunks.
            byte[] response = new byte[64];
            for (int i = 0; i < response.Length; i++)
            {
                response[i] = (byte)i;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            var peerTask = Task.Run(async () =>
            {
                // Read+discard the client's request first.
                await ReadRequestAsync(server, cts.Token);

                // Send the response length prefix + payload in 1-byte chunks.
                byte[] lenBuf = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)response.Length);
                for (int i = 0; i < 4 + response.Length; i++)
                {
                    byte b = i < 4 ? lenBuf[i] : response[i - 4];
                    await server.SendAsync(new byte[] { b }, SocketFlags.None, cts.Token).ConfigureAwait(false);
                }
            }, cts.Token);

            byte[] request = [11];

            var writer = new ArrayBufferWriter<byte>();
            await transport.TransactAsync(request, writer, cts.Token);
            Assert.Equal(response, writer.WrittenSpan.ToArray());

            await peerTask;
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    /// <summary>
    /// When the peer closes the connection mid-receive, the transport throws
    /// a SocketRecv error.
    /// </summary>
    [Fact]
    public async Task Transact_PeerClosesAfterLength_ThrowsSocketRecv()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var peerTask = Task.Run(async () =>
            {
                // Read+discard the client's request.
                await ReadRequestAsync(server, cts.Token);

                // Send a length prefix claiming 100 bytes, then close immediately.
                byte[] lenBuf = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(lenBuf, 100);
                await server.SendAsync(lenBuf, SocketFlags.None, cts.Token).ConfigureAwait(false);
                server.Close();
            }, cts.Token);

            byte[] request = new byte[] { 11 };
            SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cts.Token);
            });
            Assert.Equal(SshErrorCode.SocketRecv, ex.ErrorCode);

            await peerTask;
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    /// <summary>
    /// A response length of 0 (missing message-type byte) is rejected.
    /// </summary>
    [Fact]
    public async Task Transact_ZeroLengthResponse_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var peerTask = Task.Run(async () =>
            {
                await ReadRequestAsync(server, cts.Token);
                byte[] lenBuf = new byte[4];   // length = 0
                await server.SendAsync(lenBuf, SocketFlags.None, cts.Token).ConfigureAwait(false);
            }, cts.Token);

            byte[] request = new byte[] { 11 };
            SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cts.Token);
            });
            Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
            Assert.Contains("empty response", ex.Message);

            await peerTask;
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    /// <summary>
    /// A response length exceeding the 256 KiB cap is rejected as a defensive
    /// measure against a malicious or buggy agent.
    /// </summary>
    [Fact]
    public async Task Transact_ResponseTooLong_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var peerTask = Task.Run(async () =>
            {
                await ReadRequestAsync(server, cts.Token);
                byte[] lenBuf = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(lenBuf, 300 * 1024);  // > 256 KiB cap
                await server.SendAsync(lenBuf, SocketFlags.None, cts.Token).ConfigureAwait(false);
            }, cts.Token);

            byte[] request = new byte[] { 11 };
            SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cts.Token);
            });
            Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
            Assert.Contains("too long", ex.Message);

            await peerTask;
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    [Fact]
    public async Task Transact_NotConnected_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var transport = new UnixSocketAgentTransport();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            var writer = new ArrayBufferWriter<byte>();
            await transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken);
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Dispose semantics
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task DisposeAsync_Twice_NoOp()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket _ = await listener.AcceptAsync(cancellationToken);

            await transport.DisposeAsync();
            await transport.DisposeAsync();  // idempotent
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    [Fact]
    public async Task Transact_AfterDispose_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket _ = await listener.AcceptAsync(cancellationToken);

            await transport.DisposeAsync();

            await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(new byte[] { 11 }, writer, cancellationToken);
            });
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // over-read past the declared response length
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// The payload read handed the ENTIRE pool segment to one ReceiveAsync, so
    /// a peer delivering more bytes than the declared response length in one
    /// write over-read past the response: the loop exited over-full, the extra
    /// bytes were consumed and lost, and the next transaction read response
    /// tail bytes as its length prefix (framing desync). The receive is now
    /// bounded to the declared remainder.
    /// </summary>
    [Fact]
    public async Task Transact_PeerOverDelivers_BoundedReceive_DoesNotOverRead()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var peerTask = Task.Run(async () =>
            {
                await ReadRequestAsync(server, cts.Token);

                // One write: declared response [len=1][0x7F] + 4 extra bytes
                // [DE AD BE EF] (a buggy/malicious agent over-delivering). The
                // transport's single ReceiveAsync must consume exactly the
                // declared byte, leaving the extra bytes in the stream.
                byte[] frame = [0, 0, 0, 1, 0x7F, 0xDE, 0xAD, 0xBE, 0xEF];
                await server.SendAsync(frame, SocketFlags.None, cts.Token).ConfigureAwait(false);

                // Second transaction: a clean response.
                await ReadRequestAsync(server, cts.Token);
                await server.SendAsync(new byte[] { 0, 0, 0, 1, 0x42 }, SocketFlags.None, cts.Token)
                    .ConfigureAwait(false);
            }, cts.Token);

            byte[] request = [11];

            // Transact 1: the writer must contain EXACTLY the declared payload.
            // Pre-fix the single receive consumed all 9 buffered bytes and the
            // writer held [0x7F DE AD BE EF].
            var w1 = new ArrayBufferWriter<byte>();
            await transport.TransactAsync(request, w1, cts.Token);
            Assert.Equal(new byte[] { 0x7F }, w1.WrittenSpan.ToArray());

            // Transact 2: post-fix the extra bytes stayed in the stream, so the
            // length-prefix read sees [DE AD BE EF] = 0xDEADBEEF > the 256 KiB
            // cap and fails loudly — the desync is DETECTED, not silent.
            // Pre-fix the extra bytes had been consumed and this read the
            // fresh frame instead (succeeding silently on the corrupted stream).
            SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            {
                var w2 = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, w2, cts.Token);
            });
            Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
            Assert.Contains("too long", ex.Message);

            await peerTask;
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // cancellation mid-transaction poisons the transport
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Cancelling a transaction can leave the socket holding a partially
    /// written request or a partially consumed response — its framing is
    /// corrupted and no retry is safe. The transport must poison the
    /// connection (close + clear) so the next transaction fails fast with
    /// "not connected" (reconnect required). Managed-only: the C has no
    /// cancellation concept.
    /// </summary>
    [Fact]
    public async Task Transact_CancelledMidTransaction_PoisonsTransport_NextFailsFast()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        (string path, Socket? listener) = await CreateListenerAsync(cancellationToken);
        try
        {
            await using var transport = new UnixSocketAgentTransport(path);
            await transport.ConnectAsync(cancellationToken);
            using Socket server = await listener.AcceptAsync(cancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var requestRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var peerTask = Task.Run(async () =>
            {
                await ReadRequestAsync(server, cts.Token);
                requestRead.TrySetResult();

                // Hold the response frame until the test has cancelled the
                // client's transaction. This makes the cancellation
                // deterministic: the client is blocked in its length-prefix
                // receive, so the cancel cannot race a normally-completed
                // transaction (previously the peer's write raced the cancel
                // under full-suite parallel load and the test flaked).
                await releaseWrite.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

                // Write the full response frame. The client's cancellation
                // already poisoned (closed) the socket, so this send may fail
                // with a connection reset — the frame is incidental to the
                // assertions.
                byte[] frame = [0, 0, 0, 4, 0xAA, 0xBB, 0xCC, 0xDD];
                try
                {
                    await server.SendAsync(frame, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                }
            }, cts.Token);

            byte[] request = [11];
            var tx1 = Task.Run(async () =>
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cts.Token);
            }, cts.Token);

            // Wait until the peer has consumed the request — the client is now
            // guaranteed to be blocked in its length-prefix receive, so
            // cancelling cannot race a completed transaction.
            await requestRead.Task.WaitAsync(cancellationToken);
            await cts.CancelAsync();
            releaseWrite.TrySetResult();

            // Socket.ReceiveAsync surfaces cancellation as TaskCanceledException
            // (an OperationCanceledException subclass) — accept any variant.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => tx1);

            // The next transaction must fail fast with "not connected".
            // Pre-fix the transport kept the socket and this call proceeded on
            // the corrupted stream (misparsing the response tail or succeeding
            // on a fresh frame — silently).
            InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                var writer = new ArrayBufferWriter<byte>();
                await transport.TransactAsync(request, writer, cancellationToken);
            });
            Assert.Contains("not connected", ex.Message);

            await peerTask;
        }
        finally
        {
            TryCleanup(path, listener);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a Unix-domain-socket listener at a unique temp path. Returns
    /// the path and the listener socket.
    /// </summary>
    private static async Task<(string Path, Socket Listener)> CreateListenerAsync(CancellationToken cancellationToken)
    {
        string path = Path.Combine(Path.GetTempPath(), $"libssh2cs-uds-{Guid.NewGuid():N}.sock");
        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen(1);

        // Give the OS a moment to register the bind (avoids a race where the
        // client tries to connect before the path exists).
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(2));
        while (!File.Exists(path) && !cts.IsCancellationRequested)
        {
            await Task.Delay(10, cts.Token).ConfigureAwait(false);
        }

        return (path, listener);
    }

    /// <summary>
    /// Serves one transaction: read request, write response. The request is
    /// verified for proper length-prefix framing (but contents are discarded).
    /// </summary>
    private static async Task ServeOneTransaction(Socket server, byte[] response, CancellationToken ct)
    {
        await ReadRequestAsync(server, ct).ConfigureAwait(false);

        byte[] lenBuf = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)response.Length);
        byte[] sendBuf = new byte[4 + response.Length];
        Buffer.BlockCopy(lenBuf, 0, sendBuf, 0, 4);
        Buffer.BlockCopy(response, 0, sendBuf, 4, response.Length);

        int total = 0;
        while (total < sendBuf.Length)
        {
            int sent = await server.SendAsync(sendBuf.AsMemory(total), SocketFlags.None, ct).ConfigureAwait(false);
            if (sent == 0)
            {
                break;
            }

            total += sent;
        }
    }

    /// <summary>
    /// Reads and discards one full client request: [4-byte BE length][payload].
    /// </summary>
    private static async Task ReadRequestAsync(Socket server, CancellationToken ct)
    {
        byte[] lenBuf = await ReadExactAsync(server, 4, ct).ConfigureAwait(false);
        int len = (int)BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
        if (len > 0)
        {
            _ = await ReadExactAsync(server, len, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Reads exactly N bytes from the socket, looping until full.</summary>
    private static async Task<byte[]> ReadExactAsync(Socket socket, int count, CancellationToken ct)
    {
        byte[] buf = new byte[count];
        int total = 0;
        while (total < count)
        {
            int n = await socket.ReceiveAsync(buf.AsMemory(total), SocketFlags.None, ct).ConfigureAwait(false);
            if (n == 0)
            {
                throw new IOException($"Peer closed after {total} of {count} bytes");
            }

            total += n;
        }

        return buf;
    }

    /// <summary>Best-effort cleanup of the listener + socket file.</summary>
    private static void TryCleanup(string path, Socket listener)
    {
        try
        {
            listener.Dispose();
        }
        catch
        {
            // Ignore.
        }

        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Ignore — test teardown best-effort.
        }
    }
}
