using System.Buffers;
using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Agent;

namespace LibSsh2CS.UnitTests.Agent;

/// <summary>
/// Tests for <see cref="SshAgent"/> over a fake <see cref="IAgentTransport"/>.
/// Verifies the protocol logic in <see cref="SshAgent"/> (request framing,
/// response parsing, error mapping, lifecycle) without any real socket I/O.
/// The actual transport bytes are exercised by
/// <see cref="UnixSocketAgentTransportTests"/>; the live end-to-end path is
/// exercised by <c>DockerAgentTests</c> (Phase 4 increment 4.5).
/// </summary>
public class SshAgentTests
{
    // ════════════════════════════════════════════════════════════════════════
    // Constructor / IdentityPath
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Ctor_NullTransport_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new SshAgent((IAgentTransport)null!));
    }

    [Fact]
    public void Ctor_NullSocketPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new SshAgent((string)null!));
    }

    [Fact]
    public void IdentityPath_SetBeforeConnect_RewritesTransport()
    {
        var agent = new SshAgent();
        // IdentityPath is null initially (auto-discovery).
        Assert.Null(agent.IdentityPath);

        // Override to a custom path; the transport is rebuilt.
        agent.IdentityPath = "/tmp/custom-agent.sock";
        Assert.Equal("/tmp/custom-agent.sock", agent.IdentityPath);
    }

    [Fact]
    public async Task IdentityPath_SetAfterConnect_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await agent.ConnectAsync(cancellationToken);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
        {
            agent.IdentityPath = "/tmp/other.sock";
            return Task.CompletedTask;
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Connect / Disconnect
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Connect_Twice_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await agent.ConnectAsync(cancellationToken);
        await Assert.ThrowsAsync<InvalidOperationException>(() => agent.ConnectAsync(cancellationToken));
    }

    [Fact]
    public async Task Disconnect_BeforeConnect_NoOp()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await agent.DisconnectAsync(cancellationToken);  // does not throw
        Assert.False(agent.IsConnected);
    }

    [Fact]
    public async Task Disconnect_AfterConnect_DropsConnection()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);
        Assert.True(agent.IsConnected);

        await agent.DisconnectAsync(cancellationToken);
        Assert.False(agent.IsConnected);
        Assert.True(transport.DisconnectCalled);
    }

    [Fact]
    public async Task IsConnected_True_AfterConnect()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        Assert.False(agent.IsConnected);
        await agent.ConnectAsync(cancellationToken);
        Assert.True(agent.IsConnected);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ListIdentities
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ListIdentities_NotConnected_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await agent.ListIdentitiesAsync(cancellationToken));
    }

    [Fact]
    public async Task ListIdentities_SendsRequest_Payload_Only_Msg11()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        // Pre-queue an empty identities-answer response.
        transport.Enqueue(BuildIdentitiesAnswer([]));
        await agent.ListIdentitiesAsync(cancellationToken);

        // Verify the request was a single-byte payload containing 11.
        Assert.Single(transport.SentPayloads);
        byte[] sent = transport.SentPayloads[0];
        Assert.Single(sent);
        Assert.Equal(11, sent[0]);
    }

    [Fact]
    public async Task ListIdentities_ReturnsIdentities_InOrder()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        byte[] blob1 = BuildKeyBlob("ssh-ed25519");
        byte[] blob2 = BuildKeyBlob("ssh-rsa");
        transport.Enqueue(BuildIdentitiesAnswer([
            (blob1, "alice@host"),
            (blob2, "bob@other"),
        ]));

        IReadOnlyList<SshAgentIdentity> ids = await agent.ListIdentitiesAsync(cancellationToken);

        Assert.Equal(2, ids.Count);
        Assert.Equal(blob1, ids[0].Blob);
        Assert.Equal("alice@host", ids[0].Comment);
        Assert.Equal(blob2, ids[1].Blob);
        Assert.Equal("bob@other", ids[1].Comment);
    }

    [Fact]
    public async Task ListIdentities_EmptyList_ReturnsEmpty()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        transport.Enqueue(BuildIdentitiesAnswer([]));
        IReadOnlyList<SshAgentIdentity> ids = await agent.ListIdentitiesAsync(cancellationToken);
        Assert.Empty(ids);
    }

    [Fact]
    public async Task ListIdentities_FailureResponse_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        transport.Enqueue([AgentProtocol.MsgFailure]);  // SSH_AGENT_FAILURE
        SshException ex = await Assert.ThrowsAsync<SshException>(async () => await agent.ListIdentitiesAsync(cancellationToken));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("list identities", ex.Message);
        Assert.Contains("SSH_AGENT_FAILURE", ex.Message);
    }

    [Fact]
    public async Task ListIdentities_TruncatedResponse_ThrowsAgentProtocol()
    {
        // Parity agent.c:647-718: every truncation in the identities parse is
        // LIBSSH2_ERROR_AGENT_PROTOCOL, not the wire reader's OutOfBoundary.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        // Header claims 1 identity but no blob bytes follow.
        transport.Enqueue([AgentProtocol.MsgIdentitiesAnswer, 0, 0, 0, 1]);

        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await agent.ListIdentitiesAsync(cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
    }

    [Fact]
    public async Task Sign_TruncatedResponse_ThrowsAgentProtocol()
    {
        // Parity agent.c:511-591.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        // Msg 14 with a truncated sig-blob string (declares 100 bytes, has 0).
        transport.Enqueue([AgentProtocol.MsgSignResponse, 0, 0, 0, 100]);

        var identity = new SshAgentIdentity { Blob = BuildKeyBlob("ssh-rsa"), Comment = "c" };
        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await agent.SignAsync(identity, "data"u8.ToArray(), SshAgentSignFlags.None, cancellationToken));

        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Sign
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Sign_NotConnected_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await agent.SignAsync(new SshAgentIdentity { Blob = [], Comment = "" }, new byte[] { 1 }, cancellationToken: cancellationToken));
    }

    [Fact]
    public async Task Sign_NullIdentity_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        await using var agent = new SshAgent(new FakeTransport());
        await agent.ConnectAsync(cancellationToken);
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await agent.SignAsync(null!, new byte[] { 1 }, cancellationToken: cancellationToken));
    }

    /// <summary>
    /// Sign request wire format: [13][string blob][string data][uint32 flags].
    /// </summary>
    [Fact]
    public async Task Sign_SendsWireCorrectRequest()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        byte[] blob = BuildKeyBlob("ssh-ed25519");
        byte[] data = [0xDE, 0xAD, 0xBE, 0xEF];
        transport.Enqueue(BuildSignResponse([0x00, 0x00, 0x00, 0x07, (byte)'x', (byte)'y', 1, 2, 3, 4, 5]));

        await agent.SignAsync(
            new SshAgentIdentity { Blob = blob, Comment = "" },
            data,
            flags: SshAgentSignFlags.RsaSha256,
            cancellationToken: cancellationToken);

        Assert.Single(transport.SentPayloads);
        byte[] sent = transport.SentPayloads[0];

        // Verify the request structure.
        Assert.Equal(13, sent[0]);
        int offset = 1;
        int blobLen = (int)BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(offset, 4));
        offset += 4;
        Assert.Equal(blob.Length, blobLen);
        offset += blobLen;
        int dataLen = (int)BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(offset, 4));
        offset += 4;
        Assert.Equal(data.Length, dataLen);
        offset += dataLen;
        uint gotFlags = BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(offset, 4));
        Assert.Equal((uint)SshAgentSignFlags.RsaSha256, gotFlags);
    }

    [Fact]
    public async Task Sign_NoneFlags_WritesZero()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        transport.Enqueue(BuildSignResponse([0xAA]));
        await agent.SignAsync(
            new SshAgentIdentity { Blob = [1, 2], Comment = "" },
            (byte[])[3, 4],
            flags: SshAgentSignFlags.None,
            cancellationToken: cancellationToken);

        byte[] sent = transport.SentPayloads[0];
        // [13][4=2][1,2][4=2][3,4][4=0]
        Assert.Equal((uint)SshAgentSignFlags.None,
            BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(sent.Length - 4, 4)));
    }

    [Fact]
    public async Task Sign_Sha2_512_Flag_Writes4()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        transport.Enqueue(BuildSignResponse([0xAA]));
        await agent.SignAsync(
            new SshAgentIdentity { Blob = [1, 2], Comment = "" },
            (byte[])[3, 4],
            flags: SshAgentSignFlags.RsaSha512,
            cancellationToken: cancellationToken);

        byte[] sent = transport.SentPayloads[0];
        Assert.Equal(4u,
            BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(sent.Length - 4, 4)));
    }

    [Fact]
    public async Task Sign_Sha2_BothFlags_Writes6()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        transport.Enqueue(BuildSignResponse([0xAA]));
        await agent.SignAsync(
            new SshAgentIdentity { Blob = [1, 2], Comment = "" },
            (byte[])[3, 4],
            flags: SshAgentSignFlags.RsaSha256 | SshAgentSignFlags.RsaSha512,
            cancellationToken: cancellationToken);

        byte[] sent = transport.SentPayloads[0];
        Assert.Equal(6u,
            BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(sent.Length - 4, 4)));
    }

    [Fact]
    public async Task Sign_ReturnsSigBlobIntact()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        byte[] sigBlob = [0x00, 0x00, 0x00, 0x0B, (byte)'s', (byte)'s', (byte)'h', (byte)'-', (byte)'e', (byte)'d', (byte)'2', (byte)'5', (byte)'5', (byte)'1', (byte)'9', 0xAA, 0xBB];
        transport.Enqueue(BuildSignResponse(sigBlob));

        byte[] got = await agent.SignAsync(
            new SshAgentIdentity { Blob = [1, 2], Comment = "" },
            (byte[])[3, 4],
            cancellationToken: cancellationToken);

        Assert.Equal(sigBlob, got);
    }

    [Fact]
    public async Task Sign_FailureResponse_Throws()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        transport.Enqueue([AgentProtocol.MsgFailure]);
        SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
            await agent.SignAsync(new SshAgentIdentity { Blob = [], Comment = "" }, new byte[] { 1 }, cancellationToken: cancellationToken));
        Assert.Equal(SshErrorCode.AgentProtocol, ex.ErrorCode);
        Assert.Contains("sign", ex.Message);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Concurrency
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Two concurrent ListIdentities calls execute strictly serially (the
    /// agent protocol is single-connection). The fake transport tracks
    /// in-flight call counts.
    /// </summary>
    [Fact]
    public async Task Concurrent_Transactions_AreSerialized()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        await using var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);

        // Enqueue two responses; the calls complete in arrival order but the
        // transport never sees overlapping TransactAsync calls.
        transport.Enqueue(BuildIdentitiesAnswer([]));
        transport.Enqueue(BuildIdentitiesAnswer([]));

        Task t1 = Task.Run(() => agent.ListIdentitiesAsync(cancellationToken));
        Task t2 = Task.Run(() => agent.ListIdentitiesAsync(cancellationToken));
        await Task.WhenAll(t1, t2);

        Assert.Equal(2, transport.SentPayloads.Count);
        Assert.Equal(1, transport.MaxConcurrentCalls);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Dispose
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Dispose_Twice_NoOp()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var agent = new SshAgent(new FakeTransport());
        await agent.ConnectAsync(cancellationToken);
        await agent.DisposeAsync();
        await agent.DisposeAsync();
    }

    [Fact]
    public async Task Dispose_AfterDispose_ListThrows()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var agent = new SshAgent(new FakeTransport());
        await agent.ConnectAsync(cancellationToken);
        await agent.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await agent.ListIdentitiesAsync(cancellationToken));
    }

    [Fact]
    public async Task Dispose_DisconnectsTransport()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport();
        var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);
        await agent.DisposeAsync();
        Assert.True(transport.DisconnectCalled);
    }

    [Fact]
    public async Task Dispose_SwallowsAgentDisconnectErrors()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var transport = new FakeTransport(throwOnDisconnect: true);
        var agent = new SshAgent(transport);
        await agent.ConnectAsync(cancellationToken);
        // Should not throw despite the transport raising on DisconnectAsync.
        await agent.DisposeAsync();
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>Builds an SSH string (BE32 length + raw bytes).</summary>
    private static byte[] BuildString(byte[] content)
    {
        byte[] s = new byte[4 + content.Length];
        BinaryPrimitives.WriteUInt32BigEndian(s.AsSpan(0, 4), (uint)content.Length);
        Buffer.BlockCopy(content, 0, s, 4, content.Length);
        return s;
    }

    /// <summary>Builds a minimal key-type-only SSH public key blob.</summary>
    private static byte[] BuildKeyBlob(string keyType)
        => BuildString(Encoding.UTF8.GetBytes(keyType));

    /// <summary>
    /// Builds an identities-answer payload:
    /// <c>[12][uint32 count][blob, comment]*</c>.
    /// </summary>
    private static byte[] BuildIdentitiesAnswer(
        IReadOnlyList<(byte[] Blob, string Comment)> identities)
    {
        // Each (blob, comment) pair is encoded as [string blob][string comment].
        int total = 1 + 4;
        var encoded = new List<byte[]>(identities.Count * 2);
        foreach ((byte[] blob, string comment) in identities)
        {
            byte[] blobStr = BuildString(blob);
            byte[] commentStr = BuildString(Encoding.UTF8.GetBytes(comment));
            encoded.Add(blobStr);
            encoded.Add(commentStr);
            total += blobStr.Length + commentStr.Length;
        }

        byte[] payload = new byte[total];
        payload[0] = AgentProtocol.MsgIdentitiesAnswer;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), (uint)identities.Count);

        int offset = 5;
        foreach (byte[] chunk in encoded)
        {
            Buffer.BlockCopy(chunk, 0, payload, offset, chunk.Length);
            offset += chunk.Length;
        }

        return payload;
    }

    /// <summary>
    /// Builds a sign-response payload: <c>[14][string sig_blob]</c>.
    /// </summary>
    private static byte[] BuildSignResponse(byte[] sigBlob)
    {
        byte[] sigStr = BuildString(sigBlob);
        byte[] payload = new byte[1 + sigStr.Length];
        payload[0] = AgentProtocol.MsgSignResponse;
        Buffer.BlockCopy(sigStr, 0, payload, 1, sigStr.Length);
        return payload;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Fake IAgentTransport — scripted responses, in-order delivery
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A scripted fake <see cref="IAgentTransport"/>. Enqueue responses with
    /// <see cref="Enqueue"/>; the fake returns them in FIFO order. Tracks sent
    /// payloads + max-concurrent-call count for serialization verification.
    /// </summary>
    private sealed class FakeTransport : IAgentTransport
    {
        private readonly Queue<byte[]> _responses = new();
        private readonly bool _throwOnDisconnect;
        private int _currentCalls;
        private int _maxConcurrentCalls;

        public FakeTransport(bool throwOnDisconnect = false)
        {
            _throwOnDisconnect = throwOnDisconnect;
        }

        public bool DisconnectCalled { get; private set; }
        public List<byte[]> SentPayloads { get; } = [];
        public int MaxConcurrentCalls => _maxConcurrentCalls;

        public void Enqueue(byte[] response) => _responses.Enqueue(response);

        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public async Task TransactAsync(
            ReadOnlyMemory<byte> request, IBufferWriter<byte> responseWriter,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            Interlocked.Increment(ref _currentCalls);
            int current = _currentCalls;
            // Update max (race-free enough for tests — overlap window is small).
            if (current > Volatile.Read(ref _maxConcurrentCalls))
            {
                Interlocked.Exchange(ref _maxConcurrentCalls, current);
            }

            try
            {
                await Task.Yield();
                lock (SentPayloads)
                {
                    SentPayloads.Add(request.ToArray());
                }

                byte[] response = _responses.Count > 0
                    ? _responses.Dequeue()
                    : throw new InvalidOperationException("FakeTransport: no enqueued response");

                responseWriter.Write(response);
            }
            finally
            {
                Interlocked.Decrement(ref _currentCalls);
            }
        }

        public Task DisconnectAsync(CancellationToken cancellationToken)
        {
            DisconnectCalled = true;
            if (_throwOnDisconnect)
            {
                throw new SshException(SshErrorCode.AgentProtocol, "fake disconnect failure");
            }

            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
