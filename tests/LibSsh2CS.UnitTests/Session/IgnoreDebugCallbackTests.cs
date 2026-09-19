using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Text;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;/// <summary>
/// IGNORE/DEBUG session callbacks — parity with
/// <c>libssh2_session_callback_set(LIBSSH2_CALLBACK_IGNORE)</c> /
/// <c>(LIBSSH2_CALLBACK_DEBUG)</c> (packet.c:787-821): the callbacks observe
/// the packets while the packets themselves are still discarded.
/// </summary>
public class IgnoreDebugCallbackTests
{
    [Fact]
    public async Task IgnoreAndDebugCallbacks_FireOnInboundPackets()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var ignorePayloads = new List<byte[]>();
        var debugCalls = new List<(bool AlwaysDisplay, string Message, string Language)>();
        session.IgnoreCallback = data => ignorePayloads.Add(data.ToArray());
        session.DebugCallback = (alwaysDisplay, message, language) =>
            debugCalls.Add((alwaysDisplay, message, language));

        // Start the mock server concurrently with the client handshake.
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await handshookTask;

        // Start a password auth (the client waits for the server's reply).
        Task authTask = session.AuthenticateWithPasswordAsync("user", "pass", null, ct);

        // Server: read the USERAUTH_REQUEST, then send IGNORE + DEBUG
        // followed by SUCCESS — the IGNORE/DEBUG must be inline-dispatched
        // to the callbacks during the auth wait.
        RawPacket req = await mock.ServerPacketReader!.ReadPacketAsync(ct);
        Assert.Equal(PacketType.UserauthRequest, req.Type);

        byte[] ignoreData = Encoding.ASCII.GetBytes("ignore me");
        byte[] ignorePayload = new byte[1 + 4 + ignoreData.Length];
        ignorePayload[0] = (byte)PacketType.Ignore;
        BinaryPrimitives.WriteUInt32BigEndian(ignorePayload.AsSpan(1, 4), (uint)ignoreData.Length);
        ignoreData.CopyTo(ignorePayload, 5);

        byte[] debugMsg = Encoding.ASCII.GetBytes("connection debug");
        byte[] debugLang = Encoding.ASCII.GetBytes("en-US");
        byte[] debugPayload = new byte[1 + 1 + 4 + debugMsg.Length + 4 + debugLang.Length];
        debugPayload[0] = (byte)PacketType.Debug;
        debugPayload[1] = 1;   // always_display = true
        BinaryPrimitives.WriteUInt32BigEndian(debugPayload.AsSpan(2, 4), (uint)debugMsg.Length);
        debugMsg.CopyTo(debugPayload, 6);
        BinaryPrimitives.WriteUInt32BigEndian(debugPayload.AsSpan(6 + debugMsg.Length, 4), (uint)debugLang.Length);
        debugLang.CopyTo(debugPayload, 10 + debugMsg.Length);

        await mock.ServerPacketWriter!.WritePacketAsync(PacketType.Ignore, ignorePayload, ct);
        await mock.ServerPacketWriter.WritePacketAsync(PacketType.Debug, debugPayload, ct);
        await mock.ServerPacketWriter.WritePacketAsync(PacketType.UserauthSuccess,
            new byte[] { (byte)PacketType.UserauthSuccess }, ct);

        await authTask;

        // The IGNORE callback sees the raw payload after the type byte — the
        // string field INCLUDING its length prefix (the C's data+1, datalen-1).
        Assert.Single(ignorePayloads);
        Assert.Equal(ignorePayload.AsSpan(1).ToArray(), ignorePayloads[0]);

        Assert.Single(debugCalls);
        Assert.Equal((true, "connection debug", "en-US"), debugCalls[0]);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task Callbacks_CanBeSetAfterHandshake()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await handshookTask;

        // Set the callbacks AFTER the handshake — the property setter must
        // push them into the live queue.
        int ignoreCount = 0;
        session.IgnoreCallback = _ => ignoreCount++;

        Task authTask = session.AuthenticateWithPasswordAsync("user", "pass", null, ct);

        RawPacket req = await mock.ServerPacketReader!.ReadPacketAsync(ct);
        Assert.Equal(PacketType.UserauthRequest, req.Type);

        byte[] ignorePayload = [(byte)PacketType.Ignore, 0, 0, 0, 1, (byte)'x'];
        await mock.ServerPacketWriter!.WritePacketAsync(PacketType.Ignore, ignorePayload, ct);
        await mock.ServerPacketWriter.WritePacketAsync(PacketType.UserauthSuccess,
            new byte[] { (byte)PacketType.UserauthSuccess }, ct);

        await authTask;

        Assert.Equal(1, ignoreCount);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task DebugCallback_ShortPacket_GetsEmptyStrings()
    {
        // A DEBUG packet shorter than the two string fields (2..5 bytes):
        // the C invokes the callback with whatever message/language it had
        // (stale); the port passes empty strings instead.
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var debugCalls = new List<(bool, string, string)>();
        session.DebugCallback = (a, m, l) => debugCalls.Add((a, m, l));

        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await handshookTask;

        Task authTask = session.AuthenticateWithPasswordAsync("user", "pass", null, ct);

        RawPacket req = await mock.ServerPacketReader!.ReadPacketAsync(ct);
        Assert.Equal(PacketType.UserauthRequest, req.Type);

        // [4][always_display=1] — no message/language strings at all.
        byte[] debugPayload = [(byte)PacketType.Debug, 1];
        await mock.ServerPacketWriter!.WritePacketAsync(PacketType.Debug, debugPayload, ct);
        await mock.ServerPacketWriter.WritePacketAsync(PacketType.UserauthSuccess,
            new byte[] { (byte)PacketType.UserauthSuccess }, ct);

        await authTask;

        Assert.Single(debugCalls);
        Assert.Equal((true, string.Empty, string.Empty), debugCalls[0]);

        await session.DisposeAsync();
    }
}

internal sealed class DuplexPipeFromPipes : IDuplexPipe
{
    public DuplexPipeFromPipes(PipeReader input, PipeWriter output)
    {
        Input = input;
        Output = output;
    }

    public PipeReader Input { get; }
    public PipeWriter Output { get; }
}
