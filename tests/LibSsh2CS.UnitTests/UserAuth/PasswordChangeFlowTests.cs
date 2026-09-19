using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Transport;
using LibSsh2CS.UnitTests.Session;

namespace LibSsh2CS.UnitTests.UserAuth;

/// <summary>
/// Regression tests for the password-change flow:
/// the password-change flow must terminate after at most one change attempt,
/// matching libssh2's state machine.
/// </summary>
public class PasswordChangeFlowTests
{
    [Fact]
    public async Task RepeatedPasswordChangeRequest_AfterChangeSent_ThrowsAuthenticationFailed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession();

        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(
            new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true),
            ct);
        await handshookTask;

        int changeCallbackCount = 0;
        Task authTask = session.AuthenticateWithPasswordAsync(
            "user", "pass",
            _ =>
            {
                changeCallbackCount++;
                return Task.FromResult<string?>("newpass");
            },
            ct);

        // First request is the ordinary password request.
        RawPacket first = await mock.ServerPacketReader!.ReadPacketAsync(ct);
        Assert.Equal(PacketType.UserauthRequest, first.Type);
        await SendChangeRequestAsync(mock, ct);

        // Second request is the change-password request.
        RawPacket second = await mock.ServerPacketReader!.ReadPacketAsync(ct);
        Assert.Equal(PacketType.UserauthRequest, second.Type);
        await SendChangeRequestAsync(mock, ct);

        // The second CHANGEREQ after a change has already been sent must fail
        // fast instead of invoking the callback and looping forever.
        SshException ex = await Assert.ThrowsAsync<SshException>(() => authTask);
        Assert.Equal(SshErrorCode.AuthenticationFailed, ex.ErrorCode);
        Assert.Equal(1, changeCallbackCount);

        await session.DisposeAsync();
    }

    private static async Task SendChangeRequestAsync(MockSshServer mock, CancellationToken ct)
    {
        byte[] prompt = Encoding.ASCII.GetBytes("change");
        byte[] payload = new byte[1 + 4 + prompt.Length + 4];
        payload[0] = (byte)PacketType.UserauthPasswdChangereq;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), (uint)prompt.Length);
        prompt.CopyTo(payload, 5);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5 + prompt.Length, 4), 0);

        await mock.ServerPacketWriter!.WritePacketAsync(
            PacketType.UserauthPasswdChangereq, payload, ct);
    }
}
