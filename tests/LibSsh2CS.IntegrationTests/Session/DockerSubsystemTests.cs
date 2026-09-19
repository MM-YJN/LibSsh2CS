using System.Buffers.Binary;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration tests for <see cref="SshChannel.SubsystemAsync"/>: opens
/// a session channel against a real OpenSSH server in Docker (via the shared
/// <see cref="DebianSftpSshImageFixture"/> assembly fixture, whose sshd
/// config re-enables <c>Subsystem sftp /usr/lib/openssh/sftp-server</c>),
/// requests the <c>"sftp"</c> subsystem, and verifies the
/// <c>SSH_MSG_CHANNEL_REQUEST "subsystem"</c> round-trip + a minimal SFTP
/// protocol handshake over the channel data stream.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the SFTP handshake and not just the subsystem request.</b> A bare
/// <c>SubsystemAsync("sftp")</c> only proves the server replied
/// <c>SSH_MSG_CHANNEL_SUCCESS</c>. The SFTP-level
/// <c>SSH_FXP_INIT → SSH_FXP_VERSION</c> exchange proves the
/// <c>sftp-server</c> child process was actually spawned on the channel and
/// that the channel data path carries real SFTP traffic in both directions
/// — a stronger end-to-end check that the subsystem is genuinely usable.
/// </para>
/// <para>
/// <b>Out-of-scope SFTP client.</b> LibSsh2CS exposes the channel only; a
/// full SFTP client built on top is outside the scope of these tests.
/// This test hand-codes the two SFTP
/// handshake packets (12 bytes total) rather than pulling in an SFTP
/// library.
/// </para>
/// <para>
/// <b>Gating:</b> <see cref="SshImageFixtureBase.StartContainerAsync"/>
/// calls <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> internally,
/// so tests skip (not fail) when Docker is not reachable.
/// </para>
/// </remarks>
public sealed class DockerSubsystemTests : IDisposable
{
    private readonly LoggerFactory _loggerFactory;
    private readonly DebianSftpSshImageFixture _debianSftp;

    public DockerSubsystemTests(
        DebianSftpSshImageFixture debianSftp,
        ITestOutputHelper testOutputHelper)
    {
        _debianSftp = debianSftp;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    /// <summary>
    /// Requests the <c>"sftp"</c> subsystem on a session channel against a
    /// live OpenSSH server, then runs the minimal SFTP protocol handshake
    /// (send <c>SSH_FXP_INIT</c> version 3, read <c>SSH_FXP_VERSION</c>)
    /// over the channel. Lights up <see cref="SshChannel.SubsystemAsync"/>
    /// (0% → covered) and proves the <c>sftp-server</c> child process is
    /// actually spawned and reachable through the channel data path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>SFTP packet layout.</b> Every SFTP packet is
    /// <c>[u32 length][byte type][u32 id][payload]</c>. The
    /// <c>SSH_FXP_INIT</c> packet (type 1) carries only a <c>u32</c>
    /// version; the <c>SSH_FXP_VERSION</c> reply (type 2) carries a
    /// <c>u32</c> version (and optional extensions, which this test does
    /// not parse). See RFC draft-ietf-secsh-filexfer-02 §4.
    /// </para>
    /// <para>
    /// <b>Why <c>SubstantialReadAsync</c> instead of a single
    /// <see cref="SshChannel.ReadAsync"/>.</b> The <c>SSH_FXP_VERSION</c>
    /// reply is a 5-byte SFTP packet (4-byte length + 1-byte type + 4-byte
    /// version — minus the 4-byte length prefix that the channel strips),
    /// but the server may also send a <c>SSH_FXP_VERSION</c> with
    /// extension name/value pairs. A single read may return a partial
    /// packet; the loop drains until at least 9 bytes (4 length + 1 type +
    /// 4 version) are available, which is enough to verify the version.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Subsystem_Sftp_AcceptedAndHandshakeRoundTrips()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _debianSftp.StartContainerAsync(
            _loggerFactory, ct);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, ct);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: ct);

        await using SshChannel channel = await session.OpenSessionAsync(ct);

        // Request the "sftp" subsystem. OpenSSH spawns sftp-server and replies
        // SSH_MSG_CHANNEL_SUCCESS; SubsystemAsync throws on CHANNEL_FAILURE.
        await channel.SubsystemAsync("sftp", ct);

        // ── SFTP handshake: SSH_FXP_INIT (version 3) → SSH_FXP_VERSION ──
        // Packet: [u32 length=5][byte type=1 SSH_FXP_INIT][u32 version=3].
        // The length field counts everything AFTER itself (type + version = 5).
        byte[] initPacket = new byte[9];
        BinaryPrimitives.WriteUInt32BigEndian(initPacket.AsSpan(0, 4), 5);     // length
        initPacket[4] = 1;                                                     // SSH_FXP_INIT
        BinaryPrimitives.WriteUInt32BigEndian(initPacket.AsSpan(5, 4), 3);     // version 3
        await channel.WriteAsync(initPacket, ct);

        // Read the SSH_FXP_VERSION reply. The channel delivers the SFTP packet
        // verbatim (including the 4-byte length prefix). Drain until we have at
        // least 9 bytes (length + type + version).
        using var ms = new MemoryStream();
        byte[] buf = new byte[256];
        int n;
        while (ms.Length < 9 && (n = await channel.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf.AsSpan(0, n));
        }

        byte[] reply = ms.ToArray();
        Assert.True(reply.Length >= 9, $"expected >= 9 bytes of SFTP version reply, got {reply.Length}");

        // Parse the SSH_FXP_VERSION: [u32 length][byte type=2][u32 version].
        uint replyLen = BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(0, 4));
        byte replyType = reply[4];
        uint replyVersion = BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(5, 4));

        Assert.Equal(2u, replyType);              // SSH_FXP_VERSION
        Assert.Equal(3u, replyVersion);           // sftp-server speaks version 3
        Assert.True(replyLen >= 5, "SSH_FXP_VERSION length must cover type + version");
    }
}
