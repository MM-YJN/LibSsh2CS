using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LibSsh2CS.IntegrationTests.Transport;

/// <summary>
/// End-to-end check that a peer closing the transport mid-packet is reported
/// as a prompt disconnect. The in-process TCP peer sends a valid server banner
/// followed by a truncated SSH packet header, then half-closes its send side.
/// </summary>
/// <remarks>
/// This test uses loopback sockets directly (no Docker): the behavior under
/// test is the transport/pipe EOF path, not SSH interoperability.
/// </remarks>
public sealed class TruncatedPacketAtEofTests
{
    [Fact]
    public async Task Handshake_PartialPacketThenFin_ThrowsSocketDisconnectPromptly()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using TcpClient peer = await listener.AcceptTcpClientAsync(cancellationToken);
            NetworkStream stream = peer.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes("SSH-2.0-TruncatedPeer\r\n"), cancellationToken);
            await stream.WriteAsync(BuildPartialHeader(), cancellationToken);
            await stream.FlushAsync(cancellationToken);

            // FIN rather than RST: the client's banner/KEXINIT writes must not
            // fail before it observes the truncated frame.
            peer.Client.Shutdown(SocketShutdown.Send);

            byte[] drain = new byte[1024];
            try
            {
                while (await stream.ReadAsync(drain, cancellationToken) > 0)
                {
                }
            }
            catch (IOException)
            {
            }
            catch (SocketException)
            {
            }
        }, cancellationToken);

        using var client = new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);

            await using var session = new SshSession
            {
                // Large enough that the test fails if the reader spins to the
                // deadline; the disconnect must be detected before it.
                ReadTimeout = TimeSpan.FromSeconds(5),
            };

            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(15));

            var stopwatch = Stopwatch.StartNew();
            SshException ex = await Assert.ThrowsAsync<SshException>(async () =>
                await session.HandshakeAsync(
                    client.GetStream(),
                    (_, _, _) => Task.FromResult(true),
                    handshakeCts.Token));
            stopwatch.Stop();

            Assert.Equal(SshErrorCode.SocketDisconnect, ex.ErrorCode);
            Assert.Contains("truncated", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.True(
                stopwatch.Elapsed < TimeSpan.FromSeconds(4),
                $"handshake reported the disconnect after {stopwatch.Elapsed}.");
        }
        finally
        {
            // Unblock the peer's drain loop before waiting for its task.
            client.Dispose();
            listener.Stop();
        }

        await serverTask.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
    }

    /// <summary>
    /// A cleartext packet header declaring a 1000-byte packet, with no body:
    /// the cleartext reader needs 1004 wire bytes and can never get them.
    /// </summary>
    private static byte[] BuildPartialHeader()
    {
        byte[] header = new byte[5];
        BinaryPrimitives.WriteUInt32BigEndian(header, 1000u);
        header[4] = 4;
        return header;
    }
}
