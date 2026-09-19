using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// Increment 3.4.6 — end-to-end rekey-under-load tests. These exercise the
/// rekey auto-trigger and server-initiated rekey during actual channel data
/// flow (large reads, large writes, multi-channel routing), verifying the
/// trigger fires at the right point and the channel op resumes after the
/// (stubbed) rekey callback.
/// </summary>
/// <remarks>
/// All tests use <see cref="MockSshServer"/> for the handshake + encrypted
/// post-handshake transport. The rekey callback is a counting stub (doesn't
/// actually drive a second KEX — that would require the mock to implement a
/// rekey KEX exchange, which is the domain of the live Docker test in 3.5).
/// The goal is to verify the trigger fires at the right point in the data
/// flow and the channel op continues normally afterward.
/// </remarks>
public class RekeyUnderLoadTests
{
    // ── Large write with tiny byte threshold ────────────────────────────

    [Fact]
    public async Task LargeWrite_TinyByteThreshold_TriggersMidStream()
    {
        // Set a 4-byte threshold; writing 1KB triggers the rekey on the
        // next pump (which happens during the write's window-check loop or
        // the subsequent read). The write completes normally.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake)
        {
            RekeyPolicy = new RekeyPolicy { MaxBytes = 4, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
        };
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cancellationToken), cancellationToken);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await handshookTask;

        try
        {
            int rekeyCalls = 0;
            session.ChannelRouter!.ConfigureRekeyTrigger(
                session.RekeyPolicy,
                ct =>
                {
                    rekeyCalls++;
                    return Task.CompletedTask;
                });

            // Open a channel.
            byte[] openConf = BuildOpenConfirmationPayload(0, 100, ChannelConstants.WindowDefault, ChannelConstants.PacketDefault);
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.ChannelOpenConfirmation, openConf, cancellationToken);
            SshChannel ch = await session.OpenSessionAsync(cancellationToken);

            // Write 1KB. The write splits into chunks (WriteChunkCap=32700),
            // so it's one packet. The outbound counter bumps past 4 bytes.
            // The WINDOW_ADJUST from the server (the mock doesn't send one,
            // so we must feed one) is needed if the window is exhausted —
            // but with 2MB initial window, a 1KB write fits. After the write,
            // the next channel op (read) triggers MaybeRekey.
            byte[] data = new byte[1024];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(i & 0xFF);
            }
            await ch.WriteAsync(data, cancellationToken);

            // Drain the client→server pipe (the mock isn't reading).
            DrainPipe(mock.ServerReader!);

            // Feed a ChannelData + EOF so the read triggers MaybeRekey (which
            // fires because outbound bytes > 4) then routes the DATA and returns.
            byte[] dataPayload = BuildChannelDataPayload(0, [0x42]);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelData, dataPayload, cancellationToken);

            byte[] buf = new byte[8];
            int n = await ch.ReadAsync(buf, cancellationToken);
            Assert.Equal(1, n);
            Assert.Equal(0x42, buf[0]);
            Assert.True(rekeyCalls >= 1, $"rekey should fire at least once (got {rekeyCalls})");

            // Clean up: feed EOF + CLOSE.
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelEof, BuildEofPayload(0), cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelClose, BuildClosePayload(0), cancellationToken);
            await ch.DisposeAsync();
        }
        finally
        {
            mock.Dispose();
            await session.DisposeAsync();
        }
    }

    // ── Large read with tiny byte threshold ───────────────────────────

    [Fact]
    public async Task LargeRead_TinyByteThreshold_TriggersMidStream()
    {
        // Set a 4-byte threshold; reading a large DATA packet triggers the
        // rekey on the next pump (the read's PumpOnceAsync checks thresholds
        // before reading).
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake)
        {
            RekeyPolicy = new RekeyPolicy { MaxBytes = 4, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.MaxValue },
        };
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cancellationToken), cancellationToken);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await handshookTask;

        try
        {
            int rekeyCalls = 0;
            session.ChannelRouter!.ConfigureRekeyTrigger(
                session.RekeyPolicy,
                ct =>
                {
                    rekeyCalls++;
                    return Task.CompletedTask;
                });

            byte[] openConf = BuildOpenConfirmationPayload(0, 100, ChannelConstants.WindowDefault, ChannelConstants.PacketDefault);
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.ChannelOpenConfirmation, openConf, cancellationToken);
            SshChannel ch = await session.OpenSessionAsync(cancellationToken);

            // Feed a large DATA packet (256 bytes). The read's PumpOnceAsync
            // checks thresholds — the inbound counter is already > 4 (from the
            // OpenConfirmation). The trigger fires, then the DATA is read.
            byte[] data = new byte[256];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(i & 0xFF);
            }
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelData, BuildChannelDataPayload(0, data), cancellationToken);

            byte[] buf = new byte[512];
            int n = await ch.ReadAsync(buf, cancellationToken);
            Assert.Equal(256, n);
            Assert.Equal(data, buf.AsSpan(0, n).ToArray());
            Assert.True(rekeyCalls >= 1, $"rekey should fire at least once (got {rekeyCalls})");

            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelEof, BuildEofPayload(0), cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelClose, BuildClosePayload(0), cancellationToken);
            await ch.DisposeAsync();
        }
        finally
        {
            mock.Dispose();
            await session.DisposeAsync();
        }
    }

    // ── Server-initiated rekey mid-read ─────────────────────────────────

    [Fact]
    public async Task ServerInitiatedRekey_MidRead_ReadResumes()
    {
        // Feed a KEXINIT (server rekey), then a DATA packet; the read's
        // PumpOnceAsync sees the KEXINIT, invokes the rekey callback, then
        // continues reading the DATA.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake);
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cancellationToken), cancellationToken);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await handshookTask;

        try
        {
            int serverRekeyCalls = 0;
            session.Queue!.RekeyTriggerAsync = ct =>
            {
                serverRekeyCalls++;
                return Task.CompletedTask;
            };

            byte[] openConf = BuildOpenConfirmationPayload(0, 100, ChannelConstants.WindowDefault, ChannelConstants.PacketDefault);
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.ChannelOpenConfirmation, openConf, cancellationToken);
            SshChannel ch = await session.OpenSessionAsync(cancellationToken);

            // Feed KEXINIT + DATA.
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.KexInit, (byte[])[20], cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelData, BuildChannelDataPayload(0, [0x99]), cancellationToken);

            byte[] buf = new byte[8];
            int n = await ch.ReadAsync(buf, cancellationToken);
            Assert.Equal(1, serverRekeyCalls);
            Assert.Equal(1, n);
            Assert.Equal(0x99, buf[0]);

            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelEof, BuildEofPayload(0), cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelClose, BuildClosePayload(0), cancellationToken);
            await ch.DisposeAsync();
        }
        finally
        {
            mock.Dispose();
            await session.DisposeAsync();
        }
    }

    // ── Server-initiated rekey mid-write ──────────────────────────────

    [Fact]
    public async Task ServerInitiatedRekey_MidWrite_WriteResumes()
    {
        // The write's window-check loop calls PumpOnceAsync when the window
        // is exhausted; if a KEXINIT arrives during that pump, the rekey callback
        // fires, then the write continues when a WINDOW_ADJUST arrives.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake);
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cancellationToken), cancellationToken);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await handshookTask;

        try
        {
            int serverRekeyCalls = 0;
            session.Queue!.RekeyTriggerAsync = ct =>
            {
                serverRekeyCalls++;
                return Task.CompletedTask;
            };

            // Open a channel with a tiny outbound window so the write blocks.
            byte[] openConf = BuildOpenConfirmationPayload(0, 100, window: 4, maxPacket: ChannelConstants.PacketDefault);
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.ChannelOpenConfirmation, openConf, cancellationToken);
            SshChannel ch = await session.OpenSessionAsync(cancellationToken);

            // Start a write that exceeds the 4-byte window — it blocks on
            // the zero-window path, calling PumpOnceAsync. Feed a KEXINIT
            // (rekey), then a WINDOW_ADJUST to unblock.
            byte[] data = new byte[64];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)i;
            }
            var writeTask = Task.Run(async () => await ch.WriteAsync(data, cancellationToken), cancellationToken);

            // Give the write a moment to enter the zero-window loop.
            await Task.Delay(50, cancellationToken);

            // Feed KEXINIT (server rekey), then WINDOW_ADJUST (unblocks write).
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.KexInit, (byte[])[20], cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelWindowAdjust, BuildWindowAdjustPayload(0, 1024), cancellationToken);

            await writeTask;
            Assert.Equal(1, serverRekeyCalls);

            // Drain the client→server pipe.
            DrainPipe(mock.ServerReader!);

            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelEof, BuildEofPayload(0), cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelClose, BuildClosePayload(0), cancellationToken);
            await ch.DisposeAsync();
        }
        finally
        {
            mock.Dispose();
            await session.DisposeAsync();
        }
    }

    // ── Never policy: no fire under load ──────────────────────────────

    [Fact]
    public async Task NeverPolicy_LargeTransfer_NoRekeyFires()
    {
        // With RekeyPolicy.Never, even a large transfer must NOT fire the
        // auto-trigger. The transfer completes normally.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake)
        {
            RekeyPolicy = RekeyPolicy.Never,
        };
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cancellationToken), cancellationToken);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await handshookTask;

        try
        {
            int rekeyCalls = 0;
            session.ChannelRouter!.ConfigureRekeyTrigger(
                session.RekeyPolicy,
                ct =>
                {
                    rekeyCalls++;
                    return Task.CompletedTask;
                });

            byte[] openConf = BuildOpenConfirmationPayload(0, 100, ChannelConstants.WindowDefault, ChannelConstants.PacketDefault);
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.ChannelOpenConfirmation, openConf, cancellationToken);
            SshChannel ch = await session.OpenSessionAsync(cancellationToken);

            // Write 2KB; read 2KB. Both should complete with no rekey fires.
            byte[] writeData = new byte[2048];
            for (int i = 0; i < writeData.Length; i++)
            {
                writeData[i] = (byte)(i & 0xFF);
            }
            await ch.WriteAsync(writeData, cancellationToken);
            DrainPipe(mock.ServerReader!);

            byte[] readData = new byte[2048];
            for (int i = 0; i < readData.Length; i++)
            {
                readData[i] = (byte)(0xFF - (i & 0xFF));
            }
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelData, BuildChannelDataPayload(0, readData), cancellationToken);

            byte[] buf = new byte[4096];
            int totalRead = 0;
            while (totalRead < readData.Length)
            {
                int n = await ch.ReadAsync(buf.AsMemory(totalRead), cancellationToken);
                if (n == 0)
                {
                    break;
                }
                totalRead += n;
            }

            Assert.Equal(readData.Length, totalRead);
            Assert.Equal(0, rekeyCalls);

            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelEof, BuildEofPayload(0), cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelClose, BuildClosePayload(0), cancellationToken);
            await ch.DisposeAsync();
        }
        finally
        {
            mock.Dispose();
            await session.DisposeAsync();
        }
    }

    // ── Time-based trigger under load ──────────────────────────────────

    [Fact]
    public async Task TimeTrigger_FiresDuringRead_UnderLoad()
    {
        // Advance the FakeTimeProvider past the 30-minute threshold; the
        // next channel read's MaybeRekey fires.
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var fake = new FakeTimeProvider();
        var session = new SshSession(fake)
        {
            RekeyPolicy = new RekeyPolicy { MaxBytes = long.MaxValue, MaxPackets = long.MaxValue, MaxInterval = TimeSpan.FromMinutes(30) },
        };
        var handshookTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, cancellationToken), cancellationToken);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), cancellationToken);
        await handshookTask;

        try
        {
            int rekeyCalls = 0;
            session.ChannelRouter!.ConfigureRekeyTrigger(
                session.RekeyPolicy,
                ct =>
                {
                    rekeyCalls++;
                    return Task.CompletedTask;
                });

            byte[] openConf = BuildOpenConfirmationPayload(0, 100, ChannelConstants.WindowDefault, ChannelConstants.PacketDefault);
            await mock.ServerPacketWriter!.WritePacketAsync(PacketType.ChannelOpenConfirmation, openConf, cancellationToken);
            SshChannel ch = await session.OpenSessionAsync(cancellationToken);

            // Advance time past the threshold.
            fake.Advance(TimeSpan.FromHours(1));

            // Feed a DATA packet; the read's MaybeRekey fires (time exceeded),
            // then the DATA is routed.
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelData, BuildChannelDataPayload(0, [0x77]), cancellationToken);

            byte[] buf = new byte[8];
            int n = await ch.ReadAsync(buf, cancellationToken);
            Assert.Equal(1, n);
            Assert.Equal(0x77, buf[0]);
            Assert.True(rekeyCalls >= 1, $"rekey should fire on time threshold (got {rekeyCalls})");

            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelEof, BuildEofPayload(0), cancellationToken);
            await mock.ServerPacketWriter.WritePacketAsync(PacketType.ChannelClose, BuildClosePayload(0), cancellationToken);
            await ch.DisposeAsync();
        }
        finally
        {
            mock.Dispose();
            await session.DisposeAsync();
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static void DrainPipe(PipeReader reader)
    {
        ReadResult rr = reader.ReadAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
        reader.AdvanceTo(rr.Buffer.End);
    }

    private static byte[] BuildOpenConfirmationPayload(
        uint recipientChannel, uint senderChannel, uint window, uint maxPacket)
    {
        byte[] payload = new byte[17];
        payload[0] = (byte)PacketType.ChannelOpenConfirmation;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), senderChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), window);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(13, 4), maxPacket);
        return payload;
    }

    private static byte[] BuildChannelDataPayload(uint recipientChannel, byte[] data)
    {
        byte[] payload = new byte[1 + 4 + 4 + data.Length];
        payload[0] = (byte)PacketType.ChannelData;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), (uint)data.Length);
        Buffer.BlockCopy(data, 0, payload, 9, data.Length);
        return payload;
    }

    private static byte[] BuildEofPayload(uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelEof;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }

    private static byte[] BuildClosePayload(uint recipientChannel)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)PacketType.ChannelClose;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        return payload;
    }

    private static byte[] BuildWindowAdjustPayload(uint recipientChannel, uint bytesToAdd)
    {
        byte[] payload = new byte[9];
        payload[0] = (byte)PacketType.ChannelWindowAdjust;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), recipientChannel);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), bytesToAdd);
        return payload;
    }

    private sealed class DuplexPipeFromPipes : IDuplexPipe
    {
        public DuplexPipeFromPipes(PipeReader input, PipeWriter output)
        {
            Input = input;
            Output = output;
        }

        public PipeReader Input { get; }
        public PipeWriter Output { get; }
    }
}
