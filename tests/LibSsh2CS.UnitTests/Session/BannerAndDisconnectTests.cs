using System.Buffers.Binary;
using System.IO.Pipelines;

using LibSsh2CS.Transport;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Regression tests for banner read limits and disconnect field byte lengths.
/// </summary>
public class BannerAndDisconnectTests
{
    // ── a newline-less banner must terminate the read loop ──────────

    /// <summary>
    /// The C's <c>banner_receive</c> (session.c:121) exits its read loop when
    /// the banner buffer fills and proceeds with the (possibly newline-less)
    /// line; the pre-fix port kept consuming bytes and waited for <c>\n</c>
    /// forever (until the 60 s ReadTimeout), silently eating the server's
    /// KEXINIT. Post-fix the 8192-byte newline-less banner is processed as a
    /// line and the handshake completes.
    /// </summary>
    [Fact]
    public async Task Handshake_NewlineLessBanner_FillsBufferAndProceeds()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer
        {
            // 8192 bytes, no newline, SSH- prefix — fills the port's
            // MaxBannerLen buffer exactly.
            BannerOverride = "SSH-2.0-" + new string('x', 8192 - 8),
        };
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);

        // Pre-fix the banner read consumed everything (including the server's
        // KEXINIT) waiting for a newline and hung — the bounded wait turns
        // that into a failure.
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct)
            .WaitAsync(TimeSpan.FromSeconds(10), ct);
        await serverTask;

        await session.DisposeAsync();
    }

    // ── DISCONNECT description measured in UTF-8 BYTES ──────────────

    /// <summary>
    /// The C errors <c>LIBSSH2_ERROR_INVAL</c> "too long description" when
    /// <c>strlen(description) &gt; 256</c> (session.c:1207-1212 — BYTES). The
    /// pre-fix port truncated at 256 CHARACTERS, so a multi-byte description
    /// shipped an over-long field. Post-fix the byte length is measured and an
    /// over-long description throws Inval exactly like the C.
    /// </summary>
    [Fact]
    public async Task Disconnect_DescriptionOver256Utf8Bytes_ThrowsInval()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        // 200 × "é" = 400 UTF-8 bytes (> 256) but only 200 chars (≤ 256).
        // Pre-fix the char-truncation let it through and the DISCONNECT was
        // sent with a 400-byte field — the C rejects it.
        string description = new('é', 200);

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.DisconnectAsync(SshDisconnectReason.ByApplication, description, cancellationToken: ct)
                .WaitAsync(TimeSpan.FromSeconds(10), ct));
        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
        Assert.Contains("too long description", ex.Message);

        // Sanity: a description that fits in 256 BYTES (but not 256 chars is
        // impossible — bytes ≥ chars; use a 200-char ASCII string) still sends.
        await session.DisconnectAsync(SshDisconnectReason.ByApplication, new string('a', 200),
            cancellationToken: ct);
        _ = await mock.ServerPacketReader!.ReadPacketAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);

        await session.DisposeAsync();
    }

    [Fact]
    public async Task Disconnect_LangOver256Bytes_ThrowsInval()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        string lang = new('é', 200);   // 400 UTF-8 bytes

        SshException ex = await Assert.ThrowsAsync<SshException>(() =>
            session.DisconnectAsync(SshDisconnectReason.ByApplication, "bye", lang, ct)
                .WaitAsync(TimeSpan.FromSeconds(10), ct));
        Assert.Equal(SshErrorCode.Inval, ex.ErrorCode);
        Assert.Contains("too long language string", ex.Message);

        await session.DisposeAsync();
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
