using System.IO.Pipelines;

using Microsoft.Extensions.Time.Testing;

namespace LibSsh2CS.UnitTests.Session;

/// <summary>
/// Regression test: the auth entry points went
/// through <c>SshUserAuth.EnsureReady</c>, which checked the writer/queue and
/// the authenticated flag but never the session's disposed state — auth after
/// <c>DisposeAsync</c> surfaced a raw <c>ObjectDisposedException</c> from deep
/// inside <c>PacketWriter</c> (disposed <c>SemaphoreSlim</c>) instead of the
/// clean entry-point guard every other public <c>SshSession</c> member uses.
/// Managed-only lifecycle issue (the C API has no dispose).
/// </summary>
public class AuthDisposedGuardTests
{
    [Fact]
    public async Task AuthenticateAfterDispose_ThrowsObjectDisposedAtEntry()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using var mock = new MockSshServer();
        var session = new SshSession(new FakeTimeProvider());

        var serverTask = Task.Run(() => mock.RunAsync(
            "SSH-2.0-LibSsh2CS_" + LibSsh2Version.Version, ct), ct);
        await session.HandshakeAsync(new DuplexPipeFromPipes(mock.ClientReader, mock.ClientWriter),
            verifyHostKeyAsync: (_, _, _) => Task.FromResult(true), ct);
        await serverTask;

        await session.DisposeAsync();

        // Pre-fix: EnsureReady passed (writer/queue non-null, not authenticated)
        // and the auth flow hit the disposed PacketWriter's SemaphoreSlim — an
        // ObjectDisposedException whose ObjectName is "System.Threading.SemaphoreSlim".
        // Post-fix: the entry guard throws with ObjectName = the session type.
        ObjectDisposedException ex = await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            session.AuthenticateWithPasswordAsync("user", "pass", null, ct)
                .WaitAsync(TimeSpan.FromSeconds(10), ct));

        Assert.Equal(typeof(SshSession).FullName, ex.ObjectName);
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
