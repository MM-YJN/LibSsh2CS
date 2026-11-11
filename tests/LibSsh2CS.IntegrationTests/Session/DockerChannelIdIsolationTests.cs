using System.Text;

using LibSsh2CS.IntegrationTests.DockerFixture;
using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.Session;

/// <summary>
/// Live integration check that concurrent channel opens receive distinct local
/// ids and stay isolated. Each channel runs a unique marker; if two opens share
/// a local id, registration aliases them and the marker can be delivered to the
/// wrong channel (or one open never completes).
/// </summary>
/// <remarks>
/// Kept below sshd's default <c>MaxSessions</c> (10) so the server accepts every
/// session channel. Gated like the other Docker tests: skips when Docker is not
/// reachable.
/// </remarks>
public sealed class DockerChannelIdIsolationTests : IDisposable
{
    private const int ChannelCount = 8;

    private readonly LoggerFactory _loggerFactory;
    private readonly AlpineNoKeySshImageFixture _alpineNoKey;

    public DockerChannelIdIsolationTests(
        AlpineNoKeySshImageFixture alpineNoKey,
        ITestOutputHelper testOutputHelper)
    {
        _alpineNoKey = alpineNoKey;
        _loggerFactory = new LoggerFactory([new XunitTestOutputLoggerProvider(testOutputHelper)]);
    }

    public void Dispose() => _loggerFactory.Dispose();

    [Fact]
    public async Task ConcurrentOpenSession_AllocatesDistinctIdsAndIsolatesExecOutput()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await using SshDockerContainer container = await _alpineNoKey.StartContainerAsync(
            _loggerFactory, cancellationToken);
        await using SshSession session = await SshDockerFixture.ConnectAsync(
            SshDockerFixture.Host, container.Port, cancellationToken);
        await session.AuthenticateWithPasswordAsync(
            SshDockerFixture.TestUser, SshDockerFixture.TestPassword,
            cancellationToken: cancellationToken);

        var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var openTasks = new Task<SshChannel>[ChannelCount];
        for (int i = 0; i < openTasks.Length; i++)
        {
            openTasks[i] = Task.Run(async () =>
            {
                await gate.Task.WaitAsync(cancellationToken);
                return await session.OpenSessionAsync(cancellationToken);
            }, cancellationToken);
        }

        gate.SetResult(true);

        SshChannel[]? channels = null;
        try
        {
            channels = await Task.WhenAll(openTasks)
                .WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            Assert.Equal(ChannelCount, channels.Select(channel => channel.LocalId).Distinct().Count());
            Assert.Equal(ChannelCount, channels.Select(channel => channel.RemoteId).Distinct().Count());

            Task<(string Output, int Exit)>[] executions = channels
                .Select((channel, index) => Task.Run(async () =>
                {
                    await channel.ExecAsync($"printf 'channel-{index}'", cancellationToken);
                    string output = await DrainStdoutToEndAsync(channel, cancellationToken);
                    int exit = await channel.GetExitStatusAsync(cancellationToken);
                    return (Output: output, Exit: exit);
                }, cancellationToken))
                .ToArray();

            (string Output, int Exit)[] results = await Task.WhenAll(executions)
                .WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            for (int i = 0; i < results.Length; i++)
            {
                Assert.Equal(0, results[i].Exit);
                Assert.Equal($"channel-{i}", results[i].Output);
            }
        }
        finally
        {
            if (channels is not null)
            {
                foreach (SshChannel channel in channels)
                {
                    await channel.DisposeAsync();
                }
            }
            else
            {
                // Preserve cleanup if one open failed while others completed.
                foreach (Task<SshChannel> openTask in openTasks)
                {
                    if (openTask.IsCompletedSuccessfully)
                    {
                        SshChannel completedChannel = await openTask;
                        await completedChannel.DisposeAsync();
                    }
                }
            }
        }
    }

    private static async Task<string> DrainStdoutToEndAsync(
        SshChannel channel, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = await channel.ReadAsync(buffer, cancellationToken)) > 0)
        {
            output.Write(buffer.AsSpan(0, read));
        }

        return Encoding.UTF8.GetString(output.ToArray());
    }
}
