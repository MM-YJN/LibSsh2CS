using System.Reflection;

using Docker.DotNet.Models;

using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Images;

using Microsoft.Extensions.Logging.Abstractions;

using Xunit.Sdk;

namespace LibSsh2CS.IntegrationTests.DockerFixture;

public sealed class SshImageCacheTests(AlpineNoKeySshImageFixture imageFixture)
{
    [Fact]
    public void Identity_IsCanonicalAndInvalidatesInputs()
    {
        string name = SshImageFixtureBase.GetImageName("FROM alpine\n", "4.14.0");
        Assert.Matches("^localhost/libssh2cs-tests/sshd:[0-9a-f]{64}$", name);
        Assert.Equal(name, SshImageFixtureBase.GetImageName("FROM alpine\r\n", "4.14.0"));
        Assert.NotEqual(name, SshImageFixtureBase.GetImageName("FROM debian\n", "4.14.0"));
        Assert.NotEqual(name, SshImageFixtureBase.GetImageName("FROM alpine\n", "4.15.0"));
    }

    [Fact]
    public async Task AuthorizedKey_ChangesIdentity()
    {
        await using var first = new StubFixture("ssh-ed25519 AAAA");
        await using var second = new StubFixture("ssh-ed25519 BBBB");
        Assert.NotEqual(
            SshImageFixtureBase.GetImageName(first.GetDockerfile(), "4.14.0"),
            SshImageFixtureBase.GetImageName(second.GetDockerfile(), "4.14.0"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Configuration_PreservesImagesWithStableLabels(bool refresh)
    {
        ImageFromDockerfileBuilder builder = SshImageFixtureBase.ConfigureImage(new ImageFromDockerfileBuilder(), refresh);
        // Inspect the pinned builder's protected configuration without contacting Docker.
        var configuration = (IImageFromDockerfileConfiguration)typeof(ImageFromDockerfileBuilder)
            .GetProperty("DockerResourceConfiguration", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)!.GetValue(builder)!;
        Assert.Equal(Guid.Empty, configuration.SessionId);
        Assert.Equal(Guid.Empty.ToString("D"), configuration.Labels["org.testcontainers.session-id"]);
        Assert.Equal(Guid.Empty.ToString("D"), configuration.Labels["org.testcontainers.resource-reaper-session"]);
        Assert.Equal("true", configuration.Labels["org.libssh2cs.integration-image"]);
        Assert.False(configuration.DeleteIfExists);
        Assert.True(configuration.ImageBuildPolicy(null!));
        Assert.Equal(refresh, configuration.ImageBuildPolicy(new ImageInspectResponse()));
        var parameters = new ImageBuildParameters();
        foreach (Action<ImageBuildParameters> modifier in configuration.ParameterModifiers)
        {
            modifier(parameters);
        }
        Assert.Equal(refresh, parameters.NoCache == true);
        Assert.Equal(refresh ? "true" : null, parameters.Pull);
    }

    [Fact]
    public async Task UnusedFixture_DoesNotPrepareImage()
    {
        await using var fixture = new StubFixture();
        await fixture.InitializeAsync();
        Assert.Equal(0, fixture.Attempts);
    }

    [Fact]
    public async Task ConcurrentFirstUse_PreparesOnce()
    {
        await using var fixture = new StubFixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Prepare = async ct =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(ct);
        };
        Task<IFutureDockerImage> first = fixture.EnsureImageAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Task<IFutureDockerImage>[] others = Enumerable.Range(0, 8)
            .Select(_ => fixture.EnsureImageAsync(TestContext.Current.CancellationToken)).ToArray();
        release.SetResult();
        IFutureDockerImage image = await first;
        foreach (IFutureDockerImage other in await Task.WhenAll(others))
        {
            Assert.Same(image, other);
        }
        Assert.Equal(1, fixture.Attempts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrCanceledPreparation_CanRetry(bool cancel)
    {
        await using var fixture = new StubFixture();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        fixture.Prepare = async ct =>
        {
            Assert.Equal(cancellation.Token, ct);
            if (cancel)
            {
                await cancellation.CancelAsync();
                ct.ThrowIfCancellationRequested();
            }
            throw new InvalidOperationException("Preparation failed");
        };
        if (cancel)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.EnsureImageAsync(cancellation.Token));
        }
        else
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.EnsureImageAsync(cancellation.Token));
        }
        fixture.Prepare = _ => Task.CompletedTask;
        await fixture.EnsureImageAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, fixture.Attempts);
        Assert.All(fixture.ContextDirectories, directory => Assert.False(Directory.Exists(directory)));
    }

    [Fact]
    public async Task CanceledWaiter_DoesNotInterruptPreparation()
    {
        await using var fixture = new StubFixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Prepare = async ct =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(ct);
        };
        Task<IFutureDockerImage> first = fixture.EnsureImageAsync(TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();
        Task<IFutureDockerImage> waiter = fixture.EnsureImageAsync(cancellation.Token);
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);
        release.SetResult();
        Assert.Same(await first, await fixture.EnsureImageAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, fixture.Attempts);
    }

    [Fact]
    public async Task Containers_IsolateFilesystemAndShareHostKeys()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SshDockerContainer first = await imageFixture.StartContainerAsync(NullLoggerFactory.Instance, ct);
        await first.ExecAsync("touch /tmp/libssh2cs-isolation", ct);
        await using SshDockerContainer second = await imageFixture.StartContainerAsync(NullLoggerFactory.Instance, ct);
        Assert.NotEqual(first.Port, second.Port);
        await second.ExecAsync("test ! -e /tmp/libssh2cs-isolation", ct);
        Assert.Equal(await first.GetHostKeyAsync("ed25519", ct), await second.GetHostKeyAsync("ed25519", ct));
    }

    private sealed class Sink : IMessageSink
    {
        public bool OnMessage(IMessageSinkMessage message) => true;
    }

    private sealed class StubFixture(string? key = null) : SshImageFixtureBase(new Sink())
    {
        public int Attempts { get; private set; }
        public List<string> ContextDirectories { get; } = [];
        public Func<CancellationToken, Task> Prepare { get; set; } = _ => Task.CompletedTask;
        protected override SshImageSpec Spec => new("FROM alpine:3.20", "RUN true", "RUN true", SshdConfigAuthAlpine);
        protected override string? AuthorizedKey => key;

        internal override IFutureDockerImage BuildImage(ImageFromDockerfileBuilder builder)
        {
            var configuration = (IImageFromDockerfileConfiguration)typeof(ImageFromDockerfileBuilder)
                .GetProperty("DockerResourceConfiguration", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)!.GetValue(builder)!;
            ContextDirectories.Add(configuration.DockerfileDirectory);
            // An explicit endpoint lets these tests run without Docker discovery or a daemon.
            return builder.WithDockerEndpoint("unix:///var/run/docker.sock").Build();
        }

        internal override Task CreateImageAsync(IFutureDockerImage image, CancellationToken ct)
        {
            Attempts++;
            return Prepare(ct);
        }
    }
}
