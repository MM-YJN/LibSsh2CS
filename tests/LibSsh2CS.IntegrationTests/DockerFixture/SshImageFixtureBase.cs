using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;

using LibSsh2CS.IntegrationTests.TestKit.Logger;

using Microsoft.Extensions.Logging;

using Xunit.Sdk;

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>
/// Prepares a cached SSH image on first use, shared by this variant's tests.
/// Unused fixtures do no Docker work. Images survive fixture disposal and
/// subsequent runs; each test still starts and disposes a fresh container.
/// </summary>
public abstract class SshImageFixtureBase(IMessageSink messageSink) : IAsyncLifetime
{
    private const int SshPort = 22;
    private static readonly Action<ILogger, string, string, string, double, string, Exception?> s_logPreparation =
        LoggerMessage.Define<string, string, string, double, string>(LogLevel.Information, new EventId(1),
            "SSH image {Variant} {Image} preparation {Result} in {DurationMs} ms ({Mode})");

    // sshd offering all 7 in-scope hostkey types + the in-scope
    // kex/cipher/mac, WITH compression + AcceptEnv enabled. The `\\n`
    // escapes are expanded to real newlines by `printf` in the Dockerfile
    // RUN. The per-image auth preamble
    // (SshdConfigAuthAlpine / SshdConfigAuthDebian / SshdConfigNoAuth) is
    // appended after this shared block.
    //
    // The cipher/mac/kex name-lists cover every in-scope algorithm so the
    // negotiation-matrix tests (Transport/DockerNegotiationTests) can pin
    // the client side to any single algorithm via
    // SshSession[SshMethodType.*] and still find a match here. Hostkey
    // algorithms cover all 7 in-scope types so the hostkey-negotiation
    // tests can pin any of them.
    //
    // Auth directives (PubkeyAuthentication / PasswordAuthentication) are
    // intentionally NOT in this shared block: sshd_config uses
    // first-value-wins, so appending "no" after "yes" would not disable
    // auth. Each variant's <see cref="SshImageSpec.AuthConfig"/> carries
    // the auth directives appropriate to that variant.
    private const string SshdConfigBase =
        "Port 22\\n" +
        "ListenAddress 0.0.0.0\\n" +
        "PermitRootLogin yes\\n" +
        "Compression yes\\n" +
        // AcceptEnv: OpenSSH denies every env CHANNEL_REQUEST unless the
        // variable name matches an AcceptEnv pattern. The LIBSSH2CS_*
        // pattern lets the SetEnv integration test deliver test-only
        // variables without affecting any other sshd behavior.
        "AcceptEnv LIBSSH2CS_*\\n" +
        "HostKey /etc/ssh/ssh_host_rsa_key\\n" +
        "HostKey /etc/ssh/ssh_host_ecdsa_key\\n" +
        "HostKey /etc/ssh/ssh_host_ecdsa_384_key\\n" +
        "HostKey /etc/ssh/ssh_host_ecdsa_521_key\\n" +
        "HostKey /etc/ssh/ssh_host_ed25519_key\\n" +
        "PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521\\n" +
        "HostKeyAlgorithms +ssh-rsa,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521\\n" +
        "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256\\n" +
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc\\n" +
        "MACs hmac-sha2-256,hmac-sha2-512\\n";

    // Per-image auth preamble (appended after SshdConfigBase).
    //
    // Alpine: openssh-server is built WITHOUT libpam linkage, so kbdint is
    // unavailable regardless of KbdInteractiveAuthentication / UsePAM.
    // Debian: openssh-server is PAM-linked; the default /etc/pam.d/sshd
    // pulls in pam_unix.so via @include common-auth, which drives the
    // USERAUTH_INFO_REQUEST password challenge end-to-end.
    // NoAuth: disables both password + pubkey auth (for the
    // transport-handshake-only test that never reaches userauth).

    /// <summary>Alpine auth preamble: password + pubkey enabled, PAM disabled (kbdint unavailable on Alpine's openssh-server).</summary>
    protected internal const string SshdConfigAuthAlpine =
        "PubkeyAuthentication yes\\n" +
        "PasswordAuthentication yes\\n" +
        "UsePAM no\\n";

    /// <summary>Debian auth preamble: password + pubkey + kbdint enabled (PAM-linked sshd drives the USERAUTH_INFO_REQUEST challenge).</summary>
    protected internal const string SshdConfigAuthDebian =
        "PubkeyAuthentication yes\\n" +
        "PasswordAuthentication yes\\n" +
        "UsePAM yes\\n" +
        "KbdInteractiveAuthentication yes\\n" +
        "ChallengeResponseAuthentication yes\\n";

    /// <summary>No-auth preamble: disables both password + pubkey auth (transport-handshake-only tests that never reach userauth).</summary>
    protected internal const string SshdConfigNoAuth =
        "PubkeyAuthentication no\\n" +
        "PasswordAuthentication no\\n" +
        "UsePAM no\\n";

    /// <summary>
    /// Per-image Dockerfile assembly bits: FROM line, package install +
    /// hostkey bootstrap, user-creation command, and auth-specific sshd
    /// config preamble.
    /// </summary>
    protected internal sealed record SshImageSpec(
        string FromLine,
        string InstallAndKeygen,
        string CreateUserCmd,
        string AuthConfig);

    private readonly LoggerFactory _loggerFactory = new([new XunitMessageSinkLoggerProvider(messageSink)]);
    private IFutureDockerImage? _image;
    private readonly SemaphoreSlim _preparationLock = new(1, 1);

    /// <summary>The Dockerfile assembly bits for this fixture's variant; supplied by the subclass.</summary>
    protected abstract SshImageSpec Spec { get; }

    /// <summary>
    /// Optional authorized_key line to bake into the image's
    /// <c>authorized_keys</c> (<see cref="AlpineWithEd25519KeySshImageFixture"/>
    /// loads the test Ed25519 public key,
    /// <see cref="AlpineWithRsaKeySshImageFixture"/> loads the test RSA
    /// public key). Null by default.
    /// </summary>
    protected virtual string? AuthorizedKey => null;

    /// <inheritdoc/>
    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    internal string GetDockerfile()
    {
        SshImageSpec spec = Spec;
        string sshdConfig = SshdConfigBase + spec.AuthConfig;
        string dockerfile =
            spec.FromLine + "\n" +
            spec.InstallAndKeygen + "\n" +
            $"RUN printf '{sshdConfig}' > /etc/ssh/sshd_config\n" +
            spec.CreateUserCmd + "\n";

        // Only create the test user + .ssh dir when the variant actually
        // creates a user (the no-auth handshake-only variant leaves
        // CreateUserCmd empty and skips this block entirely).
        if (spec.CreateUserCmd.Length > 0)
        {
            dockerfile += "RUN mkdir -p /home/" + SshDockerFixture.TestUser + "/.ssh && chmod 700 /home/" + SshDockerFixture.TestUser + "/.ssh\n";

            if (AuthorizedKey is not null)
            {
                // Base64-encode the key line to avoid any shell-quoting issues
                // in the Dockerfile RUN. The container decodes it before writing
                // to authorized_keys. This sidesteps single-quote, double-quote,
                // backslash, and newline handling entirely.
                string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(AuthorizedKey.TrimEnd()));
                dockerfile += "RUN echo '" + b64 + "' | base64 -d > /home/" + SshDockerFixture.TestUser +
                    "/.ssh/authorized_keys && chmod 600 /home/" + SshDockerFixture.TestUser +
                    "/.ssh/authorized_keys && chown -R " + SshDockerFixture.TestUser + ":" + SshDockerFixture.TestUser +
                    " /home/" + SshDockerFixture.TestUser + "/.ssh\n";
            }
        }

        dockerfile += "EXPOSE 22\nCMD [\"/usr/sbin/sshd\", \"-D\", \"-e\"]\n";

        return dockerfile.ReplaceLineEndings("\n");
    }

    internal static string GetImageName(string dockerfile, string builderVersion)
    {
        const string cacheFormatVersion = "1";
        byte[] identity = Encoding.UTF8.GetBytes(
            cacheFormatVersion + "\n" + builderVersion + "\n" + dockerfile.ReplaceLineEndings("\n"));
        return "localhost/libssh2cs-tests/sshd:" + Convert.ToHexStringLower(SHA256.HashData(identity));
    }

    internal static ImageFromDockerfileBuilder ConfigureImage(ImageFromDockerfileBuilder builder, bool refresh)
    {
        builder = builder
            .WithImageBuildPolicy(refresh ? PullPolicy.Always : PullPolicy.Missing)
            .WithDeleteIfExists(false)
            .WithCleanUp(false)
            .WithLabel("org.testcontainers.session-id", Guid.Empty.ToString("D"))
            .WithLabel("org.libssh2cs.integration-image", "true");
        return refresh
            ? builder.WithCreateParameterModifier(parameters =>
            {
                parameters.NoCache = true;
                parameters.Pull = "true";
            })
            : builder;
    }

    internal async Task<IFutureDockerImage> EnsureImageAsync(CancellationToken ct)
    {
        await _preparationLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_image is not null)
            {
                return _image;
            }

            string dockerfile = GetDockerfile();
            string version = typeof(ImageFromDockerfileBuilder).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
            string name = GetImageName(dockerfile, version);
            bool refresh = Environment.GetEnvironmentVariable("LIBSSH2CS_TEST_IMAGE_REFRESH") == "1";
            ILogger logger = _loggerFactory.CreateLogger<SshImageFixtureBase>();
            long started = Stopwatch.GetTimestamp();
            string tempDir = Path.Combine(Path.GetTempPath(), "libssh2cs-ssh-" + Guid.NewGuid().ToString("N"));
            IFutureDockerImage? image = null;
            try
            {
                Directory.CreateDirectory(tempDir);
                await File.WriteAllTextAsync(Path.Combine(tempDir, "Dockerfile"), dockerfile, new UTF8Encoding(false), ct).ConfigureAwait(false);
                image = BuildImage(ConfigureImage(new ImageFromDockerfileBuilder(), refresh)
                    .WithName(name)
                    .WithDockerfile("Dockerfile")
                    .WithDockerfileDirectory(tempDir)
                    .WithLogger(logger));
                await CreateImageAsync(image, ct).ConfigureAwait(false);
                _image = image;
                return image;
            }
            finally
            {
                try
                {
                    if (image is not null && _image is null)
                    {
                        await image.DisposeAsync().ConfigureAwait(false);
                    }
                }
                finally
                {
                    if (Directory.Exists(tempDir))
                    {
                        Directory.Delete(tempDir, recursive: true);
                    }
                    s_logPreparation(logger,
                        GetType().Name, name, _image is null ? "failed" : "succeeded",
                        Stopwatch.GetElapsedTime(started).TotalMilliseconds, refresh ? "refresh" : "normal", null);
                }
            }
        }
        finally
        {
            _preparationLock.Release();
        }
    }

    internal virtual IFutureDockerImage BuildImage(ImageFromDockerfileBuilder builder) => builder.Build();

    internal virtual Task CreateImageAsync(IFutureDockerImage image, CancellationToken ct) => image.CreateAsync(ct);

    /// <summary>
    /// Starts a fresh container from this fixture's pre-built image. The
    /// container gets a random host port mapped to port 22. Calls
    /// <see cref="SshDockerFixture.SkipIfDockerNotAvailable"/> first, so the
    /// test is skipped when Docker is unreachable. Prepares the image lazily.
    /// </summary>
    public async Task<SshDockerContainer> StartContainerAsync(ILoggerFactory loggerFactory, CancellationToken ct)
    {
        SshDockerFixture.SkipIfDockerNotAvailable();

        IFutureDockerImage image = await EnsureImageAsync(ct).ConfigureAwait(false);

        IContainer container = new ContainerBuilder(image)
            .WithPortBinding(0, SshPort)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilInternalTcpPortIsAvailable(SshPort))
            .WithLogger(loggerFactory.CreateLogger<SshDockerContainer>())
            .Build();
        try
        {
            await container.StartAsync(ct).ConfigureAwait(false);
            int port = container.GetMappedPublicPort(SshPort);
            return new SshDockerContainer(container, port);
        }
        catch
        {
            await container.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_image is not null)
            {
                await _image.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _preparationLock.Dispose();
            _loggerFactory.Dispose();
        }
    }
}
