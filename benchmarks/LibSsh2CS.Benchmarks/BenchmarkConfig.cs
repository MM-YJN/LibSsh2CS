using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Csv;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Toolchains.CsProj;
using BenchmarkDotNet.Toolchains.DotNetCli;

namespace LibSsh2CS.Benchmarks;

/// <summary>
/// Default benchmark configuration: the default job (full rigor),
/// Markdown/CSV exports, and time + allocation measurement via the
/// per-class <c>[MemoryDiagnoser]</c> attributes. Artifacts are pinned to
/// <c>artifacts/benchmarks/</c> under the repository root.
/// </summary>
/// <remarks>
/// BenchmarkDotNet 0.15.x has no runtime moniker for <c>net11.0</c>, so the
/// default job validation (<c>GetRuntimeVersion</c>) throws for it. The job
/// therefore pins an explicit <c>net11.0</c> toolchain and carries a
/// <see cref="Net11Runtime"/> that borrows the <see cref="RuntimeMoniker.Net10_0"/>
/// moniker purely for the installed-SDK check (any 10.x/11.x SDK passes).
/// </remarks>
public sealed class BenchmarkConfig : ManualConfig
{
    public BenchmarkConfig()
    {
        AddLogger(ConsoleLogger.Default);
        AddColumnProvider(DefaultColumnProviders.Instance);
        AddExporter(MarkdownExporter.GitHub, CsvExporter.Default);
        // AsDefault lets CLI jobs (in-process smoke or Dry) inherit the pinned
        // net11.0 runtime/toolchain instead of replacing it — without it,
        // --job Dry validates against an unrecognized runtime moniker and throws.
        AddJob(Job.Default.AsDefault()
            .WithRuntime(new Net11Runtime())
            .WithToolchain(CsProjCoreToolchain.From(new NetCoreAppSettings(
                targetFrameworkMoniker: "net11.0",
                runtimeFrameworkVersion: null,
                name: "net11.0"))));
        WithArtifactsPath(ResolveArtifactsPath());
    }

    private sealed class Net11Runtime : Runtime
    {
        public Net11Runtime()
            : base(RuntimeMoniker.Net10_0, msBuildMoniker: "net11.0", displayName: ".NET 11.0")
        {
        }
    }

    private static string ResolveArtifactsPath()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "LibSsh2CS.slnx")))
        {
            directory = Path.GetDirectoryName(directory);
        }

        return directory is null
            ? Path.Combine(Directory.GetCurrentDirectory(), "BenchmarkDotNet.Artifacts")
            : Path.Combine(directory, "artifacts", "benchmarks");
    }
}
