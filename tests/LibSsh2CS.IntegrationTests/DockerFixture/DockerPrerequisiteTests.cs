using System.Diagnostics;

namespace LibSsh2CS.IntegrationTests.DockerFixture;

public sealed class DockerPrerequisiteTests
{
    [Fact]
    public async Task ProbeAsync_ReturnsNull_ForLinuxEngine()
    {
        string? reason = await DockerPrerequisite.ProbeAsync(CreateShellStartInfo("echo linux"), TimeSpan.FromSeconds(10));
        Assert.Null(reason);
    }

    [Fact]
    public async Task ProbeAsync_ReturnsSkipReason_ForNonLinuxEngine()
    {
        string? reason = await DockerPrerequisite.ProbeAsync(CreateShellStartInfo("echo windows"), TimeSpan.FromSeconds(10));
        Assert.Equal("Docker reports engine 'windows'; these tests require Linux containers.", reason);
    }

    [Fact]
    public async Task ProbeAsync_ReturnsSkipReason_ForNonZeroExit()
    {
        string? reason = await DockerPrerequisite.ProbeAsync(CreateShellStartInfo("exit 23"), TimeSpan.FromSeconds(10));
        Assert.Equal("Docker info failed (exit 23); a reachable Linux container engine is required.", reason);
    }

    [Fact]
    public async Task ProbeAsync_ReturnsSkipReason_WhenStartupFails()
    {
        string executable = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "docker");
        string? reason = await DockerPrerequisite.ProbeAsync(new ProcessStartInfo(executable), TimeSpan.FromSeconds(10));
        Assert.StartsWith("Docker info unavailable (", reason);
        Assert.EndsWith("); a reachable Linux container engine is required.", reason);
    }

    [Fact]
    public async Task ProbeAsync_ReturnsSkipReason_WhenProbeTimesOut()
    {
        string? reason = await DockerPrerequisite.ProbeAsync(
            CreateShellStartInfo(OperatingSystem.IsWindows() ? "ping 127.0.0.1 -n 6 >NUL" : "sleep 5"),
            TimeSpan.FromMilliseconds(100));

        Assert.Equal("Docker info timed out; a reachable Linux container engine is required.", reason);
    }

    private static ProcessStartInfo CreateShellStartInfo(string command)
    {
        return OperatingSystem.IsWindows()
            ? new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", command } }
            : new ProcessStartInfo("/bin/sh") { ArgumentList = { "-c", command } };
    }
}
