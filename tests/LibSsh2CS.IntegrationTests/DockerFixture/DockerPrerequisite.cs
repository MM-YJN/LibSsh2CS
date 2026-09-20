using System.ComponentModel;
using System.Diagnostics;

namespace LibSsh2CS.IntegrationTests.DockerFixture;

/// <summary>Checks Docker capability before any image build is attempted.</summary>
internal static class DockerPrerequisite
{
    internal static ProcessStartInfo CreateStartInfo() => new("docker")
    {
        ArgumentList = { "info", "--format", "{{.OSType}}" },
    };

    // A separate start info and timeout let regression tests exercise real process
    // startup, output, failure, and cancellation without requiring Docker.
    internal static async Task<string?> ProbeAsync(ProcessStartInfo startInfo, TimeSpan timeout)
    {
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        using var timeoutSource = new CancellationTokenSource(timeout);
        try
        {
            ProcessTextOutput result = await Process.RunAndCaptureTextAsync(startInfo, timeoutSource.Token).ConfigureAwait(false);
            if (result.ExitStatus.ExitCode != 0)
            {
                return $"Docker info failed (exit {result.ExitStatus.ExitCode}); a reachable Linux container engine is required.";
            }

            string engine = result.StandardOutput.Trim();
            return string.Equals(engine, "linux", StringComparison.OrdinalIgnoreCase)
                ? null
                : $"Docker reports engine '{engine}'; these tests require Linux containers.";
        }
        catch (OperationCanceledException)
        {
            return "Docker info timed out; a reachable Linux container engine is required.";
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            return $"Docker info unavailable ({ex.Message}); a reachable Linux container engine is required.";
        }
    }
}
