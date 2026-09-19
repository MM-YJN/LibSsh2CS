using System.Text.RegularExpressions;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// Source-scanning convention tests for LibSsh2CS, ported 1:1 from
/// <c>tests/LibGit2CS.UnitTests/IO/AsyncConventionTests.cs</c> and pointed at
/// <c>source/LibSsh2CS/**/*.cs</c>. These tripwires run on every
/// <c>dotnet test</c> and catch async-convention regressions introduced by Phase 1
/// increments 4-8 and beyond.
/// </summary>
/// <remarks>
/// <para>
/// Scans production source only (test projects suppress CA2007 via
/// <c>NoWarnForTestProjects</c>).
/// </para>
/// <para>
/// <b>Check (a)</b> — no sync-over-async bridges (<c>.GetAwaiter().GetResult()</c>,
/// <c>.Wait(</c>) in production code. Allowlist is empty.
/// </para>
/// <para>
/// <b>Check (b)</b> — every <c>async</c> <c>IAsyncEnumerable&lt;T&gt;</c>
/// method with a <c>CancellationToken</c> parameter must also carry
/// <c>[EnumeratorCancellation]</c>. Non-async methods are exempt —
/// <c>[EnumeratorCancellation]</c> has no effect outside async-iterator
/// methods (CS8424).
/// </para>
/// <para>
/// <b>Check (c)</b> — every <c>Task</c>/<c>ValueTask</c>-returning <c>*Async</c>
/// method with at least one parameter must have a <c>CancellationToken</c>.
/// </para>
/// <para>
/// <b>Check (d)</b> — no buffered <c>System.IO.File</c> read/write/append calls in
/// production code (LibSsh2CS does no file IO at all, so this is a pure guard).
/// Allowlist is empty.
/// </para>
/// </remarks>
public partial class AsyncConventionTests
{
    private static readonly string s_sourceDir = FindSourceDir();

    /// <summary>
    /// No LibSsh2CS file is known to bridge sync-over-async; this stays empty. If a
    /// temporary bridge is ever needed, add it here and shrink back to empty when
    /// the bridge is removed.
    /// </summary>
    private static readonly HashSet<string> s_syncOverAsyncAllowlist = [];

    /// <summary>
    /// <see cref="IO.AsyncFileIO"/> (Phase 3 increment 3.1.6) is the single
    /// chokepoint for buffered <see cref="File"/> IO in the library. It uses
    /// async BCL calls (<c>File.ReadAllBytesAsync</c> / <c>File.WriteAllBytesAsync</c>)
    /// which the regex does not flag (it matches the sync <c>File.ReadAll*</c>
    /// variants only), but the file is allowlisted explicitly to document the
    /// intent: this is the ONLY file that may touch <c>File.*</c>.
    /// </summary>
    private static readonly HashSet<string> s_bufferedFileIoAllowlist = ["IO/AsyncFileIO.cs"];

    // ── Check (a): no sync-over-async bridges ─────────────────────────

    [Fact]
    public void NoSyncOverAsyncBridges()
    {
        var violations = new List<string>();

        foreach ((string relPath, string content) in EnumerateSourceFiles())
        {
            if (s_syncOverAsyncAllowlist.Contains(relPath))
            {
                continue;
            }

            if (content.Contains(".GetAwaiter().GetResult()", StringComparison.Ordinal))
            {
                violations.Add($"{relPath}: '.GetAwaiter().GetResult()'");
            }

            // Matches '.Wait(' or '.Wait (' but NOT '.WaitAsync('.
            foreach (Match m in MyRegex().Matches(content))
            {
                violations.Add($"{relPath}: '.Wait(' at offset {m.Index}");
            }
        }

        Assert.Empty(violations);
    }

    // ── Check (b): IAsyncEnumerable methods have [EnumeratorCancellation] ──

    [Fact]
    public void IAsyncEnumerableMethodsHaveEnumeratorCancellation()
    {
        var violations = new List<string>();

        foreach ((string relPath, string content) in EnumerateSourceFiles())
        {
            if (!content.Contains("IAsyncEnumerable<", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (Match m in IAsyncEnumerableMethodPattern().Matches(content))
            {
                string signature = m.Value;
                bool isAsyncIterator = m.Groups[1].Success;
                if (isAsyncIterator &&
                    signature.Contains("CancellationToken", StringComparison.Ordinal) &&
                    !signature.Contains("[EnumeratorCancellation]", StringComparison.Ordinal))
                {
                    violations.Add($"{relPath}: async IAsyncEnumerable method has CancellationToken without [EnumeratorCancellation]");
                }
            }
        }

        Assert.Empty(violations);
    }

    // ── Check (c): *Async methods with parameters have CancellationToken ──

    [Fact]
    public void AsyncMethodsWithParametersHaveCancellation()
    {
        var violations = new List<string>();

        foreach ((string relPath, string content) in EnumerateSourceFiles())
        {
            foreach (Match m in AsyncMethodPattern().Matches(content))
            {
                string methodName = m.Groups[1].Value;
                string paramList = m.Groups[2].Value.Trim();

                if (string.IsNullOrEmpty(paramList))
                {
                    continue;
                }

                if (!paramList.Contains("CancellationToken", StringComparison.Ordinal))
                {
                    violations.Add($"{relPath}: '{methodName}' has parameters but no CancellationToken");
                }
            }
        }

        Assert.Empty(violations);
    }

    // ── Check (d): no buffered File.IO in production code ─────────────

    [Fact]
    public void NoBufferedFileIO()
    {
        var violations = new List<string>();

        foreach ((string relPath, string content) in EnumerateSourceFiles())
        {
            if (s_bufferedFileIoAllowlist.Contains(relPath))
            {
                continue;
            }

            foreach (Match m in BufferedFileIoPattern().Matches(content))
            {
                int line = LineOf(content, m.Index);
                violations.Add($"{relPath}:{line}: '{m.Value.Trim()}'");
            }
        }

        Assert.Empty(violations);
    }

    // ── Helpers ────────────────────────────────────────────────────────

    [GeneratedRegex(@"(async\s+)?IAsyncEnumerable\s*<[^>]*>\s*\w+\s*\([^)]*\)", RegexOptions.Singleline)]
    private static partial Regex IAsyncEnumerableMethodPattern();

    [GeneratedRegex(@"(?:Task|ValueTask)(?:\s*<[^>]*>)?\s+(\w+Async)\s*\(([^)]*)\)", RegexOptions.Singleline)]
    private static partial Regex AsyncMethodPattern();

    [GeneratedRegex(@"File\.(ReadAllBytes|ReadAllLines|ReadAllText|WriteAllBytes|WriteAllText|AppendAllText)\s*\(")]
    private static partial Regex BufferedFileIoPattern();

    private static int LineOf(string content, int offset)
    {
        int line = 1;
        for (int i = 0; i < offset && i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    private static IEnumerable<(string relPath, string content)> EnumerateSourceFiles()
    {
        foreach (string file in Directory.EnumerateFiles(s_sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            string relPath = Path.GetRelativePath(s_sourceDir, file);
            yield return (relPath, File.ReadAllText(file));
        }
    }

    private static string FindSourceDir()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            string candidate = Path.Combine(dir, "source", "LibSsh2CS");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = Path.GetDirectoryName(dir);
        }

        throw new DirectoryNotFoundException("Could not locate source/LibSsh2CS/ from " + AppContext.BaseDirectory);
    }

    [GeneratedRegex(@"\.Wait\s*\(")]
    private static partial Regex MyRegex();
}
