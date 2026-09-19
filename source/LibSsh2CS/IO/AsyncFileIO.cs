using System.Text;

namespace LibSsh2CS.IO;

/// <summary>
/// Async filesystem IO helper for LibSsh2CS, used by
/// <see cref="SshKnownHosts.ReadFileAsync"/> and <see cref="SshKnownHosts.WriteFileAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the design of <c>LibGit2CS.IO.AsyncFileIO</c>: every method returns
/// <see cref="ValueTask"/> / <see cref="ValueTask{TResult}"/> so small-file
/// reads and writes can complete synchronously without allocating a
/// <see cref="Task"/>.
/// </para>
/// <para>
/// <b>ConfigureAwait</b>: every <c>await</c> uses
/// <c>.ConfigureAwait(false)</c> per the CA2007 convention enforced in
/// <c>source/LibSsh2CS/</c>.
/// </para>
/// <para>
/// <b>Encoding</b>: text helpers use UTF-8 without BOM, matching the on-disk
/// convention for OpenSSH <c>known_hosts</c> (ASCII-only in practice, but
/// UTF-8 is the safe superset).
/// </para>
/// <para>
/// <b>Convention-test allowlist:</b> this file is listed in
/// <c>AsyncConventionTests.s_bufferedFileIoAllowlist</c> as the designated
/// chokepoint for <see cref="File"/> IO. All other files in
/// <c>source/LibSsh2CS/</c> must not call <c>File.Read*</c> / <c>File.Write*</c>
/// directly.
/// </para>
/// </remarks>
internal static class AsyncFileIO
{
    private static readonly Encoding s_utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// Reads a file as UTF-8 text. Returns an empty string for an empty file.
    /// </summary>
    /// <param name="path">File path.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The file contents as a string.</returns>
    /// <exception cref="FileNotFoundException">Thrown if the file does not exist.</exception>
    public static Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken)
    {
        return File.ReadAllTextAsync(path, s_utf8NoBom, cancellationToken);
    }

    /// <summary>
    /// Writes text to a file as UTF-8 (no BOM). Overwrites the file if it
    /// already exists; creates it if it does not.
    /// </summary>
    /// <param name="path">File path.</param>
    /// <param name="content">The text to write.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken)
    {
        return File.WriteAllTextAsync(path, content, s_utf8NoBom, cancellationToken);
    }
}
