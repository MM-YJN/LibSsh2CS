using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.IO;
using LibSsh2CS.Util;

namespace LibSsh2CS;

/// <summary>
/// An in-memory collection of <see cref="SshKnownHostEntry"/> instances, mirroring
/// libssh2's <c>LIBSSH2_KNOWNHOSTS</c> (<c>knownhost.c:64-68</c>). Provides
/// add/delete/iterate operations, host checks, and file/line IO.
/// </summary>
/// <remarks>
/// <para>
/// <b>No <see cref="IDisposable"/> leak on forget:</b> the entries hold no
/// unmanaged resources — only managed <see cref="string"/>/<see cref="byte"/>[]
/// references. <see cref="Dispose"/> is idempotent and exists primarily for
/// API parity with the C <c>libssh2_knownhost_free</c> and to drop the entry
/// list early; the GC would reclaim everything eventually. Mirrors the C
/// pattern where <c>libssh2_knownhost_free</c> walks the list freeing each
/// node, which in C# becomes <see cref="List{T}.Clear"/>.
/// </para>
/// <para>
/// <b>Decoupled from <see cref="SshSession"/>:</b> libssh2's
/// <c>LIBSSH2_KNOWNHOSTS</c> stores a <c>session</c> pointer purely for the
/// allocator and <c>_libssh2_error</c> cache. Both vanish in C# (GC + throwing
/// <see cref="SshException"/>), so <see cref="SshKnownHosts"/> has no session
/// dependency and can be constructed standalone.
/// </para>
/// <para>
/// <b>Thread safety:</b> not thread-safe. Matches libssh2's single-threaded
/// model. Callers serialize access if needed.
/// </para>
/// </remarks>
public sealed class SshKnownHosts : IDisposable
{
    private readonly List<SshKnownHostEntry> _entries = new();
    private bool _disposed;

    /// <summary>
    /// Creates an empty known-hosts collection. Mirrors
    /// <c>libssh2_knownhost_init</c> (<c>knownhost.c:93-111</c>) minus the
    /// session parameter (not needed — see type-level remarks).
    /// </summary>
    public SshKnownHosts()
    {
    }

    /// <summary>
    /// Adds a hostname + key pair to the collection. Mirrors
    /// <c>libssh2_knownhost_add</c> (<c>knownhost.c:283-291</c>) and
    /// <c>libssh2_knownhost_addc</c> (<c>knownhost.c:321-330</c>); the C pair of
    /// entry points (with/without comment) collapses to a single method whose
    /// <paramref name="comment"/> defaults to <c>null</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Per-format parameter interpretation</b> (parity with the SHA1/Plain/
    /// Custom branches of <c>knownhost_add</c> at <c>knownhost.c:161-192</c>):
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <term><see cref="SshKnownHostFormat.Plain"/></term>
    /// <description>
    /// <paramref name="host"/> is the plaintext hostname (e.g.
    /// <c>"example.com"</c>). <paramref name="salt"/> is <c>null</c> (passed
    /// value is ignored). Mirrors <c>LIBSSH2_KNOWNHOST_TYPE_PLAIN</c>.
    /// </description>
    /// </item>
    /// <item>
    /// <term><see cref="SshKnownHostFormat.Custom"/></term>
    /// <description>
    /// <paramref name="host"/> is the caller-supplied pre-hashed hostname
    /// (compared by string equality at check time; the library performs no
    /// hashing). <paramref name="salt"/> is <c>null</c>. Mirrors
    /// <c>LIBSSH2_KNOWNHOST_TYPE_CUSTOM</c>.
    /// </description>
    /// </item>
    /// <item>
    /// <term><see cref="SshKnownHostFormat.Sha1"/></term>
    /// <description>
    /// <paramref name="host"/> is the base64-encoded HMAC-SHA1 digest of the
    /// hostname (exactly as it appears on disk after <c>|1|&lt;salt&gt;|</c>).
    /// <paramref name="salt"/> is the <em>raw</em> salt bytes (the parser
    /// base64-decodes the on-disk salt before calling; a programmatic caller
    /// already has raw bytes). The host string is <em>not</em> decoded here —
    /// it is stored verbatim so it round-trips back to disk via
    /// <c>WriteLine</c>; the <c>Check</c> path decodes it lazily for
    /// comparison. Parity with <c>knownhost.c:173-187</c>, modulo storing the
    /// hash as its on-disk base64 form rather than raw bytes.
    /// </description>
    /// </item>
    /// </list>
    /// <para>
    /// <b>Key encoding</b> mirrors the <c>LIBSSH2_KNOWNHOST_KEYENC_RAW</c>
    /// branch of <c>knownhost_add</c> (<c>knownhost.c:207-219</c>): the
    /// <paramref name="key"/> is raw bytes and is base64-encoded once here
    /// (via <see cref="Base64.EncodeToString(ReadOnlySpan{byte})"/>) before being
    /// stored on the entry. To supply a pre-encoded base64 key, build the entry
    /// at a layer above (<c>ReadLine</c> does this; an
    /// <c>AddBase64Key</c> overload can be added if a programmatic caller needs
    /// it).
    /// </para>
    /// <para>
    /// <b>Comment semantics</b> (parity with <c>knownhost.c:234-247</c>):
    /// <c>null</c> means "no comment" (no trailing space written by
    /// <c>WriteLine</c>); a non-null value (including the empty string) is
    /// stored verbatim. The distinction between <c>null</c> and <c>""</c>
    /// matters at <c>WriteLine</c> time — see <c>knownhost.c:819-820</c>.
    /// </para>
    /// <para>
    /// <b>Key-type validation:</b> libssh2 rejects calls where
    /// <c>!(typemask &amp; LIBSSH2_KNOWNHOST_KEY_MASK)</c>
    /// (<c>knownhost.c:149-151</c>) — i.e. the caller forgot to set any key
    /// type bits. The C# type system makes this impossible (the
    /// <paramref name="keyType"/> parameter is required), so the check is
    /// unnecessary and <see cref="SshKnownHostKeyType.Unknown"/> is accepted here
    /// as a valid stored type (it round-trips but never matches a
    /// <c>Check</c>, parity with <c>knownhost.c:459</c>).
    /// </para>
    /// </remarks>
    /// <param name="host">Hostname (Plain/Custom) or base64-encoded SHA1 hash.</param>
    /// <param name="salt">Raw salt bytes for <see cref="SshKnownHostFormat.Sha1"/>; <c>null</c> otherwise.</param>
    /// <param name="key">Raw public-key bytes; base64-encoded internally.</param>
    /// <param name="keyType">Stored key-type discriminator.</param>
    /// <param name="format">Hostname encoding format.</param>
    /// <param name="comment">Optional comment; <c>null</c> for no comment.</param>
    /// <returns>The newly added entry (a stable handle for <see cref="Delete"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="host"/> or <paramref name="key"/> is <c>null</c>.
    /// </exception>
    /// <exception cref="SshException">
    /// Thrown with <see cref="SshErrorCode.Inval"/> if
    /// <see cref="SshKnownHostFormat.Sha1"/> is requested without a salt.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public SshKnownHostEntry Add(
        string host,
        byte[]? salt,
        byte[] key,
        SshKnownHostKeyType keyType,
        SshKnownHostFormat format,
        string? comment = null)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(key);
        return Add(host, salt.AsSpan(), key.AsSpan(), keyType, format, comment);
    }

    /// <summary>
    /// Adds a known-host entry from raw salt and public-key spans.
    /// </summary>
    /// <param name="host">Hostname (Plain/Custom) or base64-encoded SHA1 hash.</param>
    /// <param name="salt">Raw salt bytes for <see cref="SshKnownHostFormat.Sha1"/>; empty otherwise.</param>
    /// <param name="key">Raw public-key bytes; base64-encoded internally.</param>
    /// <param name="keyType">Stored key-type discriminator.</param>
    /// <param name="format">Hostname encoding format.</param>
    /// <param name="comment">Optional comment; <c>null</c> for no comment.</param>
    /// <returns>The newly added entry (a stable handle for <see cref="Delete"/>).</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="host"/> is <c>null</c>.</exception>
    /// <exception cref="SshException">
    /// Thrown with <see cref="SshErrorCode.Inval"/> if
    /// <see cref="SshKnownHostFormat.Sha1"/> is requested without a salt.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public SshKnownHostEntry Add(
        string host,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> key,
        SshKnownHostKeyType keyType,
        SshKnownHostFormat format,
        string? comment = null)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(host);

        // Public Add takes raw key bytes and base64-encodes them once here
        // (parity with the KEYENC_RAW branch at knownhost.c:207-219). The
        // internal AddParsed bypasses the encoding for the ReadLine path,
        // where the on-disk key is already base64 (KEYENC_BASE64 flag).
        string base64Key = Base64.EncodeToString(key);
        return AddParsed(host, salt, base64Key, keyType, format, comment, keyTypeName: null);
    }

    /// <summary>
    /// Adds an entry with a pre-base64-encoded key string. Used by the line
    /// parser (<see cref="ReadLine"/>) where the on-disk key text is already
    /// base64 and re-encoding it would be a wasteful round-trip. Mirrors the
    /// <c>LIBSSH2_KNOWNHOST_KEYENC_BASE64</c> path of <c>knownhost_add</c>
    /// (<c>knownhost.c:194-206</c>).
    /// </summary>
    /// <param name="host">Hostname plaintext (for Plain/Custom) or base64-decoded
    /// HMAC-SHA1 digest text (for Sha1). Becomes the entry's <c>Name</c>.</param>
    /// <param name="salt">Raw salt bytes for Sha1 entries; <c>null</c> otherwise.</param>
    /// <param name="base64Key">The base64-encoded key string read from disk
    /// (no key-type prefix, no comment).</param>
    /// <param name="keyType">The parsed key-type discriminator.</param>
    /// <param name="format">The hostname encoding format (Plain/Custom/Sha1).</param>
    /// <param name="comment">Trailing comment from the on-disk line, or
    /// <c>null</c> when no comment was present.</param>
    /// <param name="keyTypeName">
    /// The wire-format key type name, stored only for
    /// <see cref="SshKnownHostKeyType.Unknown"/> entries (parity with
    /// <c>knownhost.c:221-232</c>); <c>null</c> otherwise.
    /// </param>
    internal SshKnownHostEntry AddParsed(
        string host,
        ReadOnlySpan<byte> salt,
        string base64Key,
        SshKnownHostKeyType keyType,
        SshKnownHostFormat format,
        string? comment,
        string? keyTypeName)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(base64Key);

        // Parity with the Plain/Custom branch of knownhost_add (knownhost.c:162-172):
        // the C code's calloc leaves entry->salt NULL unless the SHA1 branch
        // (knownhost.c:181-186) explicitly populates it. We mirror that by
        // dropping any caller-supplied salt for non-SHA1 formats — the field
        // is meaningless without a hash to salt it. The SHA1 branch copies the
        // salt so the entry owns it: the caller's array must not be able to
        // change a stored entry's HMAC after Add returns.
        byte[]? storedSalt = null;
        if (format == SshKnownHostFormat.Sha1)
        {
            if (salt.Length == 0)
            {
                throw new SshException(
                    SshErrorCode.Inval,
                    "SHA1-format known-host entries require a non-empty salt");
            }

            storedSalt = salt.ToArray();
        }

        // Only UNKNOWN entries carry the wire key-type name (parity with
        // knownhost.c:221-232). Known types derive the name from KeyType at
        // write time.
        string? storedKeyName = keyType == SshKnownHostKeyType.Unknown ? keyTypeName : null;

        var entry = new SshKnownHostEntry(host, storedSalt, base64Key, keyType, format, comment, storedKeyName);
        _entries.Add(entry);
        return entry;
    }

    /// <summary>
    /// Checks a host + key against the collection. Mirrors
    /// <c>libssh2_knownhost_checkp</c> (<c>knownhost.c:550-559</c>); the
    /// no-port overload mirrors <c>libssh2_knownhost_check</c>
    /// (<c>knownhost.c:517-525</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Port handling</b> (parity with <c>knownhost.c:373-387</c>): when
    /// <paramref name="port"/> is non-negative, the check first tries the
    /// bracketed form <c>[host]:port</c>, then falls back to the plain host.
    /// When <paramref name="port"/> is negative, only the plain host is checked.
    /// </para>
    /// <para>
    /// <b>SHA1 input is unsupported</b>: per <c>knownhost.c:367-369</c>, a
    /// caller passing <see cref="SshKnownHostFormat.Sha1"/> as
    /// <paramref name="inputFormat"/> gets <see cref="SshKnownHostCheckStatus.Mismatch"/>
    /// immediately — hashed inputs cannot be matched against hashed entries
    /// (only plaintext inputs can be matched against SHA1 entries).
    /// </para>
    /// <para>
    /// <b>Key-type matching</b> (parity with <c>knownhost.c:451-478</c>): an
    /// entry's key bytes are compared only when the caller's
    /// <paramref name="keyType"/> is concrete and equals the stored entry's
    /// <see cref="SshKnownHostEntry.KeyType"/>. <see cref="SshKnownHostKeyType.Unknown"/>
    /// as a caller argument short-circuits to no match (mirrors C's
    /// <c>host_key_type != LIBSSH2_KNOWNHOST_KEY_UNKNOWN</c> guard at line 459).
    /// The C wildcard mode (<c>host_key_type == 0</c>) is not surfaced: callers
    /// must name a concrete algorithm. In practice, libgit2's
    /// <c>find_hostkey_preference</c> always probes one type at a time.
    /// </para>
    /// <para>
    /// <b>Badkey tracking</b> (parity with <c>knownhost.c:474-477</c>): if the
    /// hostname and key type both match but the key bytes differ, the first
    /// such entry is remembered and surfaced via
    /// <see cref="SshKnownHostCheckResult.Matched"/> with status
    /// <see cref="SshKnownHostCheckStatus.Mismatch"/>. This is how callers
    /// distinguish "unknown host" (NotFound) from "host known but key changed"
    /// (Mismatch). Key-type mismatches do <em>not</em> register as badkey — the
    /// C code only updates <c>badkey</c> inside the key-type-matched branch.
    /// </para>
    /// </remarks>
    /// <param name="host">Plaintext hostname (or pre-hashed for Custom input).</param>
    /// <param name="port">TCP port (-1 or any negative value to skip the <c>[host]:port</c> form).</param>
    /// <param name="key">Raw public-key bytes; base64-encoded internally for comparison.</param>
    /// <param name="keyType">Concrete key type; <see cref="SshKnownHostKeyType.Unknown"/> never matches.</param>
    /// <param name="inputFormat">
    /// Caller-side hostname encoding: <see cref="SshKnownHostFormat.Plain"/> (default)
    /// or <see cref="SshKnownHostFormat.Custom"/>. <see cref="SshKnownHostFormat.Sha1"/>
    /// returns <see cref="SshKnownHostCheckStatus.Mismatch"/> immediately.
    /// </param>
    /// <returns>A result carrying the status and the matched/badkey entry.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="host"/> or <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public SshKnownHostCheckResult Check(
        string host,
        int port,
        ReadOnlyMemory<byte> key,
        SshKnownHostKeyType keyType,
        SshKnownHostFormat inputFormat = SshKnownHostFormat.Plain)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(host);

        // Parity with knownhost.c:367-369 — SHA1 input is unsupported (a hashed
        // input cannot be matched against either hashed or plaintext entries).
        if (inputFormat == SshKnownHostFormat.Sha1)
        {
            return new SshKnownHostCheckResult(SshKnownHostCheckStatus.Mismatch, null);
        }

        // Encode the raw key once for string comparison against stored entries.
        // Parity with knownhost.c:389-402 (the KEYENC_RAW branch).
        string base64Key = Base64.EncodeToString(key.Span);

        // Build the host forms to check, in C's order: [host]:port first, then
        // plain host. port < 0 collapses to plain-host-only (numcheck == 1).
        string hostWithPort = port >= 0
            ? string.Create(CultureInfo.InvariantCulture, $"[{host}]:{port}")
            : host;

        // badkey: first host-match-with-key-mismatch across ALL host forms.
        // Persists across both iterations (parity with the outer do-while's
        // single badkey variable in knownhost.c:358).
        SshKnownHostEntry? badkey = null;

        // First pass: [host]:port (or plain host if port < 0).
        SshKnownHostEntry? match = FindMatch(hostWithPort, base64Key, inputFormat, keyType, ref badkey);
        if (match is not null)
        {
            return new SshKnownHostCheckResult(SshKnownHostCheckStatus.Match, match);
        }

        // Second pass: plain host (only when port was specified).
        if (port >= 0)
        {
            match = FindMatch(host, base64Key, inputFormat, keyType, ref badkey);
            if (match is not null)
            {
                return new SshKnownHostCheckResult(SshKnownHostCheckStatus.Match, match);
            }
        }

        if (badkey is not null)
        {
            return new SshKnownHostCheckResult(SshKnownHostCheckStatus.Mismatch, badkey);
        }

        return new SshKnownHostCheckResult(SshKnownHostCheckStatus.NotFound, null);
    }

    /// <summary>
    /// Checks a host + key without a port. Equivalent to passing
    /// <c>port = -1</c> to the four-arg overload. Mirrors
    /// <c>libssh2_knownhost_check</c> (<c>knownhost.c:517-525</c>).
    /// </summary>
    public SshKnownHostCheckResult Check(
        string host,
        byte[] key,
        SshKnownHostKeyType keyType,
        SshKnownHostFormat inputFormat = SshKnownHostFormat.Plain)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Check(host, -1, key, keyType, inputFormat);
    }

    /// <summary>
    /// Parses a single OpenSSH known_hosts line and adds the entry (or entries)
    /// to the collection. Mirrors <c>libssh2_knownhost_readline</c>
    /// (<c>knownhost.c:878-948</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Line format</b> (OpenSSH):
    /// <code>
    /// &lt;host-or-hash&gt; &lt;key-type-name&gt; &lt;base64-key&gt; [comment]
    /// </code>
    /// Where <c>&lt;host-or-hash&gt;</c> is either a plaintext hostname (or a
    /// comma-separated list) or a hashed entry of the form
    /// <c>|1|&lt;base64-salt&gt;|&lt;base64-hash&gt;</c>.
    /// </para>
    /// <para>
    /// <b>No-op lines:</b> blank lines, lines containing only whitespace, and
    /// lines starting with <c>#</c> are silently ignored (parity with
    /// <c>knownhost.c:903-905</c>).
    /// </para>
    /// <para>
    /// <b>Key type dispatch:</b> the key type name is parsed and matched against
    /// the known set (<c>ssh-rsa</c>, <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256/384/521</c>,
    /// <c>ssh-dss</c>). Unrecognized names store an <see cref="SshKnownHostKeyType.Unknown"/>
    /// entry that preserves the original name (for round-tripping via WriteLine).
    /// A key whose first character is an ASCII digit is treated as RSA1 (SSH1
    /// legacy) — parity with <c>knownhost.c:761-771</c>.
    /// </para>
    /// <para>
    /// <b>Comma-separated hosts:</b> a plaintext host like
    /// <c>host1,host2,host3</c> expands into three separate entries sharing the
    /// same key (parity with <c>oldstyle_hostline</c>, <c>knownhost.c:620-674</c>).
    /// </para>
    /// <para>
    /// <b>Newline handling:</b> trailing <c>\n</c> and <c>\r</c> are stripped
    /// before parsing. The C code strips only <c>\n</c> (<c>knownhost.c:933-940</c>)
    /// but C# callers typically pass already-split lines; stripping <c>\r</c>
    /// too handles CRLF files robustly without affecting key/comment content.
    /// </para>
    /// </remarks>
    /// <param name="line">A single line from a known_hosts file.</param>
    /// <param name="type">File format; must be <see cref="SshKnownHostFileType.OpenSsh"/>.</param>
    /// <exception cref="SshException">
    /// Thrown with <see cref="SshErrorCode.MethodNotSupported"/> for unsupported
    /// file types, malformed lines (missing key, key too short), or overlong
    /// hostnames/salts (parity with the C error paths).
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public void ReadLine(ReadOnlySpan<char> line, SshKnownHostFileType type)
    {
        ThrowIfDisposed();

        if (type != SshKnownHostFileType.OpenSsh)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Unsupported type of known-host information store");
        }

        // Strip trailing newlines (handles both \n and \r\n — see remarks).
        ReadOnlySpan<char> trimmed = line.TrimEnd("\r\n");

        // Skip leading whitespace (parity with knownhost.c:898-901).
        int i = 0;
        while (i < trimmed.Length && IsSpaceOrTab(trimmed[i]))
        {
            i++;
        }

        // Empty line, comment, or null byte: no-op (parity with knownhost.c:903-905).
        if (i >= trimmed.Length || trimmed[i] == '\0' || trimmed[i] == '#')
        {
            return;
        }

        // Scan host part until whitespace (parity with knownhost.c:911-914).
        int hostStart = i;
        while (i < trimmed.Length && !IsSpaceOrTab(trimmed[i]))
        {
            i++;
        }

        int hostLen = i - hostStart;

        // Skip whitespace between host and key (parity with knownhost.c:919-922).
        while (i < trimmed.Length && IsSpaceOrTab(trimmed[i]))
        {
            i++;
        }

        if (i >= trimmed.Length)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Failed to parse known_hosts line");
        }

        ReadOnlySpan<char> hostPart = trimmed.Slice(hostStart, hostLen);
        ReadOnlySpan<char> keyPart = trimmed.Slice(i);

        ParseHostLine(hostPart, keyPart);
    }

    /// <summary>
    /// Dispatches a parsed (host, key) pair to the oldstyle or hashed parser.
    /// Mirrors <c>hostline</c> (<c>knownhost.c:744-848</c>).
    /// </summary>
    private void ParseHostLine(ReadOnlySpan<char> host, ReadOnlySpan<char> key)
    {
        // Parity with knownhost.c:755-759 — keys shorter than 20 bytes are
        // rejected (even the shortest SSH2 key type name + minimal base64
        // exceeds this; the guard catches truncated/corrupt lines).
        if (key.Length < 20)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Failed to parse known_hosts line (key too short)");
        }

        // Parse the key into (keyType, keyTypeName, keyBody, comment). hasComment
        // carries the null-vs-empty distinction: ReadOnlySpan<char> cannot hold
        // null, so the sentinel is a separate bool (false → null comment, no
        // trailing space; true → comment span is the text, possibly empty).
        ParseKey(
            key,
            out SshKnownHostKeyType keyType,
            out ReadOnlySpan<char> keyTypeName,
            out ReadOnlySpan<char> keyBody,
            out ReadOnlySpan<char> comment,
            out bool hasComment);

        // Dispatch on hostname format (parity with knownhost.c:831-847):
        // "|1|" prefix → hashed; anything else (if length > 2) → oldstyle plain.
        // The C guard is `hostlen > 2 && memcmp(host, "|1|", 3)` — i.e. the
        // host does NOT start with "|1|". We invert: if it DOES start with
        // "|1|", parse as hashed; else oldstyle.
        if (host.Length > 2 && host.StartsWith("|1|", StringComparison.Ordinal))
        {
            ParseHashedHostLine(host, keyBody, keyType, keyTypeName, comment, hasComment);
        }
        else
        {
            ParseOldStyleHostLine(host, keyBody, keyType, keyTypeName, comment, hasComment);
        }
    }

    /// <summary>
    /// Parses the key portion of a known_hosts line, extracting the key type,
    /// optional wire-format type name (for unrecognized types), the base64 key
    /// body, and optional comment. Mirrors the <c>default</c> branch of the
    /// switch in <c>hostline</c> (<c>knownhost.c:773-829</c>).
    /// </summary>
    /// <remarks>
    /// RSA1 keys (first char is an ASCII digit) take a fast path: no key type
    /// name, no comment, key body is the entire key string (parity with
    /// <c>knownhost.c:761-771</c>).
    /// </remarks>
    private static void ParseKey(
        ReadOnlySpan<char> key,
        out SshKnownHostKeyType keyType,
        out ReadOnlySpan<char> keyTypeName,
        out ReadOnlySpan<char> keyBody,
        out ReadOnlySpan<char> comment,
        out bool hasComment)
    {
        // RSA1 fast path (knownhost.c:761-771).
        if (key[0] is >= '0' and <= '9')
        {
            keyType = SshKnownHostKeyType.Rsa1;
            keyTypeName = ReadOnlySpan<char>.Empty;
            keyBody = key;
            comment = ReadOnlySpan<char>.Empty;
            hasComment = false;
            return;
        }

        // Parse key type name: scan until whitespace (knownhost.c:774-780).
        int nameEnd = 0;
        while (nameEnd < key.Length && !IsSpaceOrTab(key[nameEnd]))
        {
            nameEnd++;
        }

        ReadOnlySpan<char> nameSpan = key[..nameEnd];
        keyType = MatchKeyTypeName(nameSpan);
        keyTypeName = keyType == SshKnownHostKeyType.Unknown ? nameSpan : null;

        // Skip whitespace after key type name (knownhost.c:800-803).
        int rest = nameEnd;
        while (rest < key.Length && IsSpaceOrTab(key[rest]))
        {
            rest++;
        }

        // Scan key body until whitespace (knownhost.c:805-813).
        int afterNameLen = key.Length - rest;
        int keyEnd = 0;
        while (keyEnd < afterNameLen && !IsSpaceOrTab(key[rest + keyEnd]))
        {
            keyEnd++;
        }

        keyBody = key.Slice(rest, keyEnd);

        // Comment: everything after the key body (knownhost.c:805-827).
        int commentStart = rest + keyEnd;
        int commentLen = key.Length - commentStart;

        if (commentLen == 0)
        {
            // Nothing after the key body → no comment (knownhost.c:819-820).
            // hasComment=false preserves the null sentinel that AddParsed stores
            // as a null Comment (no trailing space at write time).
            comment = ReadOnlySpan<char>.Empty;
            hasComment = false;
        }
        else
        {
            // Skip whitespace before comment (knownhost.c:822-827).
            int cs = 0;
            while (cs < commentLen && IsSpaceOrTab(key[commentStart + cs]))
            {
                cs++;
            }

            // If there was whitespace but nothing after it, this produces an
            // empty string (distinct from null) — parity with knownhost.c:818-820's
            // "empty comment" case (a trailing space means "write a space").
            // hasComment=true carries that distinction: an empty span with
            // hasComment=true is the empty-comment case, not the null case.
            comment = key.Slice(commentStart + cs);
            hasComment = true;
        }
    }

    /// <summary>
    /// Maps a wire-format key type name to its <see cref="SshKnownHostKeyType"/>
    /// enum value. Parity with <c>hostline:782-797</c>.
    /// </summary>
    /// <remarks>
    /// <see cref="SshKnownHostKeyType.Unknown"/> is returned for any unrecognized
    /// name — the original string is preserved by the caller for round-tripping.
    /// <c>ssh-dss</c> is matched (parity with <c>LIBSSH2_DSA</c>) even though
    /// DSS is deprecated.
    /// </remarks>
    private static SshKnownHostKeyType MatchKeyTypeName(ReadOnlySpan<char> name)
        // The C code uses strncmp with the name length; for C#, exact string
        // equality is equivalent since nameSpan is already the right length.
        // Delegates to the shared HostKeyTypeRegistry (single source of truth
        // for wire-name ↔ enum mapping) — parity-preserving refactor.
        => SshHostKeyTypeRegistry.LookupByWireName(name)?.Known
            ?? SshKnownHostKeyType.Unknown;

    /// <summary>
    /// Parses a comma-separated plaintext hostname list, adding each as a
    /// separate entry sharing the same key. Mirrors
    /// <c>oldstyle_hostline</c> (<c>knownhost.c:620-674</c>).
    /// </summary>
    private void ParseOldStyleHostLine(
        ReadOnlySpan<char> host,
        ReadOnlySpan<char> keyBody,
        SshKnownHostKeyType keyType,
        ReadOnlySpan<char> keyTypeName,
        ReadOnlySpan<char> comment,
        bool hasComment)
    {
        if (host.Length < 1)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Failed to parse known_hosts line (no host names)");
        }

        // Walk the comma-separated list right-to-left, extracting each name.
        // Parity with knownhost.c:636-671's reverse scan.
        int end = host.Length;
        while (end > 0)
        {
            // Find the start of the current name (scan back to comma or start).
            int start = end - 1;
            while (start > 0 && host[start - 1] != ',')
            {
                start--;
            }

            ReadOnlySpan<char> hostname = host.Slice(start, end - start);

            AddParsed(
                host: hostname.ToString(),
                salt: null,
                base64Key: keyBody.ToString(),
                keyType: keyType,
                format: SshKnownHostFormat.Plain,
                comment: hasComment ? comment.ToString() : null,
                keyTypeName: keyTypeName.ToString());

            if (start > 0)
            {
                // Skip the comma.
                end = start - 1;
            }
            else
            {
                end = 0;
            }
        }
    }

    /// <summary>
    /// Parses a hashed hostname entry of the form
    /// <c>|1|&lt;base64-salt&gt;|&lt;base64-hash&gt;</c>, decoding the salt to
    /// raw bytes and storing the hash as its base64 string. Mirrors
    /// <c>hashed_hostline</c> (<c>knownhost.c:677-732</c>).
    /// </summary>
    private void ParseHashedHostLine(
        ReadOnlySpan<char> host,
        ReadOnlySpan<char> keyBody,
        SshKnownHostKeyType keyType,
        ReadOnlySpan<char> keyTypeName,
        ReadOnlySpan<char> comment,
        bool hasComment)
    {
        // Skip the "|1|" magic marker (knownhost.c:687-688).
        const string Magic = "|1|";
        ReadOnlySpan<char> rest = host.Slice(Magic.Length);

        // Find the next '|' separator (end of salt) — knownhost.c:691-692.
        // Using the span overload avoids the CA1307/CA1865 conflict between
        // string.IndexOf(char) [wants StringComparison] and string.IndexOf(string)
        // [wants char]. ReadOnlySpan<char>.IndexOf(char) is implicitly ordinal.
        int sep = rest.IndexOf('|');
        if (sep < 0)
        {
            // Parity with knownhost.c:730-731: the C code silently returns 0
            // (treated as success-without-add) for a malformed hashed line.
            // We do the same — no throw, no entry added.
            return;
        }

        ReadOnlySpan<char> saltBase64 = rest[..sep];
        ReadOnlySpan<char> hashBase64 = rest[(sep + 1)..];

        if (saltBase64.Length >= 32)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Failed to parse known_hosts line (unexpectedly long salt)");
        }

        if (hashBase64.Length >= 256)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Failed to parse known_hosts line (unexpected length)");
        }

        // Decode the salt from base64 to raw bytes (parity with the second
        // _libssh2_base64_decode call at knownhost.c:181-186). The hash stays
        // as its base64 text — stored in KnownHostEntry.Name and decoded
        // lazily at Check time. Uses libssh2's lenient decoder (skips junk,
        // accepts unpadded tails — misc.c:396-424); the BCL decoder rejected
        // non-canonical salts the C accepts.
        byte[] saltBytesBuffer = ArrayPool<byte>.Shared.Rent(LenientBase64.GetMaxDecodedLength(saltBase64.Length));
        Span<byte> saltBytes;
        try
        {
            int decodedLength = LenientBase64.Decode(saltBase64, saltBytesBuffer);
            saltBytes = saltBytesBuffer.AsSpan(0, decodedLength);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.Inval)
        {
            ArrayPool<byte>.Shared.Return(saltBytesBuffer);

            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Failed to parse known_hosts line (invalid base64 salt)");
        }

        AddParsed(
            host: hashBase64.ToString(),
            salt: saltBytes,
            base64Key: keyBody.ToString(),
            keyType: keyType,
            format: SshKnownHostFormat.Sha1,
            comment: hasComment ? comment.ToString() : null,
            keyTypeName: keyTypeName.ToString());

        ArrayPool<byte>.Shared.Return(saltBytesBuffer);
    }

    /// <summary>
    /// Returns <c>true</c> for ASCII space (0x20) and horizontal tab (0x09) —
    /// the two whitespace characters the C parser treats as field separators.
    /// </summary>
    private static bool IsSpaceOrTab(char ch) => ch is ' ' or '\t';

    /// <summary>
    /// Formats an entry as an OpenSSH known_hosts line. Mirrors
    /// <c>knownhost_writeline</c> (<c>knownhost.c:1003-1166</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The output format dispatches on two booleans (key-type-name present?
    /// comment present?) producing four sub-formats per hostname format — eight
    /// total, matching the C code's eight <c>snprintf</c> branches at
    /// <c>knownhost.c:1122-1155</c>.
    /// </para>
    /// <para>
    /// <b>Hashed entries</b> (<see cref="SshKnownHostFormat.Sha1"/>) re-encode the
    /// salt to base64 for output (the salt is stored as raw bytes internally).
    /// The hash (<see cref="SshKnownHostEntry.Name"/>) is already stored as its
    /// base64 text form and is emitted verbatim — no double-encoding.
    /// </para>
    /// <para>
    /// <b>Comment distinction</b>: a <c>null</c> comment produces no trailing
    /// space; a non-null comment (including the empty string) produces a space
    /// followed by the comment text. This matches the C semantics at
    /// <c>knownhost.c:1091-1092</c> (<c>if(node-&gt;comment)</c>) and the
    /// parse-time distinction at <c>knownhost.c:818-820</c>.
    /// </para>
    /// <para>
    /// <b>Unknown key types</b>: an <see cref="SshKnownHostKeyType.Unknown"/> entry
    /// with a stored <see cref="SshKnownHostEntry.KeyTypeName"/> emits that name.
    /// An <see cref="SshKnownHostKeyType.Unknown"/> entry without a stored name
    /// throws <see cref="SshErrorCode.MethodNotSupported"/> — parity with the
    /// <c>LIBSSH2_FALLTHROUGH()</c> to the default error case at
    /// <c>knownhost.c:1059-1064</c>.
    /// </para>
    /// </remarks>
    /// <param name="entry">The entry to format (must be from this collection, though this is not enforced).</param>
    /// <param name="type">File format; must be <see cref="SshKnownHostFileType.OpenSsh"/>.</param>
    /// <returns>The formatted line including a trailing <c>\n</c>.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="entry"/> is <c>null</c>.</exception>
    /// <exception cref="SshException">
    /// Thrown with <see cref="SshErrorCode.MethodNotSupported"/> for unsupported
    /// file types or entries whose key type cannot be serialized.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public string WriteLine(SshKnownHostEntry entry, SshKnownHostFileType type)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(entry);

        if (type != SshKnownHostFileType.OpenSsh)
        {
            throw new SshException(
                SshErrorCode.MethodNotSupported,
                "Unsupported type of known-host information store");
        }

        // Resolve the wire-format key type name. Parity with the switch at
        // knownhost.c:1022-1065. Returns null for RSA1 (no name on disk).
        string? keyTypeName = ResolveKeyTypeName(entry);

        var sb = new StringBuilder();

        // Hostname portion (parity with knownhost.c:1094-1155).
        if (entry.Format == SshKnownHostFormat.Sha1)
        {
            // Hashed: |1|<base64-salt>|<base64-hash>
            // Salt is stored raw; re-encode for output. Hash (entry.Name) is
            // already base64 — emit verbatim.
            if (entry.Salt.IsEmpty)
            {
                throw new SshException(
                    SshErrorCode.Inval,
                    "SHA1-format entry missing salt");
            }

            sb.Append(CultureInfo.InvariantCulture, $"|1|{new Base64EncodedBytes(entry.Salt)}|{entry.Name}");
        }
        else
        {
            // Plain or Custom: hostname verbatim.
            sb.Append(entry.Name);
        }

        // Key type name (if present).
        if (keyTypeName is not null)
        {
            sb.Append(' ').Append(keyTypeName);
        }

        // Key body (always present).
        sb.Append(' ').Append(entry.Key);

        // Comment (if present — null means no comment; non-null means write it).
        if (entry.Comment is not null)
        {
            sb.Append(' ').Append(entry.Comment);
        }

        sb.Append('\n');
        return sb.ToString();
    }

    /// <summary>
    /// Maps a <see cref="SshKnownHostKeyType"/> to its wire-format name string.
    /// Parity with <c>knownhost_writeline</c>'s switch at
    /// <c>knownhost.c:1022-1065</c>.
    /// </summary>
    /// <returns>The wire name, or <c>null</c> for RSA1 (no name on disk).</returns>
    /// <exception cref="SshException">
    /// Thrown for <see cref="SshKnownHostKeyType.Unknown"/> entries without a
    /// stored <see cref="SshKnownHostEntry.KeyTypeName"/>.
    /// </exception>
    private static string? ResolveKeyTypeName(SshKnownHostEntry entry)
    {
        // Delegates the known-types branch to the shared HostKeyTypeRegistry.
        // The Unknown branch stays local — it carries the KeyTypeName fallback
        // + the parity-pinned "no name → MethodNotSupported throw" from
        // knownhost.c:766-770 (libssh2's "claim it's base64 for strcmp
        // purposes" comment).
        if (entry.KeyType == SshKnownHostKeyType.Unknown)
        {
            return entry.KeyTypeName
                ?? throw new SshException(
                    SshErrorCode.MethodNotSupported,
                    "Unsupported type of known-host entry");
        }

        // Returns null for Rsa1 (no SSH2 wire name on disk) — parity with the
        // original switch's `KnownHostKeyType.Rsa1 => null` branch.
        return SshHostKeyTypeRegistry.WireNameFor(entry.KeyType);
    }

    /// <summary>
    /// Reads a known_hosts file and adds all entries to this collection.
    /// Mirrors <c>libssh2_knownhost_readfile</c> (<c>knownhost.c:959-990</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The file is read as UTF-8, split on newlines, and each line is passed to
    /// <see cref="ReadLine"/>. Blank lines and comments are silently skipped;
    /// malformed lines throw <see cref="SshException"/> (the C code breaks
    /// and returns an error on the first failure — we propagate via exception).
    /// </para>
    /// <para>
    /// <b>File IO</b> goes through <see cref="AsyncFileIO"/>, the library's
    /// single async-file-IO chokepoint (allowlisted by the convention test).
    /// </para>
    /// </remarks>
    /// <param name="path">Path to the known_hosts file.</param>
    /// <param name="type">File format; defaults to <see cref="SshKnownHostFileType.OpenSsh"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of entries added (a comma-separated host line counts as N entries).</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="path"/> is <c>null</c>.</exception>
    /// <exception cref="SshException">Thrown on parse errors (wraps the underlying line error).</exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public async Task<int> ReadFileAsync(
        string path,
        SshKnownHostFileType type = SshKnownHostFileType.OpenSsh,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(path);

        string content = await AsyncFileIO.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);

        int added = 0;
        // Split on '\n' only; ReadLine strips trailing '\r' (handles CRLF files).
        string[] lines = content.Split('\n');
        foreach (string line in lines)
        {
            // ReadLine handles empty/comment lines as no-ops, so we don't need
            // to pre-filter. Count is incremented for every line that doesn't
            // throw — matches the C num++ at knownhost.c:981.
            int before = _entries.Count;
            ReadLine(line, type);
            added += _entries.Count - before;
        }

        return added;
    }

    /// <summary>
    /// Writes all entries in this collection to a known_hosts file. Mirrors
    /// <c>libssh2_knownhost_writefile</c> (<c>knownhost.c:1199-1242</c>).
    /// </summary>
    /// <remarks>
    /// Each entry is formatted via <see cref="WriteLine"/> and concatenated.
    /// The file is written atomically (UTF-8, no BOM) via
    /// <see cref="AsyncFileIO"/>.
    /// </remarks>
    /// <param name="path">Path to write.</param>
    /// <param name="type">File format; defaults to <see cref="SshKnownHostFileType.OpenSsh"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="Task"/> representing the async write operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="path"/> is <c>null</c>.</exception>
    /// <exception cref="SshException">Thrown if any entry cannot be serialized.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public async Task WriteFileAsync(
        string path,
        SshKnownHostFileType type = SshKnownHostFileType.OpenSsh,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(path);

        // Snapshot the entry list to avoid mutation during async write.
        // (List<T>.ForEach is not available on List; manual loop is fine.)
        var entries = new List<SshKnownHostEntry>(_entries);
        var sb = new StringBuilder(entries.Count * 80);
        foreach (SshKnownHostEntry entry in entries)
        {
            sb.Append(WriteLine(entry, type));
        }

        await AsyncFileIO.WriteAllTextAsync(path, sb.ToString(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Walks the entry list looking for a full host+keytype+key match against a
    /// single host form. Updates <paramref name="badkey"/> with the first
    /// host+keytype match whose key bytes differ (parity with
    /// <c>knownhost.c:404-484</c>'s inner loop).
    /// </summary>
    /// <param name="hostForm">The host string to compare against (either plain or [host]:port).</param>
    /// <param name="base64Key">The base64-encoded caller key.</param>
    /// <param name="inputFormat">Caller-side format (Plain or Custom).</param>
    /// <param name="keyType">Caller-side key type.</param>
    /// <param name="badkey">Ref-updated first mismatched entry (set once, never cleared here).</param>
    /// <returns>The fully-matching entry, or <c>null</c>.</returns>
    private SshKnownHostEntry? FindMatch(
        string hostForm,
        string base64Key,
        SshKnownHostFormat inputFormat,
        SshKnownHostKeyType keyType,
        ref SshKnownHostEntry? badkey)
    {
        foreach (SshKnownHostEntry node in _entries)
        {
            if (!HostFormMatches(node, hostForm, inputFormat))
            {
                continue;
            }

            // Key-type gate. Parity with knownhost.c:459-461:
            //   if(host_key_type != UNKNOWN && (host_key_type == 0 || host_key_type == known_key_type))
            // We do not expose the wildcard (host_key_type == 0); callers must
            // pass a concrete key type. Unknown short-circuits to no match.
            if (keyType == SshKnownHostKeyType.Unknown || keyType != node.KeyType)
            {
                // Key type mismatch — NOT a badkey (C only sets badkey inside the
                // key-type-matched branch). Continue scanning; another entry
                // with a matching key type might still hit.
                continue;
            }

            if (string.Equals(base64Key, node.Key, StringComparison.Ordinal))
            {
                return node;
            }

            badkey ??= node;
        }

        return null;
    }

    /// <summary>
    /// Tests whether <paramref name="node"/>'s hostname matches <paramref name="hostForm"/>,
    /// dispatching on the node's stored format and the caller's input format.
    /// Parity with <c>knownhost.c:407-449</c>.
    /// </summary>
    private static bool HostFormMatches(SshKnownHostEntry node, string hostForm, SshKnownHostFormat inputFormat)
    {
        // knownhost.c:407-449 dispatch. SHA1-stored entries match only when the
        // caller supplies a Plain input hostname (the library HMACs it and
        // compares to the stored digest — knownhost.c:416-446).
        return node.Format switch
        {
            SshKnownHostFormat.Plain => inputFormat == SshKnownHostFormat.Plain
                && string.Equals(hostForm, node.Name, StringComparison.Ordinal),
            SshKnownHostFormat.Custom => inputFormat == SshKnownHostFormat.Custom
                && string.Equals(hostForm, node.Name, StringComparison.Ordinal),
            SshKnownHostFormat.Sha1 => inputFormat == SshKnownHostFormat.Plain
                && HostHashMatches(node, hostForm),
            _ => false,
        };
    }

    /// <summary>
    /// Verifies a plaintext <paramref name="hostForm"/> against a SHA1-hashed
    /// entry by recomputing <c>HMAC-SHA1(salt, host)</c> and comparing to the
    /// stored digest. Parity with <c>knownhost.c:416-446</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The stored <see cref="SshKnownHostEntry.Name"/> is the base64-encoded
    /// digest (the form that appears on disk after <c>|1|&lt;salt&gt;|</c>).
    /// It is decoded here for comparison — the storage representation stays
    /// base64 so <c>WriteLine</c> round-trips without re-encoding.
    /// </para>
    /// <para>
    /// <b>Length gate</b> (parity with <c>knownhost.c:427-431</c>): the decoded
    /// digest must be exactly <c>SHA_DIGEST_LENGTH</c> (20) bytes. A stored
    /// entry whose hash isn't 20 bytes is silently skipped — it cannot have
    /// been produced by HMAC-SHA1 and so cannot match any input.
    /// </para>
    /// <para>
    /// <b>Constant-time compare</b>: the digest comparison is folded into
    /// <see cref="HMACSHA1.Verify(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>, which applies
    /// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> internally so
    /// timing does not leak how much of the hash matched. This is a hardening
    /// measure beyond the C <c>memcmp</c> (<c>knownhost.c:442</c>); the exposure
    /// window is small (host identity, not a secret key) but the cost is negligible.
    /// </para>
    /// <para>
    /// <b>Hostname encoding</b>: the input hostname is UTF-8 encoded to bytes
    /// before HMAC. ASCII hostnames (the common case) produce identical bytes
    /// to C's <c>char *</c> string; non-ASCII (IDN) hostnames should already be
    /// punycode-encoded by the caller, which is also ASCII.
    /// </para>
    /// </remarks>
    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "HMAC-SHA1 is the OpenSSH known_hosts hashed-hostname format (|1|salt|hash|); parity with libssh2 knownhost.c:416-446. Host identity, not a secret key.")]
    private static bool HostHashMatches(SshKnownHostEntry node, string hostForm)
    {
        // Defensive: Add validates non-null/non-empty salt for SHA1, but a
        // corrupt entry (or one constructed via reflection) could lack it.
        // Parity: knownhost.c:432-434 fails closed on _libssh2_hmac_sha1_init
        // error; we fail closed on a missing salt.
        if (node.Salt.IsEmpty)
        {
            return false;
        }

        // Decode the stored hash. Add stored it verbatim from the on-disk base64
        // form, so a corrupt entry might not decode cleanly. Uses libssh2's
        // lenient decoder (misc.c:396-424): an unpadded stored digest — which
        // the C accepts and matches — previously failed the BCL decoder and
        // silently never matched. The C's only
        // decode failure (a lone leftover sextet) throws Inval → no match.
        // Use the lenient decoder's ceiling capacity rather than the BCL strict
        // decoder's floor bound. The extra capacity holds the staged byte for
        // an unpadded partial trailing group.
        int storedHashCapacity = LenientBase64.GetMaxDecodedLength(node.Name.Length);
        byte[] storedHashBuffer = ArrayPool<byte>.Shared.Rent(storedHashCapacity);
        byte[]? hostBytesBuffer = null;
        try
        {
            int storedHashLength;
            try
            {
                storedHashLength = LenientBase64.Decode(node.Name, storedHashBuffer);
            }
            catch (SshException ex) when (ex.ErrorCode == SshErrorCode.Inval)
            {
                // Silent skip on a corrupt stored digest — parity with
                // knownhost.c:427-431.
                return false;
            }

            // Parity with knownhost.c:427-431 — SHA1 produces exactly 20 bytes.
            const int Sha1DigestLength = 20;
            if (storedHashLength != Sha1DigestLength)
            {
                return false;
            }

            ReadOnlySpan<byte> storedHash = storedHashBuffer.AsSpan(0, storedHashLength);

            hostBytesBuffer = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(hostForm.Length));
            int hostBytesLength = Encoding.UTF8.GetBytes(hostForm, hostBytesBuffer);
            ReadOnlySpan<byte> hostBytes = hostBytesBuffer.AsSpan(0, hostBytesLength);

            // Compute HMAC-SHA1(salt, host) and compare to the stored digest in one
            // call. HMACSHA1.Verify does the keyed hash + a constant-time
            // FixedTimeEquals internally (and zeroizes its scratch), replacing the
            // manual IncrementalHash + FixedTimeEquals pair. The 20-byte length
            // guard above is required: Verify throws ArgumentException on a
            // non-HashSizeInBytes hash, but parity with knownhost.c:427-431 wants a
            // silent skip (return false) for a corrupt stored digest.
            return HMACSHA1.Verify(node.Salt.Span, hostBytes, storedHash);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(storedHashBuffer);
            if (hostBytesBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(hostBytesBuffer);
            }
        }
    }

    /// <summary>
    /// Removes <paramref name="entry"/> from the collection. Mirrors
    /// <c>libssh2_knownhost_del</c> (<c>knownhost.c:568-593</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Identity comparison:</b> uses <see cref="ReferenceEqualityComparer"/>
    /// — matches the C API, which compares entries by their
    /// <c>struct known_host*</c> node pointer (<c>knownhost.c:583</c>'s
    /// <c>_libssh2_list_remove</c>). Two entries that happen to share all field
    /// values but were added separately are distinct for deletion. The
    /// <see cref="SshKnownHostEntry"/>'s inherited record value equality is
    /// deliberately bypassed; treat the entry returned by <see cref="Add(string, byte[], byte[], SshKnownHostKeyType, SshKnownHostFormat, string)"/> as
    /// a handle.
    /// </para>
    /// <para>
    /// <b>No-op if not present:</b> deleting an entry that isn't in this
    /// collection returns <c>false</c> without throwing. This diverges slightly
    /// from C, which returns <c>LIBSSH2_ERROR_INVAL</c> for a bad handle, but
    /// matches typical C# collection semantics and avoids races where the
    /// caller's handle was already removed.
    /// </para>
    /// </remarks>
    /// <param name="entry">The entry to remove (must be a handle from <see cref="Add(string, byte[], byte[], SshKnownHostKeyType, SshKnownHostFormat, string)"/>).</param>
    /// <returns><c>true</c> if the entry was found and removed; <c>false</c> if not present.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="entry"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public bool Delete(SshKnownHostEntry entry)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(entry);

        int idx = _entries.FindIndex(e => ReferenceEquals(e, entry));
        if (idx < 0)
        {
            return false;
        }

        _entries.RemoveAt(idx);
        return true;
    }

    /// <summary>
    /// Returns the first entry in insertion order, or <c>null</c> if empty.
    /// Mirrors <c>libssh2_knownhost_get</c> called with <c>oprev = NULL</c>
    /// (<c>knownhost.c:1256-1280</c>).
    /// </summary>
    /// <returns>The first entry, or <c>null</c>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public SshKnownHostEntry? GetFirst()
    {
        ThrowIfDisposed();
        return _entries.Count > 0 ? _entries[0] : null;
    }

    /// <summary>
    /// Returns the entry after <paramref name="previous"/> in insertion order,
    /// or <c>null</c> at end-of-list. Mirrors <c>libssh2_knownhost_get</c>
    /// called with <c>oprev != NULL</c> (<c>knownhost.c:1262-1268</c>).
    /// </summary>
    /// <remarks>
    /// Uses <see cref="ReferenceEqualityComparer"/> to locate
    /// <paramref name="previous"/> — see <see cref="Delete"/> for the rationale
    /// (entries are handles, not values).
    /// </remarks>
    /// <param name="previous">An entry previously returned by <see cref="GetFirst"/> or this method.</param>
    /// <returns>The next entry, or <c>null</c> if <paramref name="previous"/> was the last entry or is no longer present.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="previous"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if this instance is disposed.</exception>
    public SshKnownHostEntry? GetNext(SshKnownHostEntry previous)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(previous);

        int idx = _entries.FindIndex(e => ReferenceEquals(e, previous));
        if (idx < 0 || idx + 1 >= _entries.Count)
        {
            return null;
        }

        return _entries[idx + 1];
    }

    /// <summary>
    /// Releases the entry list. Idempotent. Mirrors
    /// <c>libssh2_knownhost_free</c> (<c>knownhost.c:601-612</c>) minus the
    /// explicit per-entry free (handled by the GC).
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _entries.Clear();
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
