namespace LibSsh2CS;

/// <summary>
/// A single known_hosts entry: a hostname (or its HMAC-SHA1 hash), an
/// associated public key, and the metadata needed to round-trip the entry
/// through <c>ReadLine</c>/<c>WriteLine</c>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the C <c>struct known_host</c> (<c>knownhost.c:43-62</c>), replacing
/// the C pointer + length pairs with C# strings and byte arrays. The C
/// <c>typemask</c> bitfield is unpacked into <see cref="Format"/> and
/// <see cref="KeyType"/> named fields — the bit layout is an API convention
/// only and never appears on disk.
/// </para>
/// <para>
/// <b>Key representation:</b> the key is stored base64-encoded (matching
/// <c>struct known_host-&gt;key</c>, which the C code keeps base64 throughout
/// its lifetime). <see cref="SshKnownHosts.Add(string, byte[], byte[], SshKnownHostKeyType, SshKnownHostFormat, string)"/>
/// accepts either raw bytes or a pre-encoded base64 string; raw bytes are
/// encoded once at <c>Add</c> time.
/// </para>
/// <para>
/// <b>Hostname representation:</b>
/// <list type="bullet">
/// <item><term><see cref="SshKnownHostFormat.Plain"/></term>
///     <description><see cref="Name"/> is the plaintext hostname; <see cref="Salt"/> is <c>null</c>.</description></item>
/// <item><term><see cref="SshKnownHostFormat.Custom"/></term>
///     <description><see cref="Name"/> is the caller-supplied pre-hashed hostname (compared by string equality); <see cref="Salt"/> is <c>null</c>.</description></item>
/// <item><term><see cref="SshKnownHostFormat.Sha1"/></term>
///     <description><see cref="Name"/> is the HMAC-SHA1 digest (already base64-decoded into bytes — i.e. <see cref="Name"/> holds the raw digest text); <see cref="Salt"/> is the raw salt bytes. For fidelity to <c>struct known_host-&gt;name</c>/<c>salt</c>, these are not re-encoded into base64 in memory — only at <c>WriteLine</c> time.</description></item>
/// </list>
/// </para>
/// <para>
/// <b>Comment distinction:</b> a <c>null</c> <see cref="Comment"/> means no
/// comment (no trailing space written); an empty-string comment means an empty
/// comment (a single space is written after the key). This matches the C
/// semantics at <c>knownhost.c:819-820</c>.
/// </para>
/// <para>
/// Equality is reference-based by design (mirroring the C API, which compares
/// entries by their <c>struct known_host*</c> pointer for
/// <c>libssh2_knownhost_del</c>). Two entries with identical fields but added
/// separately are distinct for deletion purposes. The record's inherited value
/// equality is therefore not used; treat this type as a handle.
/// </para>
/// </remarks>
/// <param name="Name">
/// The hostname, pre-hash plaintext (for <see cref="SshKnownHostFormat.Plain"/>,
/// <see cref="SshKnownHostFormat.Custom"/>), or the base64-decoded HMAC-SHA1
/// digest text (for <see cref="SshKnownHostFormat.Sha1"/>). Never <c>null</c>.
/// </param>
/// <param name="Salt">
/// Raw salt bytes for <see cref="SshKnownHostFormat.Sha1"/> entries; <c>null</c>
/// for all other formats.
/// </param>
/// <param name="Key">
/// The base64-encoded public key (no key-type prefix; no comment). Never
/// <c>null</c> or empty.
/// </param>
/// <param name="KeyType">
/// Discriminator for the key algorithm. <see cref="SshKnownHostKeyType.Unknown"/>
/// entries are stored for round-trip but never match a <c>Check</c>.
/// </param>
/// <param name="Format">
/// Hostname encoding format. Drives the <c>Check</c> comparison rule and the
/// <c>WriteLine</c> output shape.
/// </param>
/// <param name="Comment">
/// Optional trailing comment, or <c>null</c> for no comment. See remarks for
/// the <c>null</c>-vs-empty distinction.
/// </param>
/// <param name="KeyTypeName">
/// Wire-format key type name (e.g. <c>"ssh-rsa"</c>, <c>"sk-ssh-ed25519@openssh.com"</c>).
/// Populated only when <see cref="KeyType"/> is <see cref="SshKnownHostKeyType.Unknown"/>
/// — i.e. the parser saw a key type name it didn't recognize and preserved it
/// verbatim for round-tripping. Parity with <c>struct known_host-&gt;key_type_name</c>
/// (<c>knownhost.c:54</c>) and the storage gate at <c>knownhost.c:221-232</c>
/// (only UNKNOWN entries store the name). <c>null</c> for all recognized types;
/// the name is implied by <see cref="KeyType"/> and re-derived at write time.
/// </param>
public sealed record SshKnownHostEntry(
    string Name,
    byte[]? Salt,
    string Key,
    SshKnownHostKeyType KeyType,
    SshKnownHostFormat Format,
    string? Comment,
    string? KeyTypeName = null);
