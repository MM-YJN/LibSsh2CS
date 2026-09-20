# LibSsh2CS

A standalone managed C# port of [libssh2](https://libssh2.org/) for .NET 11.
LibSsh2CS provides asynchronous SSH-2 sessions, authentication, command execution,
and forwarding without requiring the native libssh2 library. The library and
tests were migrated from LibGit2CS and have no dependency on it.

## Installation

The library targets .NET 11.

```sh
dotnet add package LibSsh2CS
```

## Quick start

Connect to an SSH server, verify its host key, and run a command. Replace the
host and username, set `SSH_PASSWORD`, and set `SSH_HOST_FINGERPRINT` to the
server's SHA-256 fingerprint obtained through a trusted channel (in
`SHA256:...` format, without Base64 padding).

```csharp
using System.Net.Sockets;
using System.Security.Cryptography;
using LibSsh2CS;

const string host = "ssh.example.com";
const int port = 22;
string password = Environment.GetEnvironmentVariable("SSH_PASSWORD")
    ?? throw new InvalidOperationException("Set SSH_PASSWORD.");
string trustedFingerprint = Environment.GetEnvironmentVariable("SSH_HOST_FINGERPRINT")
    ?? throw new InvalidOperationException("Set SSH_HOST_FINGERPRINT.");

using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
CancellationToken ct = timeout.Token;
using var client = new TcpClient();
await client.ConnectAsync(host, port, ct);
await using var session = new SshSession();

await session.HandshakeAsync(client.GetStream(), (hostKey, _, _) =>
{
    string fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(hostKey))
        .TrimEnd('=');
    return Task.FromResult(fingerprint == trustedFingerprint);
}, ct);

await session.AuthenticateWithPasswordAsync("alice", password, cancellationToken: ct);
await using SshChannel channel = await session.OpenSessionAsync(ct);
await channel.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, ct);
await channel.ExecAsync("echo hello", ct);
await channel.SendEofAsync(ct);

using Stream output = Console.OpenStandardOutput();
byte[] buffer = new byte[4096];
int count;
while ((count = await channel.ReadAsync(buffer, ct)) != 0)
{
    await output.WriteAsync(buffer.AsMemory(0, count), ct);
}

int exitCode = await channel.GetExitStatusAsync(ct);
Console.WriteLine($"Exit status: {exitCode}");
```

The examples below reuse `session` and `ct` from this setup. Authentication
examples replace the password call and run after the handshake, before opening
channels. Other channel examples use an authenticated session.

## Verify a known host

`HandshakeAsync` requires a host-trust callback. The library verifies the
server's exchange signature first; the callback decides whether to trust the
host key. Returning `false` aborts the handshake.

As an alternative to fingerprint pinning, load a previously trusted OpenSSH
`known_hosts` file. This example restricts negotiation to Ed25519 so the key
type passed to `Check` matches the negotiated key. Use it in place of the
handshake above:

```csharp
using var knownHosts = new SshKnownHosts();
await knownHosts.ReadFileAsync("/path/to/trusted/known_hosts", cancellationToken: ct);
session[SshMethodType.HostKey] = "ssh-ed25519";

await session.HandshakeAsync(client.GetStream(), (hostKey, _, _) =>
{
    SshKnownHostCheckResult result = knownHosts.Check(
        host, port, hostKey, SshKnownHostKeyType.Ed25519);
    return Task.FromResult(result.Status == SshKnownHostCheckStatus.Match);
}, ct);
```

Only `Match` is accepted; a missing or mismatched entry is rejected. Load the
file explicitly: the session does not automatically read `~/.ssh/known_hosts`.
The callback applies to the initial handshake; it is not called again during
rekeying.

## Authenticate with a private key

Read the private key into memory and let the library derive its public key.
The parser supports OpenSSH private keys and supported PEM formats, including
RSA, ECDSA, and Ed25519 keys.

```csharp
byte[] privateKeyData = await File.ReadAllBytesAsync("/path/to/id_ed25519", ct);
await session.AuthenticateWithPublicKeyAsync(
    "alice",
    publicKeyBlob: null,
    privateKeyData: privateKeyData,
    passphrase: Environment.GetEnvironmentVariable("SSH_KEY_PASSPHRASE"),
    cancellationToken: ct);
```

For signing outside the library, use the public-key overload that accepts a
`PublicKeySignCallback`. Password-change and keyboard-interactive callbacks are
also available through `SshUserAuth`.

## Authenticate through an SSH agent

`new SshAgent()` discovers the agent when `ConnectAsync` runs: on Windows it
tries Pageant first and then the Unix socket named by `SSH_AUTH_SOCK`, and on
other platforms it uses the Unix socket. Passing a socket path to the
constructor — or setting `IdentityPath` before connecting, which is rejected
once a connect has started or the agent is connected — pins the client to that
Unix socket and skips discovery.

```csharp
using LibSsh2CS.Agent;

await using var agent = new SshAgent();
await agent.ConnectAsync(ct);
IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(ct);
if (identities.Count == 0)
{
    throw new InvalidOperationException("The SSH agent has no loaded identities.");
}

await agent.AuthenticateWithIdentityAsync(session, "alice", identities[0], ct);
```

This example selects the first identity; choose the identity authorized for your
account. The agent performs the signing.

Pageant is reached through its legacy `WM_COPYDATA` and file-mapping interface,
so the client and Pageant must run in the same Windows session and user context.
Requests are limited to 8188 bytes. A request waits — for an earlier request to
finish and for Pageant to answer — for at most five minutes, long enough for
Pageant's confirmation and passphrase prompts; that bound applies to the caller,
not to Pageant's work: the request travels through a synchronous window message
that completes only when Pageant's window procedure has processed it. The
mapping must stay valid for as long as Pageant can still read it, so a timeout
or cancellation releases the caller immediately while the worker keeps the
native send, the mapping, and the message data alive until that send returns;
Pageant may still act on a request it already received, and a Pageant that never
returns can retain that worker until its window procedure returns or its process
exits. Only one request can be outstanding at a time, so a retry waits for that
worker instead of starting a second native send, and repeated retries cannot
accumulate workers, mappings, or pinned message data. The Windows OpenSSH
named-pipe agent backend is not implemented.

## Read command output and send input

`ReadAsync` reads stdout and `ReadStderrAsync` reads stderr by default. Drain both
streams while a command runs so buffered output does not exhaust the channel
window. Alternatively, set `SshExtendedDataMode.Merge` before starting the
command, as in the quick start, or use `Ignore` to discard stderr.

In merge mode, stdout is drained before buffered stderr; their original
interleaving is not preserved. Reads return bytes, so use a streaming decoder
if you need to decode text across read boundaries.

Send input with `WriteAsync` and call `SendEofAsync` when finished:

```csharp
await using SshChannel command = await session.OpenSessionAsync(ct);
await command.SetExtendedDataModeAsync(SshExtendedDataMode.Merge, ct);
await command.ExecAsync("wc -c", ct);
await command.WriteAsync("hello\n"u8.ToArray(), ct);
await command.SendEofAsync(ct);

using Stream destination = Console.OpenStandardOutput();
byte[] bytes = new byte[4096];
int received;
while ((received = await command.ReadAsync(bytes, ct)) != 0)
{
    await destination.WriteAsync(bytes.AsMemory(0, received), ct);
}

int status = await command.GetExitStatusAsync(ct);
Console.WriteLine($"Exit status: {status}");
```

Drain output before waiting for exit status. `GetExitStatusAsync` waits for exit
information or channel closure; it returns zero if the server closes without
sending a status. `ExitSignal` exposes a received termination signal.

For interactive sessions, request a PTY with `RequestPtyAsync` before calling
`ShellAsync`. Use `SetEnvAsync` before starting the process; the server decides
which environment variables to accept.

## Open a forwarded connection

Ask the SSH server to connect to a TCP endpoint reachable from that server:

```csharp
await using SshChannel tunnel = await session.OpenDirectTcpIpAsync(
    "127.0.0.1", 5432, cancellationToken: ct);

// Exchange the destination protocol's bytes using tunnel.ReadAsync and WriteAsync.
```

`ListenForwardAsync` requests remote TCP forwarding and returns an `SshListener`
for accepting forwarded channels. `OpenDirectStreamLocalAsync` connects to a Unix
socket on the server. Forwarding must be permitted by the server; applications
supply their own local listeners and byte-copy loops when building tunnels.

## Lifecycle and scope

The caller owns the transport passed to `HandshakeAsync`; disposing a session
does not close that stream or socket. Dispose channels before the session, then
dispose the transport. Use `await using` for sessions, channels, and agents, and
pass cancellation tokens to network operations.

Set algorithm preferences through the session indexer before the handshake.
`ReadTimeout` controls transport reads, and `RekeyPolicy` configures automatic
rekey thresholds. Time-based rekey checks run during channel activity.
`ConfigureKeepAlive` sets keepalive behavior, but the application must schedule
calls to `SendKeepAliveAsync`; the library does not start a keepalive timer.

LibSsh2CS exposes SSH transport and channel primitives. SFTP and SCP clients are
not implemented. Opening `SubsystemAsync("sftp")` still requires the caller to
implement the SFTP protocol over the channel.

See the [repository README](../../README.md) for build commands and test
prerequisites, and the [source XML comments](SshSession.cs) for API contracts.

## License and attribution

LibSsh2CS is licensed under the [BSD 3-Clause License](../../LICENSE), with
applicable upstream terms. It includes code translated from libssh2 and
Ed25519 arithmetic translated from libsodium. See
[THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md) for upstream attribution, permissions,
and file-specific terms.

`LICENSE` and `THIRD-PARTY-NOTICES.md` are included when packing the library and
must accompany binary redistributions. No upstream endorsement is implied.
