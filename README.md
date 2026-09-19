# LibSsh2CS

A C# port of [libssh2](https://libssh2.org/) for .NET 11.
LibSsh2CS provides asynchronous SSH-2 sessions, authentication, command execution,
and forwarding without requiring the native libssh2 library. The library and
tests were migrated from LibGit2CS and have no dependency on it.

The porting work is primarily done by AI.

## Features

- Asynchronous SSH-2 handshakes over a caller-owned `Stream` or `IDuplexPipe`.
- Password, public-key, keyboard-interactive, host-based, and SSH agent authentication.
- Command execution, interactive shells, PTYs, environment variables, and subsystem channels.
- Channel input/output, stderr handling, exit status, and signals.
- Direct TCP/IP channels, remote TCP forwarding, and OpenSSH Unix socket forwarding.
- OpenSSH known-hosts files, explicit host-trust callbacks, rekeying, and keepalive requests.
- Managed implementation with AOT compatibility enabled.

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

The session leaves the transport open; the caller disposes the `TcpClient`.
The example merges stderr into the output. See the
[library README](source/LibSsh2CS/README.md) for authentication alternatives,
known-hosts verification, and channel usage.

## Compatibility

This is a port of portions of libssh2, with an asynchronous C# API. It does not
provide every native libssh2 feature. SFTP and SCP clients are not implemented;
`SubsystemAsync("sftp")` opens a subsystem channel but does not implement the
SFTP protocol. The SSH agent transport currently supports Unix domain sockets;
Pageant and Windows OpenSSH named-pipe backends are not implemented.

Unit tests cover protocol behavior and cryptographic fixtures. Docker integration
tests exercise live OpenSSH servers, including authentication, channels,
forwarding, and algorithm negotiation.

## Documentation

- [Library usage and examples](source/LibSsh2CS/README.md)
- [Public API source and XML comments](source/LibSsh2CS/)
- [Integration examples](tests/LibSsh2CS.IntegrationTests/Session/)

Separate prose API guides are pending.

## Development

Use the SDK selected by [global.json](global.json). From the repository root:

```sh
dotnet restore LibSsh2CS.slnx --locked-mode
dotnet build LibSsh2CS.slnx --no-restore
dotnet build LibSsh2CS.slnx -c Release --no-restore
dotnet format LibSsh2CS.slnx --verify-no-changes --no-restore
dotnet test --solution LibSsh2CS.slnx --no-build --list-tests
dotnet test --solution LibSsh2CS.slnx --no-build
```

Tests use xUnit v3 on Microsoft Testing Platform, not VSTest. Integration tests
require Docker with Linux containers and network access to build the OpenSSH
images. Agent tests also require `ssh-agent` and `ssh-add` on `PATH`.
Docker-dependent tests skip when Docker is unreachable; agent tests skip when
those binaries are missing. Report skips separately from successful integration
validation. Fixture setup can take 10 minutes even for a single integration test;
allow additional time for test execution.

Run just the unit suite after building:

```sh
dotnet test --project tests/LibSsh2CS.UnitTests/LibSsh2CS.UnitTests.csproj --no-build
```

Keep reports and coverage under `artifacts/`. See [AGENTS.md](AGENTS.md) for
repository conventions and validation requirements.

## License and attribution

LibSsh2CS is licensed under the [BSD 3-Clause License](LICENSE), with
applicable upstream terms. It includes code translated from libssh2 and
Ed25519 arithmetic translated from libsodium. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for upstream attribution, permissions,
and file-specific terms.

`LICENSE` and `THIRD-PARTY-NOTICES.md` are included when packing the library and
must accompany binary redistributions. No upstream endorsement is implied.
