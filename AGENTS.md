# Repository guidance

LibSsh2CS is a standalone managed C# port of libssh2. Read the project files
under `source/` and `tests/` for target frameworks, and `global.json` for the SDK
version. Read `README.md` and `source/LibSsh2CS/README.md` for API usage and
compatibility scope before changing SSH behavior.

## Layout

- `source/LibSsh2CS/`: library; `SshSession.cs`, `SshChannel.cs`, and
  `SshKnownHosts.cs` expose session, channel, and known-hosts APIs. `Transport/`
  handles SSH transport and key exchange, `Crypto/` holds cryptographic helpers,
  `Agent/` implements SSH agent support, and `IO/` and `Util/` hold helpers.
- `tests/LibSsh2CS.UnitTests/`: xUnit v3 tests, embedded `Fixtures/`, and reference
  fixture generation scripts.
- `tests/LibSsh2CS.IntegrationTests/`: xUnit v3 Docker-based OpenSSH integration
  tests and embedded fixtures.
- `source/LibSsh2CS/README.md`: library usage guide and NuGet package readme;
  the root `README.md` introduces the project, compatibility, and prerequisites.
- `Directory.Build.props`: shared build, analyzer, and versioning settings.
  `global.json` selects the SDK and Microsoft Testing Platform (MTP).

## Development commands

Run commands from the repository root with the SDK selected by `global.json`.

```sh
dotnet restore LibSsh2CS.slnx --locked-mode
dotnet build LibSsh2CS.slnx --no-restore
dotnet build LibSsh2CS.slnx -c Release --no-restore
dotnet format LibSsh2CS.slnx --verify-no-changes --no-restore
dotnet test --solution LibSsh2CS.slnx --no-build
```

For focused test runs, discover names first and put xUnit runner options after
`--`:

```sh
dotnet test --project tests/LibSsh2CS.UnitTests/LibSsh2CS.UnitTests.csproj --no-build --list-tests
dotnet test --project tests/LibSsh2CS.UnitTests/LibSsh2CS.UnitTests.csproj --no-build -- --filter-class "LibSsh2CS.UnitTests.Transport.PacketReaderTests"
```

Omit the runner filter to run the full unit suite alone.

Use `.agents/skills/dotnet-mtp-tests/SKILL.md` for filtering and coverage details.
This repository uses MTP with `coverlet.MTP`; do not substitute VSTest
`--filter` or `--collect:"XPlat Code Coverage"` options. Keep generated coverage
and reports under `artifacts/`. Restore repository tools with `dotnet tool restore`
when needed; see `.agents/skills/reportgenerator/SKILL.md` for coverage reports
and `.agents/skills/dotnet-inspect/SKILL.md` for .NET API inspection.

Integration tests require Docker with Linux containers and network access for
image builds; agent tests also require `ssh-agent` and `ssh-add`. See `README.md`
for prerequisites and skip behavior. Report skipped tests separately from
successful integration validation. Docker fixture setup can take 10 minutes,
even when running only one integration test. AI agents should use generous
timeouts that allow for this setup time plus test execution, and should not
treat slow fixture startup alone as a hung test.

For code changes, run the relevant tests while iterating and the full solution
tests before finishing. For comment-only or documentation-only changes, verify
paths, examples, and claims; review the diff and run `git diff --check`. A build
or test run is unnecessary unless executable behavior is affected. Report
checks performed and any checks that could not run.

## Implementation conventions

- Follow `.editorconfig` and surrounding code: four-space C# indentation,
  file-scoped namespaces, nullable annotations, and XML documentation for public
  APIs. Preserve existing copyright and license headers.
- If whitespace or code-style warnings occur, try `dotnet format LibSsh2CS.slnx`
  for automatic fixes. Review the diff and keep formatting changes scoped to
  the task.
- Preserve the asynchronous SSH API, AOT compatibility, and independence from
  LibGit2CS and the native libssh2 library.
- Preserve caller ownership of session transports and explicit host-key trust
  verification. Keep documented compatibility limits accurate; opening an SFTP
  subsystem channel does not implement the SFTP protocol.
- Add regression coverage for behavior fixes, especially packet framing,
  authentication, key exchange, channel handling, and cancellation. Use the
  cryptographic fixtures and live OpenSSH integration tests as appropriate.
- Update the relevant readmes when public behavior changes. Keep dependency
  changes intentional. Whenever any dependency or the .NET SDK version changes,
  run `dotnet restore LibSsh2CS.slnx --force-evaluate` to regenerate all solution
  package lock files. Review and include the resulting `packages.lock.json`
  changes with the dependency or SDK change. Avoid unrelated formatting or
  dependency churn.

## Fixtures and attribution

Treat golden fixtures as reference evidence. Investigate mismatches before
changing expected output; do not regenerate goldens merely to make tests pass.
Read `tests/LibSsh2CS.UnitTests/generate-goldens.sh` and the relevant capture or
generation scripts before modifying reference fixtures. Generators may need
external source checkouts and capture tools; ordinary unit test runs use the
embedded fixtures. Record source revisions, generation details, and attribution
when adding or replacing upstream material.

Respect `.gitattributes`: C# source uses CRLF, shell scripts use LF, and fixture
text uses LF with explicit binary exceptions. Do not normalize fixture bytes
or add/remove final newlines as cleanup.

The project uses BSD-3-Clause. Preserve `LICENSE`, `THIRD-PARTY-NOTICES.md`, and
fixture-specific notices and licenses in source and binary distributions.
When translating or migrating code, preserve upstream copyright and permission
notices, add provenance to `THIRD-PARTY-NOTICES.md`, and retain file-specific
terms in the source. Do not replace these terms with another project's license
or publish packages as part of scaffold maintenance. Release setup is pending.

## Before committing

Before any agent-created commit, verify the effective repository setting with
`git config --get core.autocrlf`: it must be `true` on Windows and `input` on
Linux or macOS. Instruct the user to configure the appropriate setting from
the repository root before any commits:

- Windows: `git config core.autocrlf true`
- Linux/macOS: `git config core.autocrlf input`

If the setting is missing or incorrect, ask the user to run the appropriate
command and verify it again before committing. Do not commit until the setting
matches the operating system.
