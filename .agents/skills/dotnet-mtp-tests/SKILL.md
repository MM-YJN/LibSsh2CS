---
name: dotnet-mtp-tests
description: Run and filter xUnit v3 tests on Microsoft Testing Platform (MTP), including coverlet.MTP coverage and HTML reports. Use for dotnet test, MTP runner options, test discovery/filtering, or coverage. Do not use for build, Aspire, or performance tests.
---

# .NET MTP Tests

## Run Tests

Put project/solution and dotnet options before `--`; put every MTP, xUnit, and
Coverlet option after it.

```sh
dotnet test <TP> -- <runner-options>
dotnet test --solution <SLN> -- <runner-options>
```

MTP test projects use `<OutputType>Exe</OutputType>` and `xunit.v3.mtp-v2`.

## Help & discovery

`--help` goes **before** `--` (it is a `dotnet test` option) and prints every
option on both sides of `--` — `dotnet test` options first, then **Platform
Options** (MTP), then **Extension Options** (xUnit v3 + coverlet.MTP). Do not put
`--help` after `--`: the MTP runner crashes with an "unexpected help-related
message" error.

```sh
dotnet test <TP> --help              # full option list (all three sections)
dotnet test <TP> --no-build --help    # skip rebuild, just print help
```

`--list-tests` is also a `dotnet test` option (before `--`) and takes no
argument. It prints fully-qualified test display names (one per line, including
theory parameters in parentheses, e.g. `MyClass.MyTheory(arg: "value")`).
It **ignores any `--filter-*` options** (those live after `--` and are not
applied during discovery), so use it to see the full inventory and pick the
exact fully-qualified class/method names your filters need.

```sh
dotnet test <TP> --no-build --list-tests
```

## Filter

All `--filter-*` options are MTP/xUnit runner options and go **after `--`**.
Simple filters cannot be combined with `--filter-query`. Values support `*` only
at the start and/or end. Repeat include filters of the **same type** for OR;
repeat excludes for AND. Different simple-filter types (e.g.
`--filter-class` + `--filter-method`) combine with AND across types but OR
within a type — verify with `--list-tests` first.

Classes and exact methods must be fully qualified (namespace + class name);
`--filter-namespace` is recursive (matches sub-namespaces).

Confirm the exact namespace/class/method names with `--list-tests` before
filtering.

```sh
dotnet test tests/MyProj.UnitTests/MyProj.UnitTests.csproj -- --filter-class "MyNamespace.MyClass"
```

### Simple filters

```sh
# Include filters — repeated values of the SAME type OR together
--filter-class    "MyNamespace.MyClass"            # fully qualified
--filter-method   "*Constructor*"                  # wildcard
--filter-namespace "MyNamespace.Feature"           # recursive (sub-namespaces too)

# Traits — exact "name=value", or * on either side of name and/or value
--filter-trait "Category=Unit"
--filter-trait "Category=*"
--filter-trait "*=Unit"

# Exclude filters — repeated values of the SAME type AND together
--filter-not-method "*Slow*" --filter-not-method "*Flaky*"   # AND
--filter-not-class "*SlowTests"
--filter-not-namespace "MyNamespace.Legacy"

# Same-type repeats OR (includes) / AND (excludes), cross-type intersect
--filter-class "MyNamespace.MyClass" --filter-method "*Constructor*"
# → both filters apply (class AND method-wildcard)

# Exit code 8 when a filter matches nothing — silence with --ignore-exit-code 8
--filter-method "*DoesNotExist*" --ignore-exit-code 8
```

### Query filters

`--filter-query "/assembly/namespace/class/method[trait=value]"` — the query
**must begin with `/`**. Segments are matched against the assembly simple name,
the namespace, the **class name only** (not fully qualified), and the method
name, in that order. Omit trailing segments to wildcard them; `*` in a segment
matches all. Repeated `--filter-query` values OR together.

Trait expressions (`[name=value]` / `[name!=value]`) attach to the **last
explicit segment** — they do not combine with intermediate `*` wildcards.
Prefer the standalone `/[trait]` or `/assembly/[trait]` form for pure trait
filtering; use a full 3- or 4-segment query only when you also want to narrow
by namespace/class/method.

```sh
# Pure trait filter — last explicit segment is the assembly
--filter-query "/[Category=Smoke]"
--filter-query "/MyTests/[Category=Smoke]"

# Narrow by namespace and class — class segment is the BARE class name
--filter-query "/MyTests/MyNamespace.Feature/MyClass"
# equivalent to …/MyClass/* and …/MyClass/

# OR within a segment via parenthesized alternatives
--filter-query "/MyTests/MyNamespace.Feature/(MyClass)|(OtherClass)/*"

# Trait on the LAST explicit segment (here: the class segment)
--filter-query "/MyTests/MyNamespace.Feature/MyClass[Category=Smoke]"
# method wildcarded implicitly

# DO NOT put a trait after intermediate wildcards — silently matches nothing:
# /MyTests/*/*/*[Category=Smoke]   ← 0 tests (DO NOT USE)
# /MyTests/*[Category=Smoke]      ← 0 tests (DO NOT USE)
# Use "/[Category=Smoke]" or "/MyTests/[Category=Smoke]" instead.
```

Query syntax: <https://xunit.net/docs/query-filter-language>

### AND/OR semantics summary

| Same filter type, repeated | Different filter types together |
|---|---|
| `--filter-class A --filter-class B` → **OR** | `--filter-class A --filter-method "*X*"` → **AND** |
| `--filter-not-class A --filter-not-class B` → **AND** | `--filter-class A --filter-not-method "*X*"` → **AND** |
| `--filter-query Q1 --filter-query Q2` → **OR** | simple + query → **error** (mutually exclusive) |

## Common Options

Options split by where they go: `dotnet test` options before `--`, MTP/xUnit
runner options after. Run `dotnet test <TP> --help` for the full, authoritative
list (three sections: `dotnet test` / Platform Options / Extension Options).

```sh
# MTP/xUnit runner options — after --
--output Detailed            # or Normal (default)
--parallel none              # or collections (default)
--max-threads 4              # default | unlimited | <int> | <float>x
--fail-skips on              # treat skipped tests as failed (default off)
--fail-warns on              # treat passing-with-warnings as failed (default off)
--stop-on-fail on            # halt after first failure (default off)
--culture invariant          # or default, or a named culture like en-US
--timeout 5m                 # global execution timeout: <value>[h|m|s]
--minimum-expected-tests 100 # fail if fewer than N tests ran
--seed 12345                 # fixed randomization seed
--diagnostic                 # trace-level log file in output dir
--ignore-exit-code 8         # treat exit 8 (no tests matched) as success
```

`--help` and `--list-tests` are covered above in [Help & discovery](#help--discovery).
Use `--list-tests` to verify fully qualified names when a filter finds no
tests. An unrecognized runner option is usually on the wrong side of `--`.
A filter that matches zero tests exits with code 8; add `--ignore-exit-code 8`
after `--` to treat that as success (useful in scripts).

## Coverage

`coverlet.MTP` provides coverage; coverage is opt-in. Keep all output under
`artifacts/` (or another path the user specifies) unless the repo has its own
convention.

**`coverlet.MTP` has no `--coverlet-output` option** — the output location is
controlled by `dotnet test`'s `--results-directory` (before `--`) and the
filename by `--coverlet-file-prefix` (after `--`). The emitted file is named
`<prefix>.cobertura.<timestamp>.xml`
(default prefix `coverage` → `coverage.cobertura.<ts>.xml`).

```sh
dotnet test <TP> \
  --results-directory ./artifacts/coverage \
  -- \
  --filter-method "*MyFeature*" \
  --coverlet \
  --coverlet-output-format cobertura \
  --coverlet-include "[MyAssembly]*"

# Glob with a leading * so it matches any file-prefix and the trailing timestamp.
# reportgenerator is a common dotnet tool — install/restore once first.
dotnet tool restore   # if declared in dotnet-tools.json
dotnet reportgenerator \
  "-reports:./artifacts/coverage/*.cobertura.*.xml" \
  "-targetdir:./artifacts/coverage/report" \
  "-assemblyfilters:+MyAssembly" \
  -reporttypes:Html
```

Open `artifacts/coverage/report/index.html` for the HTML summary.

If `reportgenerator` is a repo-local dotnet tool declared in `dotnet-tools.json`,
it must be invoked as `dotnet reportgenerator` (the bare `reportgenerator`
command is not on PATH). Run `dotnet tool restore` once per clone/checkout
before the first report.

Supported Coverlet options (all after `--`; run `--help` for the full list):

```text
--coverlet
--coverlet-output-format json|lcov|opencover|cobertura  # comma-separated formats allowed
--coverlet-file-prefix <prefix>                         # controls output filename; default "coverage"
--coverlet-include "[Assembly]*"                        # repeat per assembly
--coverlet-exclude "[Assembly]*"                        # repeat per assembly
--coverlet-include-directory <path>                     # additional dirs to instrument
--coverlet-include-test-assembly
--coverlet-exclude-by-attribute "FullyQualifiedAttributeName"
--coverlet-exclude-by-file "glob"                       # exclude source files
--coverlet-exclude-assemblies-without-sources           # skip assemblies lacking source
--coverlet-does-not-return-attribute "FullyQualifiedAttributeName"
--coverlet-single-hit                                   # record at most one hit per location
--coverlet-skip-auto-props                              # skip auto-implemented properties
```

Without `--coverlet-output-format`, Coverlet emits JSON and Cobertura. Do not use
`--coverlet-output` or `--collect:"XPlat Code Coverage"`: they belong to the older
`coverlet.msbuild`/`coverlet.collector` (VSTest) drivers and are unavailable in
`coverlet.MTP`. Also absent: `--coverlet-threshold-*` (no threshold enforcement
in the MTP driver). Exclude files with `[ExcludeFromCodeCoverage]` or the test
project's `CoverletExcludedFiles` MSBuild property.
