---
name: reportgenerator
description: 'Generate and merge .NET code coverage reports with the ReportGenerator dotnet tool. Use for: code coverage report, coverage HTML report, merge cobertura xml, combine coverage results, reportgenerator, dotnet reportgenerator, coverage summary, risk hotspots, crap score, branch coverage, line coverage, per-class coverage, coverage artifacts. Do not use for: running tests (use dotnet-mtp-tests), building, or non-coverage tasks.'
---

# ReportGenerator — Coverage Reports & Merging

ReportGenerator is a repo-local dotnet tool declared in `dotnet-tools.json`
(command: `reportgenerator`, invoked as `dotnet reportgenerator`). It converts
Cobertura XML coverage files (produced by coverlet.MTP — see the `dotnet-mtp-tests`
skill) into HTML, Markdown, and other human-readable report formats, and can merge
multiple coverage runs into a single combined report.

## Prerequisites

```sh
dotnet tool restore   # installs reportgenerator from dotnet-tools.json
```

`reportgenerator` is **not** on PATH — always invoke it as `dotnet reportgenerator`.
Run `dotnet tool restore` once per clone/checkout before the first report.

## Output location convention

Per `AGENTS.md`: place all coverage output under `artifacts/` unless the user gives
an explicit path. Use `artifacts/` for both temporary artifacts (raw Cobertura XML,
intermediate files) and the final report output.

## Generate a single-run report

Input: one or more Cobertura XML files from a coverlet.MTP run. Glob with a leading
`*` so it matches any file-prefix and the trailing timestamp
(`coverage.cobertura.<timestamp>.xml`).

```sh
dotnet reportgenerator \
  "-reports:./artifacts/coverage/*.cobertura.*.xml" \
  "-targetdir:./artifacts/coverage/report" \
  "-assemblyfilters:+<TargetAssembly>" \
  -reporttypes:Html
```

Open `artifacts/coverage/report/index.html` for the HTML summary.

## Merge multiple coverage runs

ReportGenerator merges multiple Cobertura files into one combined report when you
pass multiple `-reports` globs (semicolon- or comma-separated, or repeated). This is
how you combine unit + integration coverage into a single union view.

```sh
dotnet reportgenerator \
  "-reports:./artifacts/coverage-combined/unit.cobertura.*.xml;./artifacts/coverage-combined/integration.cobertura.*.xml" \
  "-targetdir:./artifacts/coverage-combined/report" \
  "-assemblyfilters:+<TargetAssembly>" \
  -reporttypes:Html
```

The parser line in the generated `Summary.md` will read
`MultiReport (2x Cobertura)` when two files are merged.

## Report types

Pass one or more via `-reporttypes:` (comma-separated, no spaces). Common ones:

| Report type | Output | Use |
|---|---|---|
| `Html` | `index.html` + per-class pages | Default browsable report |
| `HtmlSummary` | single-page summary | Quick overview |
| `MarkdownSummary` | `Summary.md` | Text summary for chat/PR comments |
| `Cobertura` | merged Cobertura XML | Feed downstream tools |
| `Badges` | SVG badge files | CI status badges |
| `Xml` | raw XML summary | Machine-readable |
| `Latex` / `LatexSummary` | LaTeX tables | Documentation |

Combine for a full bundle:

```sh
-reporttypes:Html;MarkdownSummary;Cobertura;Badges
```

## Filters

- `-assemblyfilters:+<TargetAssembly>` — include only the named assembly (`+` = include,
  `-` = exclude). Repeat or comma-separate for multiple. Without filters, all
  referenced assemblies (including test assemblies and BCL) appear.
- `-classfilters:+<TargetAssembly>.*` — restrict to a class namespace glob.
- `-filefilters:` — restrict by source file path glob.

Always scope with `-assemblyfilters:+<TargetAssembly>` unless the user asks for
everything — unfiltered reports include test and framework code and are noisy.

## Key options

| Option | Purpose |
|---|---|
| `-reports:<glob>` | Input Cobertura XML(s); `;` or `,` separated, or repeated |
| `-targetdir:<dir>` | Output directory (created if missing) |
| `-reporttypes:<types>` | `Html`, `MarkdownSummary`, `Cobertura`, … |
| `-assemblyfilters:<f>` | `+Inc`/`-Exc` assembly filters |
| `-classfilters:<f>` | `+Inc`/`-Exc` class filters |
| `-filefilters:<f>` | `+Inc`/`-Exc` file filters |
| `-historydir:<dir>` | Persist coverage history for trend charts |
| `-tag:<label>` | Tag this run (shown in history) |
| `-plugins:<path>` | Custom plugin assemblies |
| `-verbosity:<level>` | `Error`, `Warning`, `Info`, `Verbose` |

Run `dotnet reportgenerator --help` for the authoritative option list.

## Reading the report

- **Line coverage** and **Branch coverage** are the headline metrics.
- **Risk Hotspots** table ranks methods by **Crap Score**
  (cyclomatic complexity × (1 − coverage)) — high crap = complex AND under-tested.
  These are the top targets for coverage work.
- Per-class HTML pages show line-by-line coverage with branch annotations.
- `MarkdownSummary` output (`Summary.md`) is the best format to paste into a chat
  summary or PR comment.

## Full workflow: collect coverage then report

This skill assumes the Cobertura XML already exists (produced via the
`dotnet-mtp-tests` skill). The end-to-end flow:

```sh
# 1. Run tests with coverage (see dotnet-mtp-tests skill for full options)
dotnet test tests/<Project>.UnitTests/<Project>.UnitTests.csproj \
  --results-directory ./artifacts/coverage \
  -- \
  --coverlet \
  --coverlet-output-format cobertura \
  --coverlet-include "[<TargetAssembly>]*"

# 2. Restore the tool (once per clone)
dotnet tool restore

# 3. Generate the HTML report
dotnet reportgenerator \
  "-reports:./artifacts/coverage/*.cobertura.*.xml" \
  "-targetdir:./artifacts/coverage/report" \
  "-assemblyfilters:+<TargetAssembly>" \
  -reporttypes:Html
```

For a combined unit + integration report, run both test suites into the same
`--results-directory` (or separate dated folders), then merge with two `-reports`
globs as shown above.

## Presenting results to the user

When presenting a coverage report to the user, use these sections as a guide for
the summary message (do not write a `REPORT.md` file unless explicitly asked):

1. **Date, target assembly, tooling** (xUnit v3 / MTP, coverlet.MTP, ReportGenerator).
2. **Test results table** — per suite: project, result, total/passed/failed/skipped, duration.
3. **Combined coverage table** — line and branch coverage %, covered/coverable counts, class/file counts.
4. **Per-suite contribution** — each suite measured against the full assembly (overlapping, not additive); lines covered by both, unit-only, integration-only, neither.
5. **Areas needing attention** — worst-covered classes (< 60% line), sorted ascending.
6. **Risk hotspots** — top crap-score methods with cyclomatic complexity, from the ReportGenerator `Summary.md` Risk Hotspots table.
7. **Artifacts** — list the output directory and key files (`report/index.html`, `summary/Summary.md`).

Compute per-suite contribution by parsing each raw Cobertura XML individually with
ReportGenerator (or by reading the `<line>` hits) — do not rely on the merged
number for per-suite breakdowns.
