# ReliabilityIQ

ReliabilityIQ is a repository risk-scanning toolkit that identifies portability and maintainability issues before cross-cloud deployment.

It combines static analysis, repository analytics, and incident correlation to surface high-signal findings in a single scan pipeline.

## Purpose

ReliabilityIQ targets codebases that move across cloud platforms (initial focus: Microsoft EV2 and Azure DevOps ecosystems), across languages and artifacts, and highlights blockers that make cloud portability or reliable operations harder.

Primary focus areas:

- Cross-cloud portability blockers (hardcoded endpoints, IPs, paths, region/resource identifiers, etc.).
- Magic-string opportunity detection (high-signal ranking, not just raw pattern matching).
- Git churn vs. staleness hotspots with noise suppression for generated/readme/IDE artifacts.
- Incident-to-module/service association for operational risk concentration.
- Configurable/rule-driven scanning with optional plugin extension points.
- Web/table + heatmap visualization from persisted scan results.

## Non-Goals (initial)

- Auto-fixing code.
- Full behavioral/runtime analysis (profiling, tracing).
- Zero-false-positive detection.
- Universal build-system and platform coverage in the first release.

## High-Level Design

ReliabilityIQ is planned as a multi-component .NET solution:

- `ReliabilityIQ.Cli`: orchestrates scans, runs analyzers, writes results, and emits report summaries.
- `ReliabilityIQ.Core`: rule engine, finding model, classification, scoring, persistence abstraction.
- `ReliabilityIQ.Analyzers.*`: language + artifact + history/anomaly analyzers.
- `ReliabilityIQ.Web`: ASP.NET web UI over the same SQLite result store.

The scan pipeline:

1. Load config
2. Discover repository and classify files (source, config, docs, generated, vendor, IDE, etc.)
3. Run analyzers
4. Normalize + score findings with suppressions and allowlists
5. Persist findings/results into SQLite
6. Emit CLI summary and support web/dashboard consumption

## Planned Technology Choices

- CLI: `System.CommandLine`
- Source parsing: Roslyn (C#), Tree-sitter via P/Invoke (C++/Python/PowerShell/Rust), plus JSON/YAML parsers where needed
- Git mining: `LibGit2Sharp`
- Persistence: `Microsoft.Data.Sqlite` + `Dapper`
- Web UI stack: ASP.NET, D3.js, Chart.js, DataTables (CDN-first bootstrap approach)
- Rule/config format: YAML with schema validation

## Repository scanning output

- Filterable findings list
- Repo/module/file heatmap for hotspot analysis
- Configurable severity/priority and ranking
- Incident and changelog context for each relevant finding

## Rule & configuration model

Planned rule/config structure:

- `.reliabilityiq/config.yaml`
- `.reliabilityiq/rules/{portability, magic-strings, churn, incidents, deploy-ev2, deploy-ado}.yaml`
- `.reliabilityiq/rules/custom/*.yaml`
- `.reliabilityiq/allowlists/*.yaml`

Precedence model:

1. Built-in defaults
2. Repo rules
3. Custom overrides
4. CLI flags (highest priority)

Also planned:

- Rule validation command (`reliabilityiq rules validate`)
- Inline and file-level suppressions for noise reduction
- Strong defaults for generated/vendor/IDE ignores with opt-in overrides

## Current state note

This repository’s README is now aligned to the design intent in `Docs/designdoc.md`; implementation status may vary by branch and milestone.

## CLI Reference (Current Implementation)

The CLI is a System.CommandLine app under `ReliabilityIQ.Cli`.

### Usage

- `dotnet run --project ReliabilityIQ.Cli -- <command> [options]`
- If you have a built binary, use the executable in place of `dotnet run`.

### Commands and arguments

#### `scan portability`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)
- `--suppressions`: suppression file path (default: `<repo-root>/reliabilityiq.suppressions.yaml`)
- `--fail-on`: fail command with exit code 1 when findings at or above severity are present (`error|warning|info`)

#### `scan magic-strings`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)
- `--min-occurrences`: minimum candidate occurrence count
- `--top`: max number of ranked candidates to persist
- `--config`: optional magic strings config (default: `<repo-root>/reliabilityiq.magicstrings.yaml`)

#### `scan churn`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)
- `--since`: Git lookback window (for example `90d`, `180d`, `365d`)
- `--service-map`: service boundary mapping file (format: `ServiceName=glob`)

#### `scan deploy`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)
- `--ev2-path-markers`: semicolon-delimited EV2 markers override
- `--ado-path-markers`: semicolon-delimited ADO markers override

#### `scan config-drift`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)

#### `scan deps`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)

#### `scan hygiene`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)

#### `scan all`
- `--repo` (required): repository path to scan
- `--db`: SQLite file path (default: `<repo-root>/reliabilityiq-results.db`)
- `--fail-on`: fail on `error|warning|info` for portability findings
- `--suppressions`: suppression file path (default: `<repo-root>/reliabilityiq.suppressions.yaml`)
- `--min-occurrences`: minimum magic-string candidate occurrences
- `--top`: max ranked magic-string candidates to persist
- `--config`: optional magic strings config (default: `<repo-root>/reliabilityiq.magicstrings.yaml`)
- `--since`: churn lookback window (for example `90d`, `180d`, `365d`)
- `--service-map`: service boundary mapping file (format: `ServiceName=glob`)
- `--ev2-path-markers`: semicolon-delimited EV2 markers override
- `--ado-path-markers`: semicolon-delimited ADO markers override

#### `rules validate`
- `--config`: optional path to repo root or `.reliabilityiq` directory

#### `rules list`
- `--config`: optional path to repo root or `.reliabilityiq` directory
- `--enabled-only`: show only enabled rules
- `--category`: filter by category (`portability`, `magic-strings`, `churn`, `deploy-ev2`, `deploy-ado`, `config-drift`, `dependencies`, `incidents`, `custom`)

#### `rules init`
- `--repo`: initialize rule/config templates in repo root (default: current directory)

#### `init`
- `--repo`: initialize ReliabilityIQ configuration/templates (default: current directory)

#### `server start`
- `--db` (required): SQLite database file path
- `--port`: Kestrel HTTP port (default: `5100`)
- `--no-browser`: do not auto-open browser

### Example commands

```bash
# run portability scan on current repo
dotnet run --project ReliabilityIQ.Cli -- scan portability --repo . --db ./reliabilityiq-results.db

# run all scans with custom churn lookback and fail-on threshold
dotnet run --project ReliabilityIQ.Cli -- scan all \
  --repo . \
  --since 180d \
  --fail-on warning \
  --top 250 \
  --db ./reliabilityiq-results.db

# run only magic strings scan and persist top 100 candidates
dotnet run --project ReliabilityIQ.Cli -- scan magic-strings --repo . --top 100 --min-occurrences 3

# validate config in a repo
dotnet run --project ReliabilityIQ.Cli -- rules validate --config .

# start web server against a scan database
dotnet run --project ReliabilityIQ.Cli -- server start --db ./reliabilityiq-results.db --port 5200

# initialize .reliabilityiq templates
dotnet run --project ReliabilityIQ.Cli -- init --repo .
```
