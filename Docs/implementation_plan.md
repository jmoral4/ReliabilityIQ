## Roadmap structure (Agent handoff contract)

Each **Phase i** is delivered in two back-to-back drops:

- **Agent 1 (Scanner drop)**: adds/changes CLI + analyzers + SQLite schema/migrations + tests, and produces a **sample DB** artifact (or a deterministic fixture scan) for UI development.
- **Agent 2 (Web drop)**: updates ASP.NET UI to read the new schema/data and exposes the new views (tables/heatmaps/drilldowns).

**Hard rule for coherence:** every Agent 1 drop must include:
1) a forward-only **SQLite migration** (plus `PRAGMA user_version` or `schema_version` table update),
2) an updated `docs/db-schema.md` (or equivalent),
3) at least one **golden fixture repo** + an integration test that produces the expected rows.

---

## Phase overview (N = 16)

| Phase | Agent 1 delivers (Scanner) | Agent 2 delivers (Web UI) |
|---:|---|---|
| 1 | MVP inventory scan → SQLite | Runs + Files pages |
| 2 | Portability v1 (regex/text) findings | Findings table + basic filters |
| 3 | Portability v2 (AST/context) + better severities | Finding drilldown (snippet + remediation) |
| 4 | YAML config + rule system + suppressions (MVP) | Rules + Config visibility per run |
| 5 | Magic Strings v1 (ranked + aggregated) | Magic Strings ranked view + occurrences |
| 6 | Git churn/staleness metrics (LibGit2Sharp) | Churn/Staleness dashboards + directory rollups |
| 7 | Risk scoring + Heatmap v1 (directory tree) | Heatmap (tree) with metric selector |
| 8 | Heatmap v2 (treemap) + performance cache (content analyzers) | Treemap view + “top risk” reports |
| 9 | Incidents v1 (file import + commit regex linker) | Incident density views + file/module linking |
| 10 | Incidents v2 (providers/adapters + service→path mapping) | Incident vs churn correlation reports |
| 11 | EV2 artifact scanner | EV2 artifact findings + parse error UX |
| 12 | ADO pipeline scanner | ADO findings + policy-style checks UX |
| 13 | Secrets / credential hygiene scanner | Secrets dashboard (masked) + SARIF export |
| 14 | Dependency & supply-chain risk scanner (OSV/EOL) | Dependency risk UI (packages → advisories) |
| 15 | Config drift scanner (env diffs) | Config drift diff/summary UI |
| 16 | “Ops & Quality pack” (observability/ownership/build/test) | Ops readiness dashboard + ownership overlays |

---

# Phase-by-phase deliverables (Agent 1 then Agent 2)

## Phase 1 — MVP: “Inventory into SQLite” + minimal viewer
### Agent 1 (Scanner)
**Goal:** the easiest scanner that proves the pipeline end-to-end.

- CLI:
  - `reliabilityiq scan inventory --repo <path> --db <file>`
  - (Optional) `reliabilityiq init` creates `.reliabilityiq/config.yaml` with default excludes.
- Implement:
  - Repo discovery (root + `.git` detection)
  - File enumeration + default classification (Source/Config/Docs/Generated/Vendor/IDE) using hardcoded defaults for now
- SQLite:
  - Create tables: `scan_runs`, `files` (minimum viable subset)
  - Store per-run file inventory: path, category, size, hash (fast hash ok), language
- Output:
  - CLI prints counts by category + top N largest files

**Acceptance checks**
- Scanning a medium repo produces a DB with 1 run row + N files rows.
- Re-running produces a second run row (no overwrite).

### Agent 2 (Web)
**Goal:** prove read-only web app can open DB and show data.

- Pages:
  - **Runs**: list `scan_runs`
  - **Files**: filter by run + category + path prefix
- Data access:
  - Read-only connection string (and/or “copy DB to UI workspace” toggle)

**Acceptance checks**
- Point UI at a DB path → pages load and show correct counts.

---

## Phase 2 — Portability v1 (fast regex/text scan)
### Agent 1 (Scanner)
**Goal:** first real findings with minimal parsing complexity.

- Add tables:
  - `rules` (seed built-in portability rules)
  - `findings` (core columns + `metadata` JSON)
  - Key indices from the doc (at least `findings(run_id, rule_id, severity)`, `findings(file_id)`)
- Analyzer: **Portability.Regex**
  - Detect: hardcoded DNS, IPv4, Windows paths, Linux absolute paths, Azure resource IDs, GUID-like subscription/tenant IDs, region names, `localhost` binding, basic connection string markers
  - Scope: scan only categories `Source`, `Config`, `DeploymentArtifact` (even if DeploymentArtifact is crude initially)
  - Include remediation guidance in finding `metadata` (or `message` + `metadata.recommendation`)
- CLI:
  - `reliabilityiq scan portability ...`
  - `reliabilityiq scan all` runs inventory + portability

**Acceptance checks**
- Fixture repo with known patterns yields deterministic findings with correct `rule_id`s.

### Agent 2 (Web)
- Page: **Findings**
  - DataTables grid: severity, rule, file path, line, message
  - Filters: run, severity, rule, category, path prefix
- Simple “finding details” modal (message + snippet if present)

**Acceptance checks**
- Can filter to a rule and see correct rows quickly (indexes working).

---

## Phase 3 — Portability v2 (AST + context + noise reduction)
### Agent 1 (Scanner)
**Goal:** reduce false positives, add callsite context.

- Add analyzers:
  - **C# Roslyn** string literal extraction + callsite checks (Uri/HttpClient/Dns/Socket/File IO/ProcessStartInfo etc.)
  - **Python AST** (built-in `ast`) for calls like requests/socket/subprocess/open/pathlib
  - **PowerShell AST** for Invoke-WebRequest/Invoke-RestMethod/etc.
- Add heuristics:
  - Proximity suppression/downgrade if config/env read nearby
  - Semantic suppression in C# when derived from `IConfiguration` / `Environment.GetEnvironmentVariable`
  - Test project downgrade to Info
- Add `snippetMode` config (none|line|context) to control snippet storage.

**Acceptance checks**
- Side-by-side on a fixture: AST version produces fewer higher-confidence findings than regex-only.

### Agent 2 (Web)
- “Finding drilldown” page:
  - Snippet rendering (respect snippetMode)
  - Show `metadata` fields (callsite, recommendation, confidence reasons)
  - Link to “all findings in this file”

---

## Phase 4 — Configurable rules + suppressions (MVP)
### Agent 1 (Scanner)
**Goal:** make the scanner controllable without recompiling.

- YAML config loader with precedence (built-in → repo rules → custom overrides → CLI flags)
- JSON-schema validation + `reliabilityiq rules validate`
- Implement suppressions:
  - Central suppression file `reliabilityiq.suppressions.yaml` (path + rule + optional string hash)
  - Inline suppressions for C# initially (`// reliabilityiq: ignore <rule_id> reason=...`)
- Add run-level `config_hash` recorded in `scan_runs`

**Acceptance checks**
- A suppressed finding no longer appears (or appears as suppressed if you choose to store it separately).

### Agent 2 (Web)
- Show per-run config hash + “ruleset version”
- **Rules page**: list rules + descriptions + default severity
- Optional: show “suppressed count” per rule (if stored)

---

## Phase 5 — Magic Strings v1 (ranked opportunities)
### Agent 1 (Scanner)
**Goal:** ranked list, not a flood of violations.

- New tables (recommended to support aggregation cleanly):
  - `string_candidates` (run_id, normalized_value_hash, display_value, score, occurrences_count, top_locations JSON)
  - `string_occurrences` (candidate_id, file_id, line, column, context_type)
- Implement extraction (start with C# Roslyn; optionally add Python quickly):
  - Filter: logging sinks, natural-language heuristics, too-short, tests negative weight
  - Score: frequency + comparisons/switch/dict keys positive signals
  - Exclude/redirect: endpoint/path-like strings should remain portability findings
- CLI: `reliabilityiq scan magic-strings`

**Acceptance checks**
- Candidate aggregation works: 1 candidate row per normalized string, N occurrence rows.

### Agent 2 (Web)
- **Magic Strings page**
  - Ranked candidates table (score, occurrences, top files)
  - Expand to show occurrences; click-through to file context

---

## Phase 6 — Git churn/staleness metrics
### Agent 1 (Scanner)
**Goal:** git-based risk signals with strong noise reduction.

- Implement `LibGit2Sharp` metrics:
  - last_commit_at, commits_90d/365d, authors_365d
  - ownership concentration (Gini)
  - churn_score formula + stale_score
- Store in `git_file_metrics` and roll up per directory (either computed on read or store `git_dir_metrics`)
- Respect file classification + `staleIgnore` defaults + `.gitignore` (configurable)

### Agent 2 (Web)
- **Churn/Staleness pages**
  - Sortable tables: hottest files, stalest files, highest ownership concentration
  - Directory rollups (top 10 risky directories by churn/stale)

---

## Phase 7 — Risk scoring + Heatmap v1 (directory tree)
### Agent 1 (Scanner)
- Implement composite scoring (doc formula as default, configurable weights)
- Store per-file computed `risk_score` (either in a new table or in `files` as denormalized per-run metrics table like `file_run_metrics`)
- Provide directory aggregation logic for heatmap

### Agent 2 (Web)
- **Heatmap (Tree)**
  - D3 collapsible tree colored by selected metric (risk, churn, staleness, portability count)
  - Click directory → list top files + top findings

---

## Phase 8 — Heatmap v2 (Treemap) + incremental scanning cache (content analyzers)
### Agent 1 (Scanner)
- Add incremental scan cache table:
  - `analysis_cache` (file hash + analyzer version + config hash → skip decision)
- Add treemap-ready dataset endpoint expectation:
  - Directory/file weights: LOC (optional) or file size
- CLI: `--since 180d` for git windows, and “skip unchanged” for content analyzers

### Agent 2 (Web)
- **Treemap view** (WinDirStat-like)
- “Top risk reports” page: top directories/files by chosen metric

---

## Phase 9 — Incidents v1 (import + commit regex linking)
### Agent 1 (Scanner)
- Implement `IIncidentProvider` + a simple **FileIncidentProvider** (CSV/JSON import)
- Implement `IIncidentLinker`:
  - regex in commit messages for ICM/AB#/GH- patterns
  - link incident → commits → touched files
- Store `incidents` + `incident_links`

### Agent 2 (Web)
- **Incidents page**
  - Incident list + linked files/modules
  - “Incident density by directory” table
  - File detail shows linked incidents

---

## Phase 10 — Incidents v2 (adapters + service→path mapping + correlation)
### Agent 1 (Scanner)
- Add optional providers (behind config):
  - GitHub provider (issues/PR links) and/or ADO provider
- Add service-to-path mapping support: `service Foo => /src/Foo/**`
- Compute correlation-friendly rollups (incident severity weight per module/directory)

### Agent 2 (Web)
- **Correlation report**
  - Incident density vs churn scatterplot (Chart.js)
  - Drilldown: click a point → show top findings + recent churn

---

## Phase 11 — EV2 artifact scanning
### Agent 1 (Scanner)
- Add DeploymentArtifact classification improvements (EV2 patterns)
- YAML/JSON structure-aware parsing + fallback “parse error” findings
- Rules: region pinning, hardcoded subscription/tenant/endpoints, missing health checks, PT0S waits, inline secrets references (non-secret values)

### Agent 2 (Web)
- EV2-focused filters/presets
- Parse errors shown as a first-class category with file + error detail

---

## Phase 12 — ADO pipeline scanning
### Agent 1 (Scanner)
- Pipeline detection + YAML parsing
- Rules: hardcoded pools, service connection names, Windows-only paths, `latest` tags, missing approvals (as policy checks if configured)

### Agent 2 (Web)
- ADO “policy checks” view:
  - group findings by pipeline and stage/job (from metadata)

---

## Phase 13 — Secrets / credential hygiene
### Agent 1 (Scanner)
- Implement secret detectors:
  - regex for common key formats + connection strings + SAS-like patterns
  - entropy heuristic (store *fingerprint*, do not store raw secret)
- Add SARIF export for this scanner (and optionally all findings)
- Ensure `snippetMode` defaults to safer behavior for secrets (masking)

### Agent 2 (Web)
- Secrets dashboard:
  - always masked values
  - show type, location, confidence, remediation
- “Export” UI affordance (download SARIF/JSON generated by CLI or served from a folder)

---

## Phase 14 — Dependency & supply-chain risk
### Agent 1 (Scanner)
- Parse dependency manifests/lockfiles:
  - NuGet (`packages.lock.json` / assets), pip (`requirements.txt`/lock), cargo (`Cargo.lock`)
- Optional online enrichment (config-gated): OSV/GitHub Advisory queries
- EOL framework detection (e.g., deprecated runtimes/SDK versions)
- Store:
  - `dependencies` table + `dependency_findings` (or reuse `findings` with strong metadata)

### Agent 2 (Web)
- Dependency page:
  - package → version → advisories/EOL flags
  - filter by severity and ecosystem

---

## Phase 15 — Configuration drift scanner
### Agent 1 (Scanner)
- Detect env-specific config sets (by naming conventions + config rules)
- Compare key sets across envs; flag missing keys / diverging types
- Store drift results (pairwise comparisons and summary)

### Agent 2 (Web)
- Config drift UI:
  - summary table (env A vs env B missing keys)
  - drilldown diff view (key list; no raw secret exposure)

---

## Phase 16 — Ops & Quality pack (finish remaining doc + Tier2/Tier3 add-ons)
### Agent 1 (Scanner)
Bundle remaining “product-fit” analyzers so the roadmap completes “every feature” without exploding into tiny phases:

1) **Ownership / CODEOWNERS coverage**
- parse CODEOWNERS; map files→owners; flag missing/stale ownership
- combine with git ownership concentration + “inactive owner” heuristic

2) **Observability readiness**
- heuristics for missing correlation IDs / swallowed telemetry / “dark paths” (configurable)

3) **Resilience & async/thread anti-patterns**
- missing timeouts/retry policy heuristics in known callsites
- C# `.Result`/`.Wait()` in async contexts, etc.

4) **Tech debt signals**
- TODO/FIXME counts, optional cyclomatic complexity (start C#)

5) **Build reproducibility + test health (MVP)**
- detect non-pinned toolchains in pipelines; floating tags
- (test health) start with repo-local signals (flaky markers, quarantined tests) if CI logs aren’t integrated yet

### Agent 2 (Web)
- **Ops readiness dashboard**
  - tabs: Ownership, Observability, Resilience/Async, Tech Debt, Build/Test
  - ability to overlay these metrics onto heatmap coloring/filters

---

## Practical workflow notes (to keep phases “AI-agent friendly”)

- **Schema changes:** always additive-first; if a breaking change is needed, add new tables/columns and keep old reads working for at least 1 phase.
- **Fixture-first development:** every new analyzer ships with a tiny fixture repo folder in `/fixtures/...` and a test that asserts row counts + sample rule IDs.
- **UI performance:** Agent 2 should assume DB can be large; always implement server-side paging or indexed queries (even if DataTables is used).
- **Locking strategy:** by Phase 2–3, standardize “scanner writes to DB; web reads a copied snapshot” to avoid read/write contention.
