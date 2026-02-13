# ReliabilityIQ — Design Document (v0.1)

## 1. Purpose & Goals

ReliabilityIQ scans a source code repository (and its Git history / incident metadata) to surface **maintainability and portability risks** that can block or complicate **cross-cloud deployments**, with an initial focus on:

- Languages: **C#**, **C++**, **Python**, **PowerShell**, **Rust** (prioritize compiled + code-behind patterns).
- Deployment ecosystems: **Microsoft internal EV2** and **Azure DevOps (ADO)** artifacts.
- Output: a **CLI** scanner (C#), results stored in **SQLite**, and an **ASP.NET** web UI that can present:
  - Filterable findings table
  - Repo heatmap (directory/file intensity)

### Primary Scans (requested)
1. **Cross-cloud portability blockers**
   - Hardcoded DNS names, IPs, file paths, cloud endpoints, region names, subscription/tenant IDs, etc.
2. **Magic strings**
   - Identify likely “should-be-constants/config” string literals while minimizing false positives.
3. **Commit history “churn vs. staleness”**
   - Highlight frequently modified areas and areas that are stale **without** surfacing noise (README, generated output, IDE artifacts).
4. **Incident association mapping**
   - Map modules/services to incidents (ICM and/or GitHub) to understand operational risk concentration.
5. **Rule configurability**
   - Add/remove/adjust scanner rules via config files (and optionally plugin assemblies).
6. **Visualization**
   - Table + heatmap of the codebase.


### Technology Choices
.NET 10 using latest coding techniques in C#

| Area | Recommendation |
|---|---|
| CLI framework | `System.CommandLine` |
| Non-.NET parsing | **Tree-sitter** via P/Invoke |
| Git history | `LibGit2Sharp` |
| SQLite access | `Microsoft.Data.Sqlite` + Dapper |
| Web frontend | ASP.NET + D3.js + Chart.js + DataTables.js, no Node build step. Embed js/css via CDN to start. |
| Config format | YAML with **JSON-schema validation** |



---

## 2. Non-Goals (initially)

- Automatic code fixes (autofix) beyond offering suggestions/snippets.
- Deep runtime behavior analysis (profiling, dynamic tracing).
- Perfect precision on magic strings (goal is *high-signal ranking*, not “no false positives ever”).
- Full support for every build system; instead, cover common repo patterns + EV2/ADO first.

---

## 3. High-Level Architecture

### 3.1 Components
- **ReliabilityIQ.Cli** (C#)
  - Orchestrates scans, loads configuration, runs analyzers, stores results in SQLite, prints summary, exports reports.
- **ReliabilityIQ.Core**
  - Scanner framework, rule engine, finding model, file classification, scoring, SQLite persistence.
- **ReliabilityIQ.Analyzers.\*** (built-in analyzers)
  - Language analyzers (C#, C++, Python, PowerShell, Rust)
  - Artifact analyzers (EV2/ADO configs)
  - Git history analyzer
  - Incident correlation analyzer
- **ReliabilityIQ.Web** (ASP.NET)
  - Reads SQLite, serves UI: run list, findings table, heatmap, drilldowns.

### 3.2 Scanner Pipeline Architecture
- **Three parse pipelines** (Roslyn for .cs, Tree-sitter for .cpp/.py/.ps1/.rs, JSON/YAML for config/EV2/ADO) feeding into a unified Rule Evaluator.
- **Channel-based parallelism**: `Channel<FileWork>` for fan-out, `Channel<FindingBatch>` for serialized SQLite writes. Per-worker tree-sitter instances (since parsers aren't thread-safe). Roslyn `AdhocWorkspace` per file (no full solution load).
- **Bulk insert** (per 1,000 rows) to SQLite for performance.

#### 3.2.1 Pipeline (per scan run)
1. **Load config**
2. **Discover repository**
   - Root, `.git`, solution/workspace hints, exclude patterns
3. **Classify files**
   - Source vs config vs generated vs vendor vs docs vs build output
4. **Run analyzers**
   - Content analyzers (AST / token / regex)
   - Git churn/staleness
   - Incident linking
5. **Normalize & score**
   - Deduplicate, suppress via allowlists, apply severity/risk scoring
6. **Persist to SQLite**
7. **Produce outputs**
   - CLI summary + optional HTML/JSON export
   - Web UI reads the same SQLite



---

## 4. Key Design Principles

- **Multi-signal findings**: prefer findings backed by *context* (AST usage, callsite type, file classification), not just regex.
- **Minimize noise by default**:
  - Strong ignore defaults for generated/3rd-party/IDE output
  - Ranking + thresholds for “magic strings”
  - Explicit suppressions/allowlists
- **Extensible rules**:
  - Declarative rules via config
  - Optional plugin analyzers for complex org-specific logic
- **Incremental scanning**:
  - Cache file hashes + analyzer versions per run to avoid re-scanning unchanged files.

---

## 5. Repository Discovery & File Classification

### 5.1 File categories
- `Source`: `.cs`, `.cpp`, `.h`, `.hpp`, `.py`, `.ps1`, `.rs`, etc.
- `DeploymentArtifact`: EV2 artifacts, ADO pipelines, Helm/K8s, etc. (configurable)
- `Config`: `.json`, `.yaml`, `.yml`, `.ini`, `.config`, `.toml`
- `Docs`: `.md`, `.rst`
- `Generated`: `obj/`, `bin/`, `target/`, `out/`, `dist/`, `__pycache__`, etc.
- `Vendor`: `third_party/`, `node_modules/`, `packages/`, etc.
- `IDE`: `.vs/`, `.vscode/`, `.idea/`

### 5.2 Default excludes (configurable)
- Common build outputs + IDE artifacts
- Any dot-directory by default (e.g., `.venv/`, `.cache/`, `.github/`, `.terraform/`), except scanner internals that read `.git` metadata explicitly
- Lock files and minified bundles (optional)
- Large binaries by default (skip by size threshold)
- `.gitignore` patterns are treated as implicit excludes by default (`repo.useGitIgnore: true`), with config to disable.

This classification is used by every analyzer to avoid useless “stale files” and reduce false positives.

---

## 6. Scanner Framework & Rule System

### 6.1 Analyzer types
- **Regex/Pattern Analyzer**
  - Fast scans on text/config files (paths, IPs, DNS, region strings)
- **AST Analyzer**
  - C#: Roslyn
  - PowerShell: PowerShell AST
  - Rust: tree-sitter (or rust-analyzer integration later)
  - C++: tree-sitter initially, with optional clang tooling later for deeper semantics
  - Python: built-in `ast` parsing
- **Repository Analytics Analyzer**
  - Git log mining for churn/staleness/hotspots
- **Incident Correlation Analyzer**
  - Join incidents ↔ commits ↔ files ↔ modules
- **Artifact Analyzer**
  - EV2/ADO structure-aware parsing

### 6.2 Rule configuration layout, precedence, and validation
Use a split-file layout so teams can keep scanner rules modular and override cleanly:

- `.reliabilityiq/config.yaml`
- `.reliabilityiq/rules/portability.yaml`
- `.reliabilityiq/rules/magic-strings.yaml`
- `.reliabilityiq/rules/churn.yaml`
- `.reliabilityiq/rules/incidents.yaml`
- `.reliabilityiq/rules/deploy-ev2.yaml`
- `.reliabilityiq/rules/deploy-ado.yaml`
- `.reliabilityiq/rules/custom/*.yaml`
- `.reliabilityiq/allowlists/*.yaml`

Merge precedence:
- Built-in defaults
- Repo rules (`.reliabilityiq/rules/*.yaml`)
- Custom override files (`.reliabilityiq/rules/custom/*.yaml`)
- CLI flags (highest precedence)

Validation:
- `reliabilityiq rules validate` checks schema, rule IDs, duplicate definitions, bad glob patterns, and precedence conflicts.

### 6.3 Suppressions
- Inline suppressions for AST-capable languages (e.g., C# comment pragma-like marker):
  - `// reliabilityiq: ignore portability.hardcoded.dns reason=...`
- Central suppression file:
  - `reliabilityiq.suppressions.yaml` supports file/path + rule id + optional string hash.

---

## 7. Scan 1 — Cross-Cloud Portability Blockers

### 7.1 What to detect
**Hardcoded**:
- DNS names (public/private), especially cloud-specific endpoints
- IP addresses (IPv4, optionally IPv6)
- File paths:
  - Windows drive/UNC paths
  - Linux absolute paths (`/var/...`, `/etc/...`) when inappropriate
- Cloud-specific resource identifiers:
  - Subscription/tenant GUIDs
  - Azure resource IDs, region names
  - Cloud endpoints (management endpoints, metadata endpoints)
- “Environment coupling”:
  - references to machine names
  - registry keys (Windows) if relevant
  - fixed ports (context-dependent)

### 7.2 Reduce false positives using context
**Prefer AST-based extraction** of string literals *and how they’re used*:
- C# (Roslyn):
  - Flag string literals passed into `Uri`, `HttpClient`, `Dns`, `Socket`, `WebRequest`, `ProcessStartInfo`, file IO APIs.
  - Flag literals in attribute arguments for deployment/config.
- Python:
  - Flag literals passed to `requests.*`, `socket.*`, `subprocess`, `open()`, `pathlib.Path(...)`.
- PowerShell:
  - Flag `Invoke-WebRequest`, `Invoke-RestMethod`, `New-Object System.Uri`, `Set-Content`, `Out-File`, etc.
- C++:
  - Start with regex + known callsites (`connect`, `getaddrinfo`, `curl_easy_setopt`, file APIs), then improve via clang AST later.
- Rust:
  - Identify `reqwest::`, `std::net::`, `std::fs::`, `Command::new`, and `include_str!` patterns.

### 7.3 “Portability guidance” in findings
Each finding should include **recommended remediation**:
- Replace hardcoded endpoint with configuration/secret store reference
- Use environment variables, config providers, or deployment-time parameterization
- Use cloud-agnostic abstractions (where applicable)

| Addition | Why |
|---|---|
| **Hardcoded connection strings** (`Server=`, `Data Source=`, `AccountKey=`) | A major portability blocker the original misses entirely |
| **Hardcoded non-standard ports** in known connect/listen call sites | Context-dependent but valuable when scoped to API call sites |
| **Cloud-specific SDK calls without abstraction layer** (e.g., direct `BlobServiceClient` usage without interface indirection) | Goes beyond string detection into structural coupling — a higher-value finding |
| **Hardcoded registry keys** (`HKEY_LOCAL_MACHINE\...`) | Explicitly called out with regex pattern; original only mentions "registry keys (Windows) if relevant" vaguely |
| **Proximity suppression** (if the same file reads from config/env within ±5 lines, downgrade severity) | Clever false-positive reduction not in the original |
| **Semantic suppression for C#**: if a string is assigned from `IConfiguration` or `Environment.GetEnvironmentVariable`, suppress | Reduces false positives significantly in well-structured code |
| **Test project severity downgrade** (findings in `*.Tests.csproj` or `/tests/` → `Info` not `Warning`) | More nuanced than the original's binary allowlist approach |
| **Per-language parse strategy table** using Tree-sitter node types | Actionable implementation guidance the original lacks |
| **`localhost` binding detection** — flag `localhost` that should be `0.0.0.0` for container/cloud portability | Specific, actionable pattern the original and Agent 3 both miss |
---

## 8. Scan 2 — Magic Strings (High-Signal Ranking)

### 8.1 Problem definition
“Magic strings” are string literals that function like constants/config/identifiers and should likely be:
- centralized as constants/enums
- moved to config
- or replaced with typed identifiers

But naive scanning produces massive noise (logging messages, UI text, error messages).

### 8.2 Proposed approach: extraction + scoring + ranking
1. **Extract string literals** with context:
   - file, line/column, literal text, AST parent node type, callsite symbol (where possible)
2. **Normalize**:
   - trim, case normalization (optional), collapse whitespace
3. **Filter obvious non-signal**:
   - Strings used only in logging/telemetry calls (configurable list of sinks)
   - Natural language heuristics (spaces + punctuation + stopwords)
   - Very short strings (`"a"`, `"ok"`)
   - Known safe patterns (GUID format, dates) unless requested
4. **Score candidates** using a layered stack (`exclude -> detect -> score -> threshold`) with example signals:
   - **Frequency** across repo (strong positive)
   - **Used in comparisons/switch** (`==`, `switch`, dictionary key lookups) (strong positive)
   - **Used as protocol/endpoint/path** (belongs in portability scan instead)
   - **Used as exception message** (negative)
   - **Used in tests/samples only** (negative)
5. **Aggregate & output**:
   - One candidate per unique normalized literal
   - Include occurrence count, top locations, and expandable “show all occurrences” detail
   - Not “violations” by default; output as *ranked opportunities*
   - Provide “top N per module” and “top N overall”

Additional:
**Shannon entropy analysis** for string literals. We position this for secret detection (high entropy = potential API key), but it's also useful as a *negative* signal for magic strings — very high entropy strings are likely secrets or hashes, not semantic constants. This should be added as an additional Layer 1 exclusion filter (or redirected to a secrets scanner). The original doc doesn't mention entropy at all.

### 8.3 Tuning knobs
- `minOccurrences`
- allowlist/denylist patterns
- per-language logging sink list
- max findings per directory/module (avoid floods)
- keep high-entropy detection in the separate Secrets/Credential Hygiene scanner, not in Magic Strings

---

## 9. Scan 3 — Git Commit History: Churn vs Staleness

### 9.1 Objectives
- Identify **hotspots**: frequently modified modules/files (risk of instability or complexity)
- Identify **stale areas**: not modified in a long time (risk of drift/rot/ownership gaps)
- Avoid useless “stale” results (docs, generated artifacts, IDE files)

### 9.2 Metrics (per file and aggregated per directory/module)
- `last_commit_date`
- `commits_last_30/90/180/365_days`
- `unique_authors_last_365_days` (bus factor proxy)
- `ownership_concentration` (e.g., Gini coefficient on contribution distribution)
- `lines_added/removed` (optional, slower)
- `churn_score` (weighted)
- `stale_score` (time-decay)

| Addition | Recommendation |
|---|---|
| **Ownership Concentration via Gini coefficient** (`1.0 = single owner`) | **Supersede** the original's `unique_authors_last_365_days`. The Gini coefficient is strictly more informative — it captures *concentration*, not just count. A file with 10 authors where one did 95% of commits looks fine by author count but terrible by Gini. |
| **Explicit churn score formula**: `TotalCommits × log(LinesAdded + LinesDeleted + 1)` | **Add** to the original. The original mentions `churn_score (weighted)` without defining the formula. Agent 3's formula reasonably balances frequency and magnitude. |
| **Comprehensive staleness exclude patterns** (`.designer.cs`, `.g.cs`, `.generated.*`, `packages.lock.json`, `yarn.lock`, `RolloutSpec.generated.json`) | **Merge** into the original's `staleIgnore` defaults. list is more thorough. |

### 9.3 Noise reduction
- Apply **file classification** + `staleIgnore` patterns
- Apply `.gitignore` patterns by default (configurable off)
- Allow “only consider Source + DeploymentArtifact” for staleness by default
- Optionally treat “never changed since import” differently from “stable but owned”
- Optional risk rule: flag files with high `ownership_concentration` where top owner has been inactive for `X` days

### 9.4 Module boundary strategy
Provide multiple ways to aggregate:
- Directory-based (default)
- Project file-based (C# `.csproj`, C++ `.vcxproj`, Rust `Cargo.toml`)
- Service boundary (EV2 service model / rollout spec references)

---

## 10. Scan 4 — Incident Association Mapping (ICM / GitHub)

### 10.1 Core challenge
Incidents live outside the repo; mapping must rely on **linking signals**:
- Incident/work item IDs in commit messages and PR titles
- ADO work item links to commits/PRs
- GitHub issues linked to PRs / commits
- EV2 service identifiers linking incidents to services, then to code ownership paths

### 10.2 Adapter-based design
Define a common interface:

- `IIncidentProvider`
  - Inputs: config + time window
  - Outputs: incidents (id, title, severity, service, created/resolved dates, tags)
- `IIncidentLinker`
  - Links incidents to commits/PRs and then to files/modules

Providers:
- `ICMProvider` (initially: import/export file or API if available internally)
- `GitHubProvider` (issues/incidents as configured)
- `ADOProvider` (work items + PRs)

Linking strategies (configurable priority):
1. Regex in commit messages: e.g. `ICM #123456`, `AB#12345`, `GH-123`
2. PR title/body scanning
3. ADO/GitHub link APIs (more reliable, requires auth)
4. Service-to-path mapping (manual config): `service Foo => /src/FooService/**`

### 10.3 Output
- “Incident density” per module/service
- “Top incident-associated files” and “top incident-associated directories”
- Time-window filtering (last 90/180/365 days)

---

## 11. EV2 + ADO Artifact Scanning

### 11.1 EV2 focus areas (examples)
- Rollout specs / service models / bindings:
  - Hardcoded subscription/tenant/cloud endpoints
  - Region pinning
  - Environment-specific constants not parameterized
  - Zero bake time / `WaitDuration: PT0S`
  - Missing post-deploy health checks
  - Single-region bindings with no failover path
  - Inline secrets instead of Key Vault references
- Detect opportunities for:
  - parameterization
  - environment overlays
  - separating config from code

### 11.2 ADO pipelines (YAML/classic)
- Hardcoded agent pools, paths, endpoints, service connection names
- Secrets accidentally inlined (also belongs in “other scan types”)
- Platform assumptions (Windows-only paths in scripts)
- Production stages missing approvals/gates (when policy requires them)
- Use of container `latest` tags instead of pinned digest/version

### 11.3 Artifact parsing approach
- YAML parsing (structure-aware)
- JSON parsing
- Text fallback when parsing fails (record parse errors as a finding category)

---

## 12. Data Model (SQLite)

### 12.1 Core tables (sketch)
- `scan_runs`
  - `run_id` (PK, ULID/string recommended), `repo_root`, `commit_sha`, `started_at`, `ended_at`, `tool_version`, `config_hash`
- `files`
  - `file_id` (PK), `path`, `category`, `size_bytes`, `hash`, `language`
- `findings`
  - `finding_id` (PK), `run_id`, `rule_id`, `file_id`, `file_path` (optional denormalized copy), `line`, `column`, `message`, `snippet`, `severity`, `confidence`, `fingerprint`, `metadata` (JSON text for scanner-specific fields)
- `rules`
  - `rule_id` (PK), `title`, `default_severity`, `description`
- `git_file_metrics`
  - `run_id`, `file_id`, `last_commit_at`, `commits_90d`, `commits_365d`, `authors_365d`, `churn_score`, `stale_score`
- `incidents`
  - `incident_id` (PK), `source` (ICM/GitHub/ADO), `title`, `severity`, `service`, `created_at`, `resolved_at`
- `incident_links`
  - `run_id`, `incident_id`, `file_id` (nullable), `module_key` (nullable), `link_type`, `confidence`

### 12.2 Indices
- `findings(run_id, rule_id, severity)`
- `findings(file_id)`
- `git_file_metrics(run_id, churn_score)`
- `incident_links(run_id, module_key)`

---

## 13. Scoring & Heatmap

### 13.1 Risk scoring (example)
Use configurable composite weighting so teams can tune what “risk” means:

```text
composite_risk =
  w_portability * portability_risk +
  w_magic * magic_string_opportunity +
  w_churn * churn_risk +
  w_staleness * staleness_risk +
  w_incident * incident_risk
```

```
RiskScore(file) =
    0.30 × normalize(churn_score)
  + 0.25 × normalize(finding_count_weighted_by_severity)
  + 0.25 × normalize(incident_severity_weight)
  + 0.10 × normalize(ownership_concentration)
  + 0.10 × normalize(staleness_score)
```

Per file:
- `portability_risk`: sum(severity_weight * confidence_weight)
- `magic_string_opportunity`: ranked score
- `churn_risk`: churn_score weight
- `staleness_risk`: stale_score weight
- `incident_risk`: incident_count * severity weight

Per directory/module:
- aggregate (sum or percentile-based to avoid one huge file dominating)

### 13.2 Heatmap representation
- Two complementary views:
  - Directory tree view (hierarchical heat coloring)
  - Treemap view (WinDirStat-like): size = LOC or file size, color = selected risk metric
- Color intensity based on selected metric:
  - “Portability blockers”
  - “Incident density”
  - “Churn hotspots”
  - “Stale risk”
- Drilldown: clicking a directory shows top findings and top files.

---

## 14. CLI Design (C#)

### 14.1 Commands (proposal)
- `reliabilityiq init`
  Creates default config + suppression files.
- `reliabilityiq scan all|portability|magic-strings|churn|incidents|deploy --repo <path> --config <file> [--since 180d] [--fail-on error|warning|info]`
- `reliabilityiq report table|heatmap|export --run <id> [--format csv|json|sarif|html]`
- `reliabilityiq rules list|validate|init`
- `reliabilityiq server start --db <file>` (optional: host the ASP.NET UI)

Exit codes for CI:
- `0`: no findings at or above `--fail-on`
- `1`: findings at or above `--fail-on` detected
- `2`: runtime/config/error condition (e.g., parse failure, bad config)

### 14.2 Output UX
- Summary counts by severity + rule
- Top 10 directories by risk
- Suggested next actions (e.g., “top 5 portability blockers in deployment specs”)

---

## 15. Web UI Sketch (ASP.NET + SQLite)

### 15.1 Pages
- **Runs**
  - list of scan runs with timestamps, commit SHA, config used
- **Findings**
  - table with filters: severity, rule, language, category, path prefix, run
  - sort by risk score / confidence
- **Heatmap**
  - directory tree and treemap modes + metric selector
- **Reports**
  - incidents vs churn correlation view (module and directory level)
- **File details**
  - inline snippet, occurrences, linked incidents, churn timeline (basic)

### 15.2 Data access
- Read-only SQLite access (safe default)
- Optionally copy DB to a UI workspace to avoid locking issues during scans
- Optional CODEOWNERS-derived “assigned team” column in findings and reports

---

## 16. Extensibility Strategy

### 16.1 Declarative rules first
- Regex detectors
- Heuristic detectors with tunable parameters

### 16.2 Plugin analyzers (later / optional)
- Load `.NET` assemblies from a `plugins/` folder
- `IAnalyzer` interface:
  - `Name`, `Version`, `SupportedFileCategories`
  - `AnalyzeAsync(AnalysisContext ctx) -> Findings`
- Define these interfaces in MVP even with built-in analyzers only, so plugin enablement is additive later (not a refactor prerequisite).
- Useful for org-specific:
  - ICM field mapping quirks
  - EV2 schema variations
  - Proprietary config formats

---

## 17. Performance & Incremental Scans

- Maintain a cache table:
  - last file hash + analyzer version + config hash
- Skip unchanged files for content analyzers
- Execution model:
  - file enumeration -> worker pool -> findings batching -> single SQLite writer
  - one parser instance per worker for non-thread-safe parser libraries
- SQLite strategy:
  - batched inserts in transactions to reduce write amplification
- Git metrics can be computed once per run; optimize by:
  - limiting window (`--since`)
  - caching per commit SHA

---

## 18. Testing Strategy

- Golden-repo fixtures:
  - small repos containing known portability problems, magic strings, EV2/ADO patterns
- Unit tests for:
  - rule parsing
  - file classification
  - AST extraction correctness (C#, PS, Python)
- Integration tests:
  - end-to-end scan produces stable SQLite outputs
- False-positive regression suite:
  - known noisy strings/logging-only repos

---

## 19. Security / Privacy Considerations

- SQLite contains code snippets by default—make snippet storage configurable:
  - `snippetMode: none|line|context`
- Credentials for ADO/GitHub/ICM:
  - use environment variables or OS credential store; never store tokens in SQLite
- If incident titles/descriptions are sensitive:
  - store IDs + severity only; fetch details on demand (UI) if permitted

---

## 20. Roadmap (pragmatic phased delivery)

<TODO>

---

# Freestyle Goal — Additional Scan Types That Fit This Product

1. **Secrets / Credential Hygiene**
   - Detect inline keys, connection strings, SAS tokens, private cert blobs in code/config/pipelines.
2. **Dependency & Supply Chain Risk**
   - Vulnerable package versions (NuGet, pip, cargo), pinned vs floating versions, unsigned binaries.
3. **Configuration Drift & Environment Coupling**
   - Differences between dev/test/prod configs; missing environment overrides; “one-off” configs.
4. **Observability Readiness**
   - Logging/metrics/tracing coverage signals; missing correlation IDs; “swallow exceptions” patterns.
5. **Resilience / Retry Anti-patterns**
   - Missing timeouts, unbounded retries, no circuit breaker; especially in network callsites.
6. **Build Reproducibility / Determinism**
   - Non-pinned toolchains, ambiguous build steps in pipelines, inconsistent SDK versions.
7. **Ownership / CODEOWNERS Coverage**
   - Stale/absent code ownership mappings for hot/incident-prone modules.
8. **Test Health Signals**
   - Flaky test detection (from CI logs if accessible), test-to-code churn mismatch.

### Tier 1 Freestyle — High value, directly supports stated goals:

| Scanner | Best Source | Why prioritize |
|---|---|---|
| **Secrets / Credential Leak** | Agent 3 (entropy + regex + complement to CredScan) | Directly blocks portability (different vaults per cloud) and is an operational risk. Original and Agent 2 mention it; Agent 3 is most specific. |
| **Configuration Drift** | Agent 3 (`scan-config-drift`: compare env-specific config files, flag missing keys) | Original mentions it; Agent 3 makes it a concrete scanner. Missing config keys are a top deployment failure cause. |
| **Dependency Freshness / Rot** | Agent 3 (OSV/GitHub Advisory DB integration) + Agent 2 (EOL database check, e.g., .NET Core 3.1, Python 2.7) | **Merge both**: Agent 3 covers CVEs, Agent 2 covers EOL frameworks. Together they give the full picture. |
| **Error Handling Coverage** | Agent 3 (bare catches, `except:`, `unwrap()` in non-test Rust) | Not in the original. Swallowed exceptions directly increase MTTR. |
| **Retry & Timeout Policy** | Agent 3 (`scan-resilience`: detect HTTP/DB/message bus calls lacking Polly/tenacity policies) | Original mentions it; Agent 3 gives detection specifics. Missing resilience policies → cascading failures, especially cross-cloud. |

### Tier 2 FreeStyle — Strong additions unique to one agent:

| Scanner | Source | Why include |
|---|---|---|
| **Circular Dependency Detection** | Agent 3 (unique) | Not in original or Agent 2. Circular deps complicate independent deployability and increase blast radius. Especially useful for C# project references and Rust crate graphs. |
| **Feature-Flag Hygiene** | Agent 3 (unique) | Not in original or Agent 2. Dead flags accumulate as magic strings and create untested branching complexity. Correlates with magic string scanner. |
| **Thread Safety / Async Anti-patterns** | Agent 3 (unique) | Not in original or Agent 2. `.Result`/`.Wait()` in async C#, `asyncio.run()` inside running loops, `block_on` in async Rust — these are leading causes of production hangs. |
| **Cyclomatic Complexity** | Agent 2 (unique) | Not in original or Agent 3. High complexity + high churn = immediate refactor candidate. Agent 2's suggestion to **overlay** this with the incident scanner is particularly valuable. |
| **ToDo/FIXME Debt** | Agent 2 (unique) | Not in original or Agent 3. Simple to implement, quantifies admitted tech debt. Low cost, moderate signal. |   

### Tier 3 Freestyle— Already in original, keep as-is:

| Scanner | Notes |
|---|---|
| **Observability Readiness** | Original + Agent 3 both cover this. Agent 3 adds "flag dark code paths with no instrumentation" — merge that detail. |
| **Ownership / CODEOWNERS Coverage** | Original + Agent 2's "Bus Factor" (flag modules where >80% commits by a single inactive author). Agent 3's Gini coefficient from the churn scanner already covers the quantitative side; Agent 2's "inactive author" check is an additional useful heuristic to merge. |
| **Build Reproducibility** | Original only. Keep. |
| **Test Health Signals** | Original only. Keep. |
