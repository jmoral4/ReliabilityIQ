# ReliabilityIQ — Phased Delivery Roadmap

Below is a **30-phase roadmap** organized as an initial MVP (Phases 1–2), followed by 14 paired scanner→web cycles covering every feature in the design doc.

---

## Phase 1 — MVP Scanner Foundation *(Agent 1)*

**Goal:** Establish the solution structure, core framework, simplest regex-only portability scanner, SQLite persistence, and a working CLI.

### Deliverables
1. **Solution & Project Scaffolding**
   - `ReliabilityIQ.sln`
   - `ReliabilityIQ.Cli` (console app, `System.CommandLine`)
   - `ReliabilityIQ.Core` (class library)
   - `ReliabilityIQ.Analyzers.Regex` (class library)
   - `ReliabilityIQ.Web` (empty ASP.NET project — placeholder)
   - `ReliabilityIQ.Tests` (xUnit)

2. **Core Framework (`ReliabilityIQ.Core`)**
   - `IAnalyzer` interface: `Name`, `Version`, `SupportedFileCategories`, `AnalyzeAsync(AnalysisContext) → IEnumerable<Finding>`
   - `AnalysisContext`: file path, content, file category, language, config reference
   - `Finding` model: `FindingId`, `RunId`, `RuleId`, `FilePath`, `Line`, `Column`, `Message`, `Snippet`, `Severity` (Error/Warning/Info), `Confidence` (High/Medium/Low), `Fingerprint`, `Metadata` (JSON string)
   - `FileClassifier`: categorize files into `Source`, `Config`, `DeploymentArtifact`, `Docs`, `Generated`, `Vendor`, `IDE` based on extension + path patterns
   - Default exclude patterns (build outputs, IDE, vendor dirs, `.gitignore` integration)
   - `RepoDiscovery`: find repo root, enumerate files, apply excludes + classification

3. **SQLite Schema & Persistence (`ReliabilityIQ.Core.Persistence`)**
   - Use `Microsoft.Data.Sqlite` + Dapper
   - Tables (Phase 1 subset):
     - `scan_runs` (`run_id` TEXT PK, `repo_root`, `commit_sha`, `started_at`, `ended_at`, `tool_version`, `config_hash`)
     - `files` (`file_id` INTEGER PK, `run_id`, `path`, `category`, `size_bytes`, `hash`, `language`)
     - `findings` (`finding_id` INTEGER PK, `run_id`, `rule_id`, `file_id`, `file_path`, `line`, `column`, `message`, `snippet`, `severity`, `confidence`, `fingerprint`, `metadata`)
     - `rules` (`rule_id` TEXT PK, `title`, `default_severity`, `description`)
   - Indices: `findings(run_id, rule_id, severity)`, `findings(file_id)`
   - `SqliteResultsWriter`: batched inserts (per 1,000 rows, wrapped in transactions)
   - Schema auto-migration on first run

4. **Regex-Only Portability Scanner (`ReliabilityIQ.Analyzers.Regex`)**
   - Implements `IAnalyzer`
   - **Rules** (regex-based, no AST):
     - `portability.hardcoded.ipv4` — IPv4 addresses (excluding `0.0.0.0`, `127.0.0.1` common exceptions via allowlist)
     - `portability.hardcoded.dns` — Cloud-specific DNS patterns (`*.windows.net`, `*.azure.com`, `*.core.windows.net`, `*.database.windows.net`, etc.)
     - `portability.hardcoded.filepath.windows` — Windows drive/UNC paths (`C:\...`, `\\server\...`)
     - `portability.hardcoded.filepath.linux` — Suspicious Linux absolute paths (`/var/`, `/etc/`, `/opt/` in source files)
     - `portability.hardcoded.guid` — Subscription/tenant GUID patterns near keywords (`subscription`, `tenant`, `resourceGroup`)
     - `portability.hardcoded.region` — Azure region names (`eastus`, `westus2`, `westeurope`, etc.)
     - `portability.hardcoded.endpoint` — Cloud management endpoints (`management.azure.com`, `login.microsoftonline.com`, metadata endpoints)
   - Each rule: regex pattern + file categories it applies to + default severity
   - Skip `Generated`, `Vendor`, `IDE` categories
   - Populate `rules` table on first run with built-in rule definitions

5. **CLI (`ReliabilityIQ.Cli`)**
   - Command: `reliabilityiq scan portability --repo <path> [--db <file>] [--fail-on error|warning|info]`
   - Workflow: discover repo → classify files → run regex analyzer → persist to SQLite → print summary
   - Summary output: count by severity, top 10 files by finding count
   - Exit codes: `0` (clean), `1` (findings above threshold), `2` (error)

6. **Tests**
   - Golden fixture: small directory with known hardcoded IPs, DNS names, file paths, GUIDs, region names
   - Unit tests: `FileClassifier`, regex patterns (true positives + true negatives), `SqliteResultsWriter`
   - Integration test: full scan → assert SQLite contents

### Acceptance Criteria
- `reliabilityiq scan portability --repo ./test-fixture` produces a SQLite DB with correct findings
- Files in `bin/`, `obj/`, `node_modules/`, `.vs/` are skipped
- CLI prints summary and returns correct exit code
- All tests pass

---

## Phase 2 — MVP Web Foundation *(Agent 2)*

**Goal:** ASP.NET web app that reads the SQLite database produced by Phase 1 and presents scan runs and findings in a usable table.

### Deliverables
1. **ASP.NET Project Setup (`ReliabilityIQ.Web`)**
   - ASP.NET with Razor Pages (or minimal MVC)
   - No Node build step — embed JS/CSS via CDN
   - CDN dependencies: DataTables.js, Bootstrap 5 (for layout)
   - Read-only SQLite connection (separate from scanner writes)
   - Configuration: `--db <path>` argument or `appsettings.json`

2. **Shared Data Access Layer**
   - Move SQLite read queries into `ReliabilityIQ.Core.Persistence.Queries` (shared between CLI reports and Web)
   - Query methods:
     - `GetAllRuns()` → list of scan runs
     - `GetRunById(runId)` → single run with summary stats
     - `GetFindings(runId, filters)` → paginated findings
     - `GetFileSummary(runId)` → files with finding counts
     - `GetRuleSummary(runId)` → findings grouped by rule

3. **Pages**
   - **`/` (Runs List)**
     - Table: run ID, repo root, commit SHA, started/ended, tool version, total findings (by severity badges)
     - Click a run → navigate to findings
   - **`/run/{runId}/findings` (Findings Table)**
     - DataTables.js powered table with server-side pagination
     - Columns: severity (icon + color), rule ID, file path, line, message, confidence
     - Filters (sidebar or dropdowns): severity, rule, file category, language, path prefix (text input)
     - Sort by: severity, file path, line, confidence
     - Click a row → expand to show snippet + full message
   - **`/run/{runId}/summary` (Run Summary)**
     - Findings count by severity (bar chart or simple cards)
     - Findings count by rule (horizontal bar)
     - Top 10 files by finding count

4. **Layout & Navigation**
   - Sidebar or top nav: Runs | Findings | Summary
   - Run selector (dropdown) persists across pages
   - Responsive layout (Bootstrap grid)

5. **Launch Integration**
   - `reliabilityiq server start --db <file> [--port 5100]` command in CLI project
   - Starts Kestrel, opens browser (optional `--no-browser`)

6. **Tests**
   - Integration test: seed a SQLite DB → start web host → verify pages return 200
   - Verify DataTables API endpoint returns correct JSON shape

### Acceptance Criteria
- `reliabilityiq server start --db results.db` opens a web UI showing runs and findings from Phase 1
- Findings table supports filtering by severity and rule, pagination, and sorting
- Summary page shows finding distribution
- Read-only access (no writes to DB from web)

---

## Phase 3 — AST-Enhanced Portability Scanner *(Agent 1)*

**Goal:** Upgrade the portability scanner from regex-only to AST-aware, using Roslyn (C#), Tree-sitter (C++/Python/Rust), and PowerShell AST for context-aware detection.

### Deliverables
1. **New Projects**
   - `ReliabilityIQ.Analyzers.CSharp` — Roslyn-based
   - `ReliabilityIQ.Analyzers.TreeSitter` — C++, Python, Rust via Tree-sitter P/Invoke
   - `ReliabilityIQ.Analyzers.PowerShell` — PowerShell AST

2. **C# Analyzer (Roslyn)**
   - `AdhocWorkspace` per file (no solution load)
   - Extract string literals + their **usage context**:
     - Argument to: `Uri`, `HttpClient`, `WebRequest`, `Dns`, `Socket`, `ProcessStartInfo`, `File.*`, `Path.*`, `BlobServiceClient`, `SqlConnection`, connection string patterns
     - Assignment from `IConfiguration` or `Environment.GetEnvironmentVariable` → **suppress** (semantic suppression)
     - Attribute arguments (`[DeploymentRegion("...")]`, etc.)
   - Hardcoded connection strings: `Server=`, `Data Source=`, `AccountKey=`
   - `localhost` binding detection (should be `0.0.0.0` for containers)
   - **Proximity suppression**: if config/env read within ±5 lines, downgrade to Info
   - **Test project downgrade**: findings in `*.Tests.csproj` or `/tests/` → severity `Info`

3. **Tree-sitter Analyzers (C++, Python, Rust)**
   - Tree-sitter native library via P/Invoke (per-worker instances)
   - C++: string literals in `connect()`, `getaddrinfo()`, `curl_easy_setopt()`, file APIs → flag hardcoded endpoints/paths
   - Python: string literals in `requests.*`, `socket.*`, `subprocess`, `open()`, `pathlib.Path()` → flag
   - Rust: `reqwest::`, `std::net::`, `std::fs::`, `Command::new()`, `include_str!()` patterns
   - Per-language node type mapping for string literal extraction

4. **PowerShell Analyzer**
   - PowerShell AST (`System.Management.Automation.Language`)
   - Flag strings in: `Invoke-WebRequest`, `Invoke-RestMethod`, `New-Object System.Uri`, `Set-Content`, `Out-File`

5. **Analyzer Orchestration Updates**
   - File routing by language: `.cs` → Roslyn, `.cpp/.h/.hpp` → Tree-sitter C++, `.py` → Tree-sitter Python, `.rs` → Tree-sitter Rust, `.ps1` → PowerShell AST
   - Regex analyzer still runs as fallback on config/text files
   - `Channel<FileWork>` fan-out to per-language worker pools
   - `Channel<FindingBatch>` for serialized SQLite writes

6. **New Rules**
   - `portability.hardcoded.connectionstring`
   - `portability.hardcoded.localhost`
   - `portability.hardcoded.registrykey` — `HKEY_LOCAL_MACHINE\...`
   - `portability.cloud.sdk.no_abstraction` — direct cloud SDK usage without interface indirection (C# only)
   - `portability.hardcoded.port` — non-standard ports in connect/listen calls
   - All existing regex rules now get AST-confirmed variants with higher confidence

7. **Suppression System (Basic)**
   - Inline: `// reliabilityiq: ignore portability.hardcoded.dns reason=...` (C# and similar for other languages)
   - File-level: `reliabilityiq.suppressions.yaml` — path glob + rule ID + optional fingerprint

8. **Tests**
   - Golden fixtures per language with true positives and false-positive traps (logging strings, config-sourced values, test code)
   - Verify AST-confirmed findings have higher confidence than regex-only
   - Verify suppression (inline + file-level) works
   - Verify test project severity downgrade

### Acceptance Criteria
- Scanning a C# repo uses Roslyn and produces AST-aware findings with callsite context
- Tree-sitter-based scanning works for C++, Python, Rust files
- PowerShell files are scanned with PowerShell AST
- False positives reduced vs Phase 1 (config-sourced values suppressed, test code downgraded)
- Inline and file-level suppressions functional

---

## Phase 4 — Enhanced Findings & File Detail UI *(Agent 2)*

**Goal:** Upgrade the web UI to handle AST-enhanced findings, add file detail view, remediation display, and improve filtering for the richer data.

### Deliverables
1. **Enhanced Findings Table**
   - New columns: `confidence`, `language`, `file_category`
   - Filter additions: confidence (High/Medium/Low), language dropdown, file category dropdown
   - Color-coded confidence badges
   - Findings grouped by AST-confirmed vs regex-only (visual distinction)
   - Callsite context shown in expanded row (from `metadata` JSON)

2. **File Detail Page (`/run/{runId}/file/{fileId}`)**
   - File metadata: path, category, language, size, hash
   - All findings for this file in a mini-table
   - Snippet display with syntax highlighting (use a CDN-hosted highlighter like Prism.js or highlight.js)
   - Line numbers with finding markers (colored dots/icons in gutter)

3. **Remediation Guidance Panel**
   - Each finding type shows recommended fix (stored in `rules.description` or `finding.metadata`)
   - Examples: "Replace hardcoded endpoint with `IConfiguration` lookup", "Use environment variable for connection string"
   - Collapsible guidance panel per finding row

4. **Summary Page Enhancements**
   - Findings by confidence level chart
   - Findings by language chart
   - AST-confirmed vs regex-only ratio
   - Top 10 files with most high-confidence findings

5. **Suppressed Findings View**
   - Toggle to show/hide suppressed findings (grayed out)
   - Suppression reason displayed when available

### Acceptance Criteria
- Findings table shows confidence, language, and category with working filters
- File detail page renders with syntax-highlighted snippets
- Remediation guidance appears for each finding type
- Suppressed findings toggle works

---

## Phase 5 — Magic Strings Scanner *(Agent 1)*

**Goal:** Implement the magic strings extraction, scoring, and ranking pipeline.

### Deliverables
1. **Magic String Analyzer (`ReliabilityIQ.Analyzers.MagicStrings`)**
   - Reuse AST extraction infrastructure from Phase 3
   - Extract all string literals with context: file, line, AST parent node type, callsite symbol

2. **Layer 1 — Exclusion Filters**
   - Logging/telemetry calls (configurable sink list: `Console.Write*`, `ILogger.*`, `log.*`, `print()`, `Write-Host`, `println!`, etc.)
   - Natural language heuristic: strings with ≥3 words + punctuation + high stopword ratio → exclude
   - Very short strings (length ≤ 2) → exclude
   - Known safe formats (GUID, ISO dates, semver) → exclude unless opted in
   - **Shannon entropy filter**: very high entropy strings → redirect to secrets scanner, exclude from magic strings
   - Strings already flagged by portability scanner → exclude (avoid duplication)

3. **Layer 2 — Detection & Scoring**
   - **Frequency score**: count of identical normalized literal across repo (logarithmic scaling)
   - **Comparison usage boost**: literal used in `==`, `switch`/`match`, dictionary key, `case` → strong positive
   - **Conditional/branching boost**: used in `if`/`else` conditions
   - **Test-only penalty**: all occurrences in test code → reduce score
   - **Exception message penalty**: used in `throw new`, `raise`, `panic!` → reduce score
   - Formula: `MagicScore = FrequencyScore × UsageBoost × (1 - Penalties)`

4. **Layer 3 — Aggregation & Output**
   - One entry per unique normalized literal
   - Fields: normalized text, magic score, occurrence count, top locations (file + line), all-occurrences list, AST context summary
   - New rules in `rules` table: `magic-string.high-frequency`, `magic-string.comparison-used`, `magic-string.candidate`
   - Findings stored as severity `Info` by default (these are "ranked opportunities," not violations)
   - SQLite: findings link to all occurrence locations via `metadata` JSON array

5. **Configuration Knobs**
   - `minOccurrences` (default: 2)
   - `maxFindingsPerDirectory` (default: 50)
   - `maxFindingsTotal` (default: 500)
   - Allowlist/denylist patterns
   - Per-language logging sink list (editable YAML)
   - Entropy threshold for secrets redirection

6. **CLI Integration**
   - `reliabilityiq scan magic-strings --repo <path> [--db <file>] [--min-occurrences 3] [--top 50]`
   - Summary output: "Top 20 magic string candidates" with score + count + sample location
   - `reliabilityiq scan all` now includes magic strings

7. **Tests**
   - Fixture with: repeated strings in switch statements (should rank high), logging messages (should be excluded), single-use strings (should be excluded), high-entropy tokens (should be excluded)
   - Unit tests for entropy calculation, natural language heuristic, scoring formula
   - Integration test: full scan → verify ranking order is sensible

### Acceptance Criteria
- Magic strings scanner extracts and ranks string literals from all supported languages
- Logging messages, natural language, short strings, and high-entropy strings are excluded
- Repeated strings used in comparisons rank highest
- Results stored in SQLite with occurrence details
- Configuration knobs work (minOccurrences, allowlist, etc.)

---

## Phase 6 — Magic Strings UI *(Agent 2)*

**Goal:** Present magic string candidates as ranked opportunities with occurrence exploration.

### Deliverables
1. **Magic Strings Page (`/run/{runId}/magic-strings`)**
   - Ranked table (DataTables.js): score (descending), normalized literal (truncated), occurrence count, top location, language(s)
   - Visual score indicator (bar or gradient)
   - Click row → expand to show all occurrences (file, line, AST context)
   - "Show All Occurrences" button → modal or inline expansion with paginated list

2. **Filters & Controls**
   - Minimum score slider
   - Minimum occurrence count input
   - Language filter
   - Path prefix filter
   - "Per module" vs "overall" toggle
   - "Top N" selector (10 / 25 / 50 / 100)

3. **Module-Level Aggregation View**
   - "Top N per directory/module" view
   - Collapsible directory tree → each directory shows its top magic string candidates

4. **Integration with Findings Table**
   - Magic string findings appear in the main findings table (filtered by `magic-string.*` rule IDs)
   - But the dedicated Magic Strings page provides the ranked, exploration-oriented UX

5. **Navigation Update**
   - Add "Magic Strings" to navigation bar

### Acceptance Criteria
- Magic strings page shows ranked candidates with expandable occurrences
- Filters (score, count, language, path) work correctly
- Module-level aggregation view functional
- Magic string findings also appear in main findings table

---

## Phase 7 — Git Churn & Staleness Scanner *(Agent 1)*

**Goal:** Implement Git history analysis for churn hotspots, staleness, and ownership concentration.

### Deliverables
1. **New Project: `ReliabilityIQ.Analyzers.GitHistory`**
   - Depends on `LibGit2Sharp`
   - Implements `IAnalyzer` (operates on repo level, not per-file)

2. **SQLite Schema Extension**
   - New table `git_file_metrics`:
     - `run_id`, `file_id`, `file_path`, `last_commit_at`, `commits_30d`, `commits_90d`, `commits_180d`, `commits_365d`, `authors_365d`, `ownership_concentration` (Gini coefficient), `lines_added_365d`, `lines_removed_365d`, `churn_score`, `stale_score`, `top_author`, `top_author_pct`
   - Index: `git_file_metrics(run_id, churn_score DESC)`, `git_file_metrics(run_id, stale_score DESC)`

3. **Metrics Computation**
   - Walk Git log (configurable window, default: 365 days, `--since` flag)
   - Per file:
     - `last_commit_at` — most recent commit touching this file
     - `commits_Nd` — commit count in each window
     - `authors_365d` — unique author count
     - `ownership_concentration` — Gini coefficient on per-author commit distribution (`1.0` = single owner)
     - `lines_added/removed` — diff stats (optional, configurable, slower)
     - `churn_score` = `TotalCommits × log(LinesAdded + LinesDeleted + 1)`
     - `stale_score` = time-decay function based on days since last commit
   - Per directory/module aggregation: percentile-based (to avoid one huge file dominating)

4. **Module Boundary Strategies**
   - Directory-based (default)
   - Project file-based: detect `.csproj`, `.vcxproj`, `Cargo.toml` → group contained files
   - Service boundary: EV2 service model references (config mapping: `service Foo => /src/FooService/**`)

5. **Noise Reduction**
   - Apply file classification: only compute staleness for `Source` + `DeploymentArtifact` by default
   - Extended `staleIgnore` patterns: `.designer.cs`, `.g.cs`, `.generated.*`, `packages.lock.json`, `yarn.lock`, `RolloutSpec.generated.json`
   - `.gitignore` respected by default
   - "Never changed since import" heuristic: if file was added in a single large commit and never touched again, flag differently than "stable but owned"

6. **Ownership Risk Rule**
   - Flag files where `ownership_concentration > 0.8` AND top author has no commits in last 90 days → "orphaned knowledge risk"

7. **CLI Integration**
   - `reliabilityiq scan churn --repo <path> [--db <file>] [--since 365d]`
   - Summary: top 10 churn hotspots, top 10 stale files, top 10 ownership risks
   - `reliabilityiq scan all` now includes churn

8. **Performance**
   - Cache Git metrics per commit SHA in scan cache
   - Limit log window via `--since`
   - Batch insert metrics

9. **Tests**
   - Golden Git repo fixture (scripted creation with known commit patterns)
   - Unit tests: Gini coefficient calculation, churn score formula, stale score decay
   - Verify generated files are excluded from staleness
   - Verify module aggregation works

### Acceptance Criteria
- Git metrics computed and stored for all source files
- Gini coefficient accurately reflects ownership concentration
- Stale files correctly identified (excluding generated/vendor/docs)
- Ownership risk rule fires for single-owner inactive files
- Module aggregation by directory and project file works

---

## Phase 8 — Heatmap & Churn Visualization UI *(Agent 2)*

**Goal:** Add the heatmap (directory tree + treemap) and churn/staleness visualization to the web UI.

### Deliverables
1. **Heatmap Page (`/run/{runId}/heatmap`)**
   - **Directory Tree View** (D3.js collapsible tree):
     - Each node colored by selected risk metric intensity
     - Node size indicates file count or LOC
     - Expand/collapse directories
     - Click directory → drilldown panel with top findings + top files
   - **Treemap View** (D3.js treemap, WinDirStat-like):
     - Rectangle size = file size or LOC
     - Color = selected risk metric
     - Hover: file name, metric value, finding count
     - Click: navigate to file detail page

2. **Metric Selector**
   - Dropdown/radio: Churn Hotspots | Stale Risk | Ownership Risk | Portability Blockers | Finding Density
   - Heatmap re-renders on selection change
   - Color legend (gradient with labeled breakpoints)

3. **Churn & Staleness Table (`/run/{runId}/churn`)**
   - DataTables.js table: file path, churn_score, stale_score, commits_90d, authors_365d, ownership_concentration, last_commit_at
   - Sortable by any column
   - Filters: min churn score, max stale score, module/directory prefix
   - Visual sparkline or mini-bar for churn score

4. **Ownership View**
   - Table of files with high ownership concentration
   - Columns: file, top author, top author %, authors count, last commit
   - "Orphaned" badge for files where top author is inactive

5. **Drilldown Integration**
   - Clicking a file in heatmap or churn table → navigates to file detail page (Phase 4)
   - Clicking a directory → shows aggregated metrics + top findings

6. **Navigation Update**
   - Add "Heatmap" and "Churn" to navigation

7. **Data Access Queries**
   - `GetGitMetrics(runId, sortBy, filters)` → paginated
   - `GetDirectoryAggregates(runId, metric)` → for heatmap
   - `GetTreemapData(runId, metric)` → hierarchical JSON for D3

### Acceptance Criteria
- Directory tree heatmap renders with correct color intensity
- Treemap view displays file sizes with risk coloring
- Metric selector changes heatmap/treemap rendering
- Churn table is filterable and sortable
- Ownership risk files are highlighted
- Drilldown from heatmap → file/directory detail works

---

## Phase 9 — EV2 & ADO Artifact Scanner *(Agent 1)*

**Goal:** Structure-aware scanning of EV2 rollout specs, service models, and ADO pipeline YAML/JSON.

### Deliverables
1. **New Project: `ReliabilityIQ.Analyzers.Artifacts`**
   - YAML parsing (`YamlDotNet`) + JSON parsing (`System.Text.Json`)
   - Text fallback when parsing fails (record parse errors as a finding)

2. **EV2 Analyzer**
   - Parse rollout specs, service models, bindings
   - Rules:
     - `deploy.ev2.hardcoded.subscription` — subscription IDs not parameterized
     - `deploy.ev2.hardcoded.tenant` — tenant IDs not parameterized
     - `deploy.ev2.hardcoded.endpoint` — cloud endpoints not parameterized
     - `deploy.ev2.hardcoded.region` — region pinning without parameterization
     - `deploy.ev2.zero_bake_time` — `WaitDuration: PT0S` or missing wait duration
     - `deploy.ev2.no_health_check` — missing post-deploy health check configuration
     - `deploy.ev2.single_region` — bindings with no failover path
     - `deploy.ev2.inline_secret` — secrets not referenced via Key Vault
     - `deploy.ev2.env_constant` — environment-specific constants that should be parameterized

3. **ADO Pipeline Analyzer**
   - Parse YAML pipelines + classic JSON definitions
   - Rules:
     - `deploy.ado.hardcoded.agentpool` — agent pool names not variable-ized
     - `deploy.ado.hardcoded.path` — hardcoded paths in script steps
     - `deploy.ado.hardcoded.endpoint` — service connection names hardcoded
     - `deploy.ado.inline_secret` — secrets not from variable groups/key vault
     - `deploy.ado.platform_assumption` — Windows-only paths in scripts
     - `deploy.ado.missing_approval` — production stages missing approval gates
     - `deploy.ado.container_latest` — `latest` tag instead of pinned digest/version

4. **File Classification Enhancement**
   - Extend `FileClassifier` to identify EV2 artifacts (rollout specs, service models) and ADO pipelines by path patterns + content heuristics
   - Configurable path patterns for EV2/ADO artifact locations

5. **CLI Integration**
   - `reliabilityiq scan deploy --repo <path> [--db <file>]`
   - Summary: count by rule category (EV2 vs ADO), top findings
   - `reliabilityiq scan all` includes deploy

6. **Tests**
   - Golden EV2 fixtures: rollout spec with hardcoded subscription, zero bake time, missing health check
   - Golden ADO fixtures: pipeline with hardcoded pool, latest tag, missing approval
   - Verify parse error fallback works for malformed YAML

### Acceptance Criteria
- EV2 and ADO artifacts detected by file classification
- All rules fire correctly on golden fixtures
- Malformed YAML/JSON produces a parse error finding (not a crash)
- Findings include specific location within YAML/JSON structure

---

## Phase 10 — Deployment Artifact UI *(Agent 2)*

**Goal:** Present EV2/ADO findings with deployment-specific context and filtering.

### Deliverables
1. **Deployment Findings View (`/run/{runId}/deploy`)**
   - Findings table filtered to `deploy.*` rules
   - Grouped by artifact type: EV2 | ADO
   - Columns: severity, rule, artifact file, location (YAML path), message, remediation
   - Expandable row: YAML/JSON context snippet

2. **Deployment Risk Summary**
   - Cards: total EV2 findings by severity, total ADO findings by severity
   - Top 5 riskiest deployment artifacts
   - Parameterization opportunities count

3. **Filters**
   - Artifact type (EV2 / ADO / All)
   - Rule subcategory (hardcoded values / missing safety / inline secrets)
   - Severity

4. **Integration**
   - Deploy findings also appear in main findings table
   - File detail page shows deployment context for artifact files

5. **Navigation Update**
   - Add "Deploy" to navigation

### Acceptance Criteria
- Deployment page shows EV2 and ADO findings with grouping
- Risk summary cards render correct counts
- Filters work correctly
- Deployment findings visible in both dedicated page and main findings table

---

## Phase 11 — Rule Configuration & Validation System *(Agent 1)*

**Goal:** Implement the full YAML-based rule configuration system with split-file layout, merge precedence, validation, and allowlists.

### Deliverables
1. **Configuration Model (`ReliabilityIQ.Core.Configuration`)**
   - YAML parsing with `YamlDotNet`
   - JSON schema for all config files (embedded resource)
   - Config model classes: `ScanConfig`, `RuleConfig`, `AllowlistConfig`, `SuppressionConfig`

2. **Split-File Layout**
   - `.reliabilityiq/config.yaml` — global settings (repo, excludes, snippet mode, scan targets)
   - `.reliabilityiq/rules/portability.yaml` — portability rule overrides
   - `.reliabilityiq/rules/magic-strings.yaml` — magic string tuning
   - `.reliabilityiq/rules/churn.yaml` — churn thresholds
   - `.reliabilityiq/rules/incidents.yaml` — incident linking config
   - `.reliabilityiq/rules/deploy-ev2.yaml` — EV2 rule overrides
   - `.reliabilityiq/rules/deploy-ado.yaml` — ADO rule overrides
   - `.reliabilityiq/rules/custom/*.yaml` — team-specific custom rules
   - `.reliabilityiq/allowlists/*.yaml` — allowlisted patterns

3. **Merge Precedence Engine**
   - Layer 1: Built-in defaults (hardcoded in assembly)
   - Layer 2: `.reliabilityiq/rules/*.yaml`
   - Layer 3: `.reliabilityiq/rules/custom/*.yaml`
   - Layer 4: CLI flags (highest precedence)
   - Deep merge: rule-level overrides (severity, enabled/disabled, threshold changes)

4. **Rule Validation CLI**
   - `reliabilityiq rules validate [--config <path>]`
     - JSON schema validation
     - Duplicate rule ID detection
     - Invalid glob pattern detection
     - Precedence conflict warnings (same rule overridden in multiple files)
     - Unknown rule ID references in allowlists/suppressions
   - `reliabilityiq rules list [--enabled-only] [--category <cat>]`
     - Print all rules with effective configuration (after merge)
   - `reliabilityiq rules init`
     - Generate default `.reliabilityiq/` directory structure with commented templates

5. **Declarative Custom Rules**
   - Support adding regex-based rules via YAML:
     ```yaml
     rules:
       - id: custom.my-org.forbidden-endpoint
         pattern: "internal\\.myorg\\.com"
         fileCategories: [Source, Config]
         severity: Warning
         message: "Replace with config-driven endpoint"
     ```
   - Custom rules loaded from `.reliabilityiq/rules/custom/*.yaml`
   - Validated against JSON schema

6. **Allowlist System**
   - Allowlist entries: path glob + rule ID + optional string pattern
   - Findings matching allowlist → suppressed (not emitted, or emitted as `Suppressed`)
   - Allowlists stored in `.reliabilityiq/allowlists/*.yaml`

7. **Plugin Interface Definition** (interfaces only, no loader yet)
   - `IAnalyzerPlugin`: `Name`, `Version`, `SupportedFileCategories`, `AnalyzeAsync(AnalysisContext) → IEnumerable<Finding>`
   - Defined in `ReliabilityIQ.Core` — ready for future plugin loading

8. **Retrofit Existing Analyzers**
   - All Phase 1–9 analyzers now read their configuration from the merged config
   - CLI flags (`--fail-on`, `--since`, `--min-occurrences`, etc.) override YAML settings

9. **`reliabilityiq init` Command**
   - Creates `.reliabilityiq/` directory with default config, rule templates, empty allowlist
   - Idempotent (doesn't overwrite existing files)

10. **Tests**
    - Unit tests: config merge logic, schema validation, glob matching
    - Test: invalid YAML produces clear error message
    - Test: CLI flag overrides YAML setting
    - Test: custom regex rule fires on matching content
    - Test: allowlist suppresses matching findings

### Acceptance Criteria
- `reliabilityiq init` creates valid config structure
- `reliabilityiq rules validate` catches schema errors, duplicate IDs, bad globs
- `reliabilityiq rules list` shows effective merged configuration
- Custom regex rules work via YAML
- Allowlists suppress matching findings
- All existing scanners respect YAML configuration
- CLI flags override YAML settings

---

## Phase 12 — Rule Management & Export UI *(Agent 2)*

**Goal:** Add rule browsing, suppression visibility, and report export capabilities to the web UI.

### Deliverables
1. **Rules Page (`/rules`)**
   - Table of all known rules (from `rules` table): rule ID, title, default severity, description, category
   - Effective state indicator: enabled / disabled / overridden
   - Filter by category (portability / magic-strings / churn / deploy / custom)
   - Click rule → show all findings for that rule across runs

2. **Suppressions Page (`/run/{runId}/suppressions`)**
   - Table of suppressed findings: file, rule, reason, suppression source (inline / allowlist / config)
   - Count of suppressions by rule
   - "What-if" indicator: total findings if suppressions were removed

3. **Report Export**
   - Export buttons on findings page:
     - CSV export (filtered view)
     - JSON export (full findings + metadata)
     - SARIF export (for integration with IDEs / CI)
     - HTML export (self-contained single-page report)
   - Export triggered via API endpoint, file downloaded via browser

4. **Run Comparison (Basic)**
   - Select two runs → show:
     - New findings (in run B, not in run A, by fingerprint)
     - Fixed findings (in run A, not in run B)
     - Unchanged findings count
   - Simple table view

5. **Navigation Update**
   - Add "Rules" and "Export" to navigation

### Acceptance Criteria
- Rules page displays all rules with effective state
- Suppressions page shows suppressed findings with source
- All four export formats produce valid output
- Run comparison shows new/fixed/unchanged findings

---

## Phase 13 — Incident Association Scanner *(Agent 1)*

**Goal:** Implement the incident-to-code mapping system with adapter-based providers and linking strategies.

### Deliverables
1. **New Project: `ReliabilityIQ.Analyzers.Incidents`**

2. **SQLite Schema Extension**
   - `incidents` table: `incident_id` TEXT PK, `source` (ICM/GitHub/ADO), `title`, `severity`, `service`, `created_at`, `resolved_at`, `tags` (JSON)
   - `incident_links` table: `run_id`, `incident_id`, `file_id` (nullable), `module_key` (nullable), `link_type` (commit_message / pr_title / api_link / service_map), `confidence` (High/Medium/Low), `commit_sha`
   - Index: `incident_links(run_id, module_key)`

3. **Provider Interfaces**
   - `IIncidentProvider`: `GetIncidentsAsync(config, timeWindow) → IEnumerable<Incident>`
   - `IIncidentLinker`: `LinkIncidentsAsync(incidents, commits, files) → IEnumerable<IncidentLink>`

4. **Providers**
   - `GitHubIssueProvider`: fetch issues labeled as incidents (configurable labels) via GitHub API
   - `ADOWorkItemProvider`: fetch work items by type/tag via ADO API
   - `FileImportProvider`: import incidents from CSV/JSON file (for ICM exports or any source)
   - Auth: environment variables (`GITHUB_TOKEN`, `ADO_PAT`) or OS credential store

5. **Linking Strategies** (configurable priority)
   1. Commit message regex: `ICM #(\d+)`, `AB#(\d+)`, `GH-(\d+)`, `Fixes #(\d+)` (configurable patterns)
   2. PR title/body scanning (for GitHub PRs linked to commits)
   3. API-based links (ADO work item → commit links, GitHub issue → PR → commit)
   4. Service-to-path mapping: manual config `service Foo => /src/FooService/**`

6. **Incident Density Computation**
   - Per file: count of linked incidents weighted by severity
   - Per module/directory: aggregate
   - Time-window filtering: `--since 90d|180d|365d`

7. **CLI Integration**
   - `reliabilityiq scan incidents --repo <path> [--db <file>] [--since 365d] [--provider github|ado|file] [--config <file>]`
   - Summary: top 10 incident-associated modules, incident density distribution
   - `reliabilityiq scan all` includes incidents (if provider configured)

8. **Security Considerations**
   - Configurable `incidentDetailMode: id_only | id_and_severity | full`
   - Tokens never stored in SQLite
   - Sensitive incident titles/descriptions: store only if `full` mode enabled

9. **Tests**
   - Golden repo with scripted commit messages containing incident IDs
   - Mock providers for GitHub and ADO
   - Test linking strategies independently
   - Test service-to-path mapping

### Acceptance Criteria
- Incidents imported from at least one provider (GitHub or file import)
- Commit message regex linking works with configurable patterns
- Incident density computed per file and module
- Security modes respected (id_only doesn't store titles)
- Time-window filtering works

---

## Phase 14 — Incident Correlation & Composite Risk UI *(Agent 2)*

**Goal:** Visualize incident associations, and introduce the composite risk scoring dashboard.

### Deliverables
1. **Incident Page (`/run/{runId}/incidents`)**
   - Incident density table: module/directory, incident count, weighted severity, top incidents
   - Top incident-associated files table
   - Time-window selector (90d / 180d / 365d)
   - Click module → expand to show linked incidents with source, severity, link type, confidence

2. **Incidents × Churn Correlation View (`/run/{runId}/reports/correlation`)**
   - Scatter plot (Chart.js): X = churn score, Y = incident density, point size = file size, color = severity
   - Quadrant labels: "High churn + High incidents" (top-right = highest risk)
   - Click point → navigate to file detail
   - Module-level and directory-level aggregation toggle

3. **Composite Risk Scoring (Backend)**
   - Add to `ReliabilityIQ.Core.Scoring`:
     ```
     composite_risk =
       w_portability × portability_risk +
       w_magic × magic_string_opportunity +
       w_churn × churn_risk +
       w_staleness × staleness_risk +
       w_incident × incident_risk
     ```
   - Default weights from config, per-file and per-directory computation
   - Store in new table `risk_scores`: `run_id`, `file_id`, `composite_risk`, `portability_risk`, `magic_risk`, `churn_risk`, `stale_risk`, `incident_risk`
   - Compute after all scanners complete

4. **Risk Dashboard (`/run/{runId}/dashboard`)**
   - Top 20 riskiest files (by composite score) with breakdown bars
   - Top 10 riskiest directories
   - Risk distribution histogram
   - Per-risk-dimension cards (total portability / magic / churn / staleness / incident findings)
   - Make this the new landing page for a run

5. **Heatmap Enhancement**
   - Add "Composite Risk" and "Incident Density" as metric options in the heatmap (Phase 8)

6. **Navigation Update**
   - Add "Incidents" and "Dashboard" (make Dashboard the default run page)

### Acceptance Criteria
- Incident density table and top-files view render correctly
- Scatter plot shows churn × incident correlation with clickable points
- Composite risk scores computed and stored
- Dashboard shows top riskiest files/directories with breakdown
- Heatmap supports composite risk and incident density metrics

---

## Phase 15 — Incremental Scanning & Performance *(Agent 1)*

**Goal:** Implement scan caching for incremental runs, channel-based parallelism, and performance optimizations.

### Deliverables
1. **Scan Cache Table**
   - `scan_cache`: `file_path`, `file_hash`, `analyzer_name`, `analyzer_version`, `config_hash`, `last_run_id`
   - On scan start: compare current file hash + analyzer version + config hash → skip unchanged files
   - Copy previous findings for skipped files (with new `run_id`)

2. **Channel-Based Parallelism**
   - `Channel<FileWork>` for fan-out to language-specific worker pools
   - `Channel<FindingBatch>` for serialized SQLite writes (single writer)
   - Configurable worker count (`--parallelism` or config `scan.parallelism: auto`)
   - Per-worker Tree-sitter parser instances (not shared across threads)
   - Per-worker Roslyn `AdhocWorkspace` instances

3. **Bulk Insert Optimization**
   - Batch size: 1,000 rows per transaction
   - WAL mode for SQLite (concurrent reads during writes)
   - Prepared statements reuse within batches

4. **Git Metrics Caching**
   - If commit SHA unchanged → reuse previous git metrics entirely
   - If partial change → only recompute affected files (by diffing commits since last scan)

5. **Progress Reporting**
   - CLI progress bar: files scanned / total, findings so far, estimated time
   - `--verbose` mode: per-file timing, skipped file count

6. **`reliabilityiq scan all` Orchestration**
   - Run all enabled scanners in optimal order:
     1. File discovery + classification
     2. Content analyzers (parallelized)
     3. Git metrics
     4. Incident linking
     5. Composite scoring
   - Single SQLite DB output

7. **Benchmarks**
   - Measure scan time on a medium repo (~10K files)
   - Compare full scan vs incremental scan (target: ≥80% time reduction for 5% file changes)

8. **Tests**
   - Test: unchanged files are skipped on second scan
   - Test: findings from skipped files appear in new run
   - Test: parallel scanning produces same results as sequential
   - Test: bulk insert handles 100K+ findings

### Acceptance Criteria
- Incremental scan skips unchanged files and reuses findings
- Channel-based parallelism works without data corruption
- Bulk inserts handle large finding counts efficiently
- Progress reporting works in CLI
- `scan all` orchestrates all scanners in correct order

---

## Phase 16 — Run Trends & Performance Dashboard UI *(Agent 2)*

**Goal:** Add run-over-run trend analysis, enhanced run comparison, and scan performance visibility.

### Deliverables
1. **Trends Page (`/trends`)**
   - Line chart (Chart.js): findings count by severity over multiple runs
   - Line chart: composite risk score trend (avg/median/max per run)
   - Line chart: churn hotspot count over time
   - Run selector: date range picker
   - Filter by rule category

2. **Enhanced Run Comparison (`/compare`)**
   - Side-by-side run selector
   - Diff view: new findings, fixed findings, changed severity, unchanged
   - Delta summary cards: "+12 new portability, −5 fixed, net +7"
   - Filterable diff table

3. **Scan Performance View (`/run/{runId}/perf`)**
   - Scan duration breakdown: discovery, analysis, git metrics, incident linking, scoring, persistence
   - Files scanned vs skipped (incremental cache hits)
   - Per-analyzer timing
   - Parallelism utilization

4. **Dashboard Enhancements**
   - Mini trend sparklines on dashboard cards (last 5 runs)
   - "Improvement" or "Regression" badges based on trend direction

5. **Navigation Update**
   - Add "Trends" and "Compare" to navigation

### Acceptance Criteria
- Trend charts render correctly across multiple runs
- Run comparison shows accurate new/fixed/unchanged findings
- Scan performance breakdown displays correctly
- Dashboard sparklines update with run history

---

## Phase 17 — Secrets & Credential Hygiene Scanner *(Agent 1)*

**Goal:** Detect inline secrets, API keys, connection strings, SAS tokens, and certificate blobs in code and config.

### Deliverables
1. **New Project: `ReliabilityIQ.Analyzers.Secrets`**

2. **Detection Strategies**
   - **High-entropy string detection**: Shannon entropy threshold (configurable, default: 4.5 for base64, 3.5 for hex)
   - **Known patterns** (regex):
     - Azure Storage account keys (`AccountKey=...`)
     - SAS tokens (`?sv=...&sig=...`)
     - Azure AD client secrets
     - AWS access keys (`AKIA...`)
     - GCP service account JSON patterns
     - Generic API key patterns (`api[_-]?key\s*[:=]\s*["']...`)
     - Private key headers (`-----BEGIN.*PRIVATE KEY-----`)
     - JWT tokens (`eyJ...`)
     - Connection strings with embedded passwords
   - **Context enhancement**: AST-aware detection (reuse Phase 3 infrastructure) — flag strings in assignment to `password`, `secret`, `key`, `token` variables
   - **File-type targeting**: config files, environment files (`.env`), deployment artifacts get extra scrutiny

3. **False Positive Reduction**
   - Allowlist for known safe patterns (example keys in docs, test fixtures with `TODO:replace`)
   - Placeholder detection: `<placeholder>`, `${...}`, `{{...}}`, `YOUR_KEY_HERE`
   - Skip strings sourced from Key Vault / env variables / secret managers

4. **Rules**
   - `secrets.high_entropy` — generic high-entropy string
   - `secrets.azure.storage_key`
   - `secrets.azure.sas_token`
   - `secrets.azure.client_secret`
   - `secrets.aws.access_key`
   - `secrets.generic.api_key`
   - `secrets.generic.private_key`
   - `secrets.generic.jwt`
   - `secrets.generic.connection_string_password`

5. **Severity**: All secret findings default to `Error` severity

6. **CLI Integration**
   - `reliabilityiq scan secrets --repo <path> [--db <file>]`
   - Configurable snippet mode for secrets: default `snippetMode: none` (don't store the actual secret value in SQLite)

7. **Tests**
   - Fixture with known secrets (test-only values), placeholder patterns, safe config-sourced values
   - Entropy threshold tuning tests
   - Verify no actual secrets stored in SQLite when `snippetMode: none`

### Acceptance Criteria
- Known secret patterns detected across all file types
- High-entropy strings flagged with appropriate confidence
- Placeholders and config-sourced values not flagged
- Secrets not stored in SQLite snippets by default
- All findings have Error severity

---

## Phase 18 — Secrets UI *(Agent 2)*

**Goal:** Present secrets findings with appropriate security UX.

### Deliverables
1. **Secrets Page (`/run/{runId}/secrets`)**
   - Findings table filtered to `secrets.*` rules
   - Columns: severity, rule, file, line, confidence (NO snippet column by default)
   - Snippet toggle: opt-in display with warning ("Snippets may contain sensitive values")
   - Grouped by secret type (Azure / AWS / Generic / High-entropy)

2. **Secret Summary Cards**
   - Count by type
   - Count by file category (source / config / deployment)
   - "Critical" badge for production-path files with secrets

3. **Remediation Panel**
   - Per-finding-type remediation: "Move to Azure Key Vault", "Use environment variable", "Use managed identity"
   - Link to Azure Key Vault docs / best practices

4. **Navigation Update**
   - Add "Secrets" to navigation with alert badge if Error-severity findings exist

### Acceptance Criteria
- Secrets page shows findings without exposing secret values by default
- Snippet toggle works with warning
- Remediation guidance displays per type
- Alert badge appears in navigation

---

## Phase 19 — Config Drift & Dependency Freshness Scanners *(Agent 1)*

**Goal:** Detect configuration drift across environments and dependency rot / CVE exposure.

### Deliverables

#### A. Configuration Drift Scanner
1. **Analyzer: `ReliabilityIQ.Analyzers.ConfigDrift`**
2. **Detection**:
   - Identify environment-specific config file sets (e.g., `appsettings.Development.json`, `appsettings.Production.json`, `config.dev.yaml`, `config.prod.yaml`)
   - Configurable naming convention patterns
   - Compare key sets across environments → flag:
     - Missing keys in some environments
     - Keys present in only one environment (potential orphans)
     - Value differences that look like hardcoded environment-specific values (not parameterized)
3. **Rules**:
   - `config.drift.missing_key` — key exists in env A but not env B
   - `config.drift.orphan_key` — key in only one environment
   - `config.drift.hardcoded_env_value` — value differs across envs but isn't parameterized
4. **Output**: findings with environment comparison context in metadata

#### B. Dependency Freshness Scanner
1. **Analyzer: `ReliabilityIQ.Analyzers.Dependencies`**
2. **Package file parsing**:
   - NuGet: `.csproj` `<PackageReference>`, `packages.config`, `Directory.Packages.props`
   - pip: `requirements.txt`, `setup.py`, `pyproject.toml`
   - Cargo: `Cargo.toml`
   - npm (bonus): `package.json` (if present in repo)
3. **CVE lookup**: query OSV (Open Source Vulnerabilities) API or GitHub Advisory Database API
4. **EOL framework detection**:
   - .NET Core 3.1, .NET 5 (out of support)
   - Python 2.x, Python 3.6 (EOL)
   - Known EOL package versions
5. **Version pinning check**: flag floating version ranges vs pinned versions
6. **Rules**:
   - `deps.vulnerable.critical` / `deps.vulnerable.high` / `deps.vulnerable.medium`
   - `deps.eol.framework`
   - `deps.unpinned_version`
7. **CLI**: `reliabilityiq scan config-drift` and `reliabilityiq scan deps`

8. **Tests**
   - Config drift: fixture with dev/prod configs missing keys
   - Dependencies: fixture with known vulnerable + EOL packages
   - Mock OSV API responses

### Acceptance Criteria
- Config drift detects missing keys across environment configs
- Dependency scanner parses NuGet, pip, and Cargo files
- CVE lookup identifies known vulnerabilities
- EOL frameworks flagged
- Unpinned versions detected

---

## Phase 20 — Config Drift & Dependency UI *(Agent 2)*

**Goal:** Visualize configuration drift and dependency health.

### Deliverables
1. **Config Drift Page (`/run/{runId}/config-drift`)**
   - Environment comparison matrix: keys × environments with status (present/missing/differs)
   - Missing key highlights (red cells)
   - Click cell → show value diff (redacted if sensitive)

2. **Dependencies Page (`/run/{runId}/dependencies`)**
   - Package table: name, current version, latest version, pinned (yes/no), CVE count, EOL status
   - Sort by: CVE severity, staleness
   - CVE details expandable per package
   - EOL framework warnings (prominent banner)

3. **Navigation Update**
   - Add "Config Drift" and "Dependencies" to navigation

### Acceptance Criteria
- Config drift matrix renders correctly
- Dependency table shows CVE and EOL status
- Filters and sorting work

---

## Phase 21 — Error Handling & Resilience Scanners *(Agent 1)*

**Goal:** Detect error handling anti-patterns and missing resilience policies.

### Deliverables

#### A. Error Handling Coverage Scanner
1. **Analyzer: `ReliabilityIQ.Analyzers.ErrorHandling`**
2. **Detection** (AST-based where possible):
   - C#: empty `catch` blocks, `catch (Exception)` without rethrow/log, `catch` that only sets a bool
   - Python: bare `except:`, `except Exception: pass`
   - PowerShell: empty `catch` blocks
   - Rust: `.unwrap()` in non-test code, `.expect()` with non-descriptive messages
   - C++: empty `catch(...)` blocks
3. **Rules**:
   - `error.empty_catch` — catch block with no meaningful handling
   - `error.bare_except` — untyped exception catch
   - `error.swallowed_exception` — exception caught and ignored
   - `error.rust_unwrap` — `.unwrap()` in production code

#### B. Resilience Scanner
1. **Analyzer: `ReliabilityIQ.Analyzers.Resilience`**
2. **Detection**:
   - HTTP client calls without timeout configuration
   - Database calls without timeout
   - Network calls without retry policy (Polly for C#, tenacity for Python)
   - Unbounded retry loops (retry without max count or exponential backoff)
   - Missing circuit breaker on external service calls
3. **Rules**:
   - `resilience.missing_timeout` — network/DB call without timeout
   - `resilience.missing_retry` — external call without retry policy
   - `resilience.unbounded_retry` — retry without limit
   - `resilience.no_circuit_breaker` — high-frequency external calls without circuit breaker

4. **CLI**: `reliabilityiq scan error-handling` and `reliabilityiq scan resilience`

5. **Tests**
   - Fixtures per language with error handling anti-patterns
   - Fixture with HTTP calls missing timeouts/retries

### Acceptance Criteria
- Empty catch blocks detected across all languages
- Rust unwrap() in non-test code flagged
- Missing timeout/retry on network calls detected
- Unbounded retries flagged

---

## Phase 22 — Error Handling & Resilience UI *(Agent 2)*

**Goal:** Present error handling and resilience findings.

### Deliverables
1. **Error Handling Page (`/run/{runId}/error-handling`)**
   - Findings table for `error.*` rules
   - Anti-pattern categorization: empty catch / bare except / swallowed / unwrap
   - Per-module coverage summary (files with issues vs total files)

2. **Resilience Page (`/run/{runId}/resilience`)**
   - Findings table for `resilience.*` rules
   - "Network callsite inventory": list of detected external calls with policy status (has timeout? has retry?)
   - Missing policy summary by module

3. **Dashboard Integration**
   - Error handling and resilience counts added to dashboard cards
   - Included in composite risk if weight configured

### Acceptance Criteria
- Error handling findings displayed with categorization
- Resilience findings show network callsite inventory
- Dashboard integration works

---

## Phase 23 — Structural Analysis Scanners (Circular Deps + Complexity) *(Agent 1)*

**Goal:** Detect circular dependencies and compute cyclomatic complexity.

### Deliverables

#### A. Circular Dependency Scanner
1. **Analyzer: `ReliabilityIQ.Analyzers.Structure`**
2. **Detection**:
   - C#: parse `<ProjectReference>` in `.csproj` files → build directed graph → detect cycles (Tarjan's algorithm)
   - Rust: parse `Cargo.toml` workspace member dependencies → detect cycles
   - Python: parse `import` statements → build module graph → detect cycles (best-effort, not perfect)
3. **Rules**:
   - `structure.circular_dependency` — project/crate/module cycle detected (list cycle path)
4. **Output**: cycle path in finding metadata

#### B. Cyclomatic Complexity Scanner
1. **Detection** (AST-based):
   - C# (Roslyn): count branch points per method (if/else, switch cases, &&, ||, catch, ternary, null-coalescing)
   - Python (AST): count per function
   - Rust (Tree-sitter): count per function
2. **Rules**:
   - `structure.high_complexity` — function with complexity > threshold (default: 15)
   - `structure.extreme_complexity` — function with complexity > threshold (default: 30)
3. **Correlation**: flag high-complexity functions in high-churn files (cross-reference with git metrics) → highest priority refactor candidates
4. **CLI**: `reliabilityiq scan structure`

5. **Tests**
   - Circular dependency: fixture with known project reference cycles
   - Complexity: fixture with functions of varying complexity

### Acceptance Criteria
- Circular dependencies detected in C# project references and Rust crate graphs
- Cyclomatic complexity computed for C#, Python, Rust functions
- High-complexity + high-churn correlation identified
- Cycle paths included in findings

---

## Phase 24 — Structural Analysis UI *(Agent 2)*

**Goal:** Visualize dependency graphs and complexity metrics.

### Deliverables
1. **Dependency Graph Page (`/run/{runId}/dependencies/graph`)**
   - Interactive force-directed graph (D3.js): nodes = projects/crates, edges = references
   - Circular dependencies highlighted in red with animated edges
   - Click node → show project details + finding count
   - Zoom/pan controls

2. **Complexity Page (`/run/{runId}/complexity`)**
   - Table: function name, file, complexity score, churn score, combined priority
   - Sort by: complexity, combined priority (complexity × churn)
   - "Refactor candidates" = top 20 by combined priority
   - Complexity distribution histogram

3. **Heatmap Integration**
   - Add "Complexity" as a metric option in the heatmap

### Acceptance Criteria
- Dependency graph renders with cycle highlighting
- Complexity table shows function-level metrics with churn correlation
- Refactor candidate ranking works
- Heatmap supports complexity metric

---

## Phase 25 — Code Hygiene Scanners (Feature Flags + TODO/FIXME + Async Anti-patterns) *(Agent 1)*

**Goal:** Detect stale feature flags, admitted tech debt, and thread safety / async anti-patterns.

### Deliverables

#### A. Feature Flag Hygiene Scanner
1. **Detection**:
   - Scan for common feature flag patterns: `IsEnabled("flag_name")`, `feature_flag["..."]`, `#if FEATURE_...`, `@feature_flag(...)` decorators
   - Configurable flag API patterns in YAML
   - Count references per flag name
   - Cross-reference with Git history: flag introduced > N days ago with no recent changes → "stale flag candidate"
2. **Rules**: `hygiene.stale_feature_flag`, `hygiene.dead_feature_flag` (zero references outside definition)

#### B. TODO/FIXME Tech Debt Scanner
1. **Detection**:
   - Regex for comments: `TODO`, `FIXME`, `HACK`, `XXX`, `WORKAROUND`, `TEMP` (configurable keywords)
   - Git blame integration: determine age of each TODO comment
   - Priority classification: old TODOs (> 180 days) ranked higher
2. **Rules**: `hygiene.todo_old`, `hygiene.fixme`, `hygiene.hack`

#### C. Thread Safety / Async Anti-patterns Scanner
1. **Detection** (AST-based):
   - C#: `.Result`, `.Wait()`, `GetAwaiter().GetResult()` on `Task`/`ValueTask` in async methods
   - C#: `async void` methods (except event handlers)
   - Python: `asyncio.run()` inside already-running event loop
   - Rust: `block_on()` in async context
   - C#: `lock` on `this` or `typeof(...)` or string literals
2. **Rules**: `async.sync_over_async`, `async.async_void`, `async.nested_runtime`, `thread.bad_lock_target`

3. **CLI**: `reliabilityiq scan hygiene`

4. **Tests**: Fixtures for each pattern per language

### Acceptance Criteria
- Stale feature flags detected with age analysis
- TODO/FIXME comments found with git blame age
- Async anti-patterns detected in C#, Python, Rust
- Thread safety issues (bad lock targets) detected

---

## Phase 26 — Code Hygiene UI *(Agent 2)*

**Goal:** Present feature flags, tech debt, and async anti-pattern findings.

### Deliverables
1. **Code Hygiene Page (`/run/{runId}/hygiene`)**
   - Three tabs: Feature Flags | Tech Debt | Async/Thread Safety
   - **Feature Flags tab**: flag name, reference count, age (days), stale/dead badge, locations
   - **Tech Debt tab**: TODO/FIXME table sorted by age, keyword filter, git blame author
   - **Async tab**: anti-pattern findings with pattern type, file, line, explanation

2. **Tech Debt Aging Chart**
   - Bar chart: TODO count by age bucket (< 30d, 30–90d, 90–180d, 180d–1y, > 1y)

3. **Dashboard Integration**
   - Tech debt count and async issue count added to dashboard

### Acceptance Criteria
- All three hygiene tabs render with correct data
- Tech debt aging chart displays
- Dashboard integration works

---

## Phase 27 — Observability & Ownership Scanners *(Agent 1)*

**Goal:** Assess observability readiness and CODEOWNERS coverage.

### Deliverables

#### A. Observability Readiness Scanner
1. **Detection**:
   - Scan for logging framework usage: `ILogger`, `log4net`, `Serilog`, Python `logging`, Rust `log`/`tracing`
   - Identify "dark code paths": functions/methods with no logging, metrics, or tracing calls (AST-based for C# and Python)
   - Missing correlation ID patterns: HTTP handlers without correlation ID propagation
   - Exception swallowing without logging (overlap with error handling — cross-reference, don't duplicate)
2. **Rules**: `observability.dark_path`, `observability.no_correlation_id`, `observability.exception_no_log`

#### B. CODEOWNERS Coverage Scanner
1. **Detection**:
   - Parse `CODEOWNERS` / `.github/CODEOWNERS` file
   - Identify unowned paths (no CODEOWNERS match)
   - Cross-reference with incident density and churn: unowned + high-incident = critical gap
   - Stale ownership: owner (GitHub username) hasn't committed to owned paths in N days (configurable)
2. **Rules**: `ownership.unowned_path`, `ownership.stale_owner`, `ownership.unowned_high_risk`

3. **CLI**: `reliabilityiq scan observability` and `reliabilityiq scan ownership`

4. **Tests**: Fixtures with dark code paths and CODEOWNERS files with gaps

### Acceptance Criteria
- Dark code paths identified for C# and Python
- CODEOWNERS parsed and unowned paths flagged
- Stale ownership detected via git history cross-reference
- High-risk unowned paths (high incident density) flagged with elevated severity

---

## Phase 28 — Observability & Ownership UI *(Agent 2)*

**Goal:** Visualize observability gaps and ownership coverage.

### Deliverables
1. **Observability Page (`/run/{runId}/observability`)**
   - Dark path findings table: function, file, line, call count estimate
   - Observability coverage summary: % of functions with logging/tracing
   - Missing correlation ID findings

2. **Ownership Page (`/run/{runId}/ownership`)**
   - CODEOWNERS coverage map: directory tree with owned/unowned coloring
   - Unowned paths table with risk score (incident density, churn)
   - Stale owner table: owner, owned paths, last commit date
   - "Ownership gaps × incident density" correlation view

3. **Heatmap Integration**
   - Add "Ownership Coverage" as a metric in heatmap

### Acceptance Criteria
- Observability page shows coverage summary and dark paths
- Ownership map renders with correct owned/unowned status
- Stale owners displayed with last activity date
- Heatmap supports ownership metric

---

## Phase 29 — Build Reproducibility & Test Health Scanners *(Agent 1)*

**Goal:** Detect build reproducibility risks and test health signals.

### Deliverables

#### A. Build Reproducibility Scanner
1. **Detection**:
   - Non-pinned SDK versions in `global.json`, `rust-toolchain.toml`, `.python-version`
   - Floating tool versions in CI pipelines (`dotnet-version: 8.x` instead of `8.0.401`)
   - Ambiguous build steps (e.g., `dotnet build` without specifying project/solution in multi-project repos)
   - Inconsistent SDK versions across projects in same repo
   - Non-pinned Docker base images (`:latest` or no tag)
2. **Rules**: `build.unpinned_sdk`, `build.floating_tool`, `build.ambiguous_step`, `build.inconsistent_sdk`, `build.unpinned_docker`

#### B. Test Health Scanner
1. **Detection**:
   - Test-to-code churn mismatch: source files with high churn but corresponding test files with low/no churn
   - Test file detection: `*Tests.cs`, `*_test.py`, `*_test.rs`, `test_*.py`, `*.Tests.csproj`, etc.
   - Untested modules: source directories with no corresponding test files
   - Test file staleness: test files not updated when source changes
2. **Correlation with churn**: cross-reference git file metrics
3. **Rules**: `test.churn_mismatch`, `test.untested_module`, `test.stale_tests`

3. **CLI**: `reliabilityiq scan build` and `reliabilityiq scan test-health`

4. **Tests**: Fixtures with pinned/unpinned SDK versions, test/source churn mismatches

### Acceptance Criteria
- Unpinned SDKs and tools detected across project types
- Inconsistent SDK versions flagged
- Test-to-code churn mismatch identified
- Untested modules detected

---

## Phase 30 — Build & Test Health UI + Final Polish *(Agent 2)*

**Goal:** Present build and test health findings, and deliver final UI polish across the entire application.

### Deliverables
1. **Build Reproducibility Page (`/run/{runId}/build`)**
   - Findings table for `build.*` rules
   - SDK version consistency matrix: project × SDK version
   - Pinning recommendations with specific version suggestions

2. **Test Health Page (`/run/{runId}/test-health`)**
   - Churn mismatch table: source file, source churn, test file (if exists), test churn, mismatch score
   - Untested modules list with risk score
   - Test coverage heatmap overlay (test presence, not line coverage)

3. **Final Dashboard Polish**
   - Unified dashboard with all scanner categories as cards/sections
   - Overall repo health score (composite across all dimensions)
   - "Quick wins" panel: top 5 easiest high-impact fixes across all scanners
   - "Critical alerts" banner: Error-severity findings from secrets + portability
   - Responsive design audit and fixes

4. **Navigation Finalization**
   - Organized sidebar with categories:
     - **Overview**: Dashboard, Trends, Compare
     - **Code Quality**: Findings, Magic Strings, Complexity, Hygiene
     - **Reliability**: Error Handling, Resilience, Async
     - **Portability**: Portability, Config Drift, Deploy
     - **Operations**: Churn, Incidents, Ownership, Observability
     - **Supply Chain**: Dependencies, Secrets, Build, Test Health
   - Collapsible sidebar sections
   - Breadcrumb navigation

5. **Heatmap Final Enhancement**
   - All metrics available: composite risk, portability, churn, staleness, incident density, complexity, ownership, test coverage
   - Save/load heatmap configuration (selected metric, zoom level)

6. **Documentation Page (`/help`)**
   - In-app documentation: rule descriptions, severity definitions, scoring explanation
   - Link to configuration guide

7. **Performance Audit**
   - Optimize slow queries (add missing indices if needed)
   - Lazy loading for large datasets
   - Pagination everywhere

### Acceptance Criteria
- All scanner categories have dedicated pages and dashboard integration
- Unified dashboard provides repo health overview with quick wins
- Navigation is organized and consistent
- Heatmap supports all metrics
- Performance acceptable for repos with 100K+ findings
- Help/documentation page exists

---

## Summary Table

| Phase | Agent | Feature | Key Scanner/UI |
|-------|-------|---------|----------------|
| 1 | 1 (Scanner) | **MVP Scanner Foundation** | Regex portability scanner, SQLite schema, CLI, file classification |
| 2 | 2 (Web) | **MVP Web Foundation** | Runs list, findings table, run summary |
| 3 | 1 (Scanner) | **AST-Enhanced Portability** | Roslyn, Tree-sitter, PowerShell AST, suppressions |
| 4 | 2 (Web) | **Enhanced Findings UI** | File detail, remediation guidance, confidence filters |
| 5 | 1 (Scanner) | **Magic Strings** | Extraction, scoring, ranking, entropy filtering |
| 6 | 2 (Web) | **Magic Strings UI** | Ranked opportunities, occurrence exploration |
| 7 | 1 (Scanner) | **Git Churn & Staleness** | LibGit2Sharp, Gini coefficient, module aggregation |
| 8 | 2 (Web) | **Heatmap & Churn UI** | D3.js heatmap, treemap, churn tables |
| 9 | 1 (Scanner) | **EV2 & ADO Artifacts** | Structure-aware YAML/JSON parsing, deployment rules |
| 10 | 2 (Web) | **Deployment Artifact UI** | Artifact findings, deployment risk summary |
| 11 | 1 (Scanner) | **Rule Configuration System** | YAML config, merge precedence, validation, custom rules |
| 12 | 2 (Web) | **Rule Management & Export** | Rules page, suppressions, SARIF/CSV/JSON/HTML export |
| 13 | 1 (Scanner) | **Incident Association** | Providers, linkers, commit regex, incident density |
| 14 | 2 (Web) | **Incident & Composite Risk UI** | Correlation scatter plot, risk dashboard |
| 15 | 1 (Scanner) | **Incremental Scanning & Perf** | Scan cache, channel parallelism, bulk inserts |
| 16 | 2 (Web) | **Run Trends & Performance UI** | Trend charts, enhanced comparison, perf breakdown |
| 17 | 1 (Scanner) | **Secrets & Credentials** | Entropy + pattern detection, secure storage |
| 18 | 2 (Web) | **Secrets UI** | Secure display, remediation guidance |
| 19 | 1 (Scanner) | **Config Drift & Dependencies** | Environment comparison, CVE lookup, EOL detection |
| 20 | 2 (Web) | **Config Drift & Dependency UI** | Comparison matrix, package table with CVEs |
| 21 | 1 (Scanner) | **Error Handling & Resilience** | Empty catch, unwrap, missing timeouts/retries |
| 22 | 2 (Web) | **Error Handling & Resilience UI** | Anti-pattern categories, callsite inventory |
| 23 | 1 (Scanner) | **Structural Analysis** | Circular deps (Tarjan's), cyclomatic complexity |
| 24 | 2 (Web) | **Structural Analysis UI** | D3.js dependency graph, complexity × churn ranking |
| 25 | 1 (Scanner) | **Code Hygiene** | Feature flags, TODO/FIXME aging, async anti-patterns |
| 26 | 2 (Web) | **Code Hygiene UI** | Tabbed hygiene view, tech debt aging chart |
| 27 | 1 (Scanner) | **Observability & Ownership** | Dark paths, CODEOWNERS parsing, stale owners |
| 28 | 2 (Web) | **Observability & Ownership UI** | Coverage maps, ownership gaps × incidents |
| 29 | 1 (Scanner) | **Build & Test Health** | SDK pinning, test-code churn mismatch |
| 30 | 2 (Web) | **Final Polish** | Unified dashboard, all heatmap metrics, navigation, docs |