## High-priority merges (add to main design)

### 1) Config + rules layout with precedence (Agent 3) — **add**
Your current doc has a single YAML sketch. Agent 3’s **`.reliabilityiq/` folder structure**, split-by-scanner rule files, allowlists, and **explicit merge order** is a big usability win and makes “org defaults + team overrides + CI overrides” straightforward.

**Add to Design Doc (supersedes §6.2 Rule configuration format/shape):**
- Standard config layout:
  - `.reliabilityiq/config.yaml`
  - `.reliabilityiq/rules/{portability,magic-strings,churn,incidents,deploy-ev2,deploy-ado}.yaml`
  - `.reliabilityiq/rules/custom/*.yaml`
  - `.reliabilityiq/allowlists/*.yaml`
- Precedence chain: built-in defaults ← repo rules ← custom overrides ← CLI flags
- Add `rules validate` command (Agent 3) to prevent broken configs in CI.

**Why better:** it operationalizes “extensible rules” and avoids a monolithic config file that becomes unmaintainable.

---

### 2) CLI command tree + CI semantics (Agent 3) — **add**
Your CLI section is good but a bit “flat.” Agent 3’s command tree is clearer and adds **CI-friendly behaviors** (fail-on severity, exit codes), plus dedicated scanner subcommands.

**Add to Design Doc (§14 CLI Design):**
- Command structure:
  - `scan all|portability|magic-strings|churn|incidents|deploy`
  - `report table|heatmap|export`
  - `rules list|validate|init`
  - `server start`
- Add:
  - `--fail-on {error|warning|info}` and **exit codes** (0/1/2)
  - Export formats: **CSV / JSON / SARIF** (SARIF is especially useful for code scanning ecosystems)

**Why better:** makes the tool immediately CI-usable and discoverable.

---

### 3) Magic-string aggregation (Agent 3) + stronger heuristics (Agent 3) — **add**
Your magic string section is good conceptually, but it’s missing a key UX detail: **grouping identical literals into one finding with many locations**.

**Add to Design Doc (§8 Magic Strings):**
- Output model: one “magic string candidate” per unique normalized literal, with:
  - count, top locations, and a “show all occurrences” expansion in UI
- Incorporate Agent 3’s layered heuristic stack (exclude → detect → score → threshold)

**Why better:** reduces “finding spam” and makes results actionable.

---

### 4) `.gitignore` as an input to file exclusion (Agent 2) — **add**
You already have classification + default excludes; Agent 2 adds a very practical rule:

**Add to Design Doc (§5 Repository Discovery & File Classification and §9 Noise reduction):**
- Treat `.gitignore` patterns as **implicit excludes** by default (configurable to disable)

**Why better:** matches developer expectations and dramatically reduces noise on real repos.

---

### 5) Ownership concentration / “bus factor” metric (Agent 3 + Agent 2) — **add**
You already store `unique_authors_last_365_days`. Agent 3’s **ownership concentration metric** (e.g., Gini coefficient) plus Agent 2’s “author inactive” concept makes this much more meaningful.

**Add to Design Doc (§9 Metrics + §13 Scoring):**
- Add `ownership_concentration` (e.g., Gini) per file/module
- Optional rule: flag “high concentration + no commits by that author in last X days”

**Why better:** “unique authors” alone misses single-owner risk patterns.

---

### 6) Concrete EV2/ADO reliability lint rules (Agent 3 + Agent 2) — **add**
Your artifact scanning section is currently mostly portability-focused. Agent 2/3 propose **deployment safety** checks that align strongly with “ReliabilityIQ” (bake time, gates, health checks, single-region, etc.).

**Add to Design Doc (§11 EV2 + ADO Artifact Scanning):**
- EV2 checks like:
  - zero bake time / `WaitDuration` = `PT0S`
  - missing health checks after deploy steps
  - single-region bindings (no failover)
  - secrets embedded vs KeyVault references
- ADO checks like:
  - production stage missing approvals/gates (where applicable)
  - use of container `latest` tags instead of pinned digest/version
  - inline secrets in YAML

**Why better:** turns artifact scanning into “reliability guardrails,” not only portability pattern matching.

---

### 7) Parallelism + SQLite write strategy (Agent 3) — **add**
You mention performance and incremental scans, but not a concrete execution model.

**Add to Design Doc (§17 Performance):**
- Pipeline: file enumeration → worker pool → findings batching → **single SQLite writer**
- Bulk insert strategy (batching) to avoid SQLite write overhead
- Note: Tree-sitter parsers are not thread-safe; “one parser per worker”

**Why better:** avoids performance traps and makes scans scale to large repos.

---

## Suggestions that should **supersede** parts of the current design

### A) Findings schema should include a flexible `metadata` JSON column (Agent 3) — **supersede/upgrade §12**
Your schema is normalized and fine, but it will fight you as soon as you add scanner-specific fields (entropy, endpoint type, incident TTM, AST context, etc.).

**Change to make (keep your tables, but upgrade `findings`):**
- Add `metadata TEXT` (JSON) to `findings`
- Consider storing `file_path` directly in `findings` (Agent 3) even if you keep a `files` table, because it simplifies many queries and makes the DB robust if file IDs change across runs.

**Why this should supersede:** it prevents schema churn and keeps scanners decoupled.

---

### B) Heatmap visualization should be a treemap option (Agent 2) + composite risk weights (Agent 3) — **supersede/upgrade §13**
Your “directory tree heatmap intensity” is good, but a **treemap (WinDirStat-like)** is often more intuitive for “where is the risk concentrated.”

**Change to make (§13 + §15):**
- Offer **two views**:
  1) directory-tree heat coloring (your current plan)
  2) treemap where **size = LOC or file size**, color = risk
- Add composite risk score weighting (Agent 3) as a configurable UI metric (even if you keep simpler single-metric modes)

**Why better:** quickly shows both “risk” and “footprint,” not just intensity.

---

## Suggestions to adopt with modifications (not as-written)

### 1) “Plugin architecture everywhere” (Agent 2) — **merge, but don’t force it in MVP**
Agent 2 pushes plugin-first via `IScanner`. Your doc already has:
- declarative rules first
- plugins later/optional

**Recommended merge:**
- Keep MVP with built-in analyzers, but define stable internal interfaces (`IAnalyzer`/`IScanner`) now so plugins can be added later without refactoring.
- Avoid making plugins a hard dependency for core scans in Phase 1.

---

### 2) Tree-sitter for *all* non-C# languages (Agent 3) — **partially merge**
Agent 3 suggests Tree-sitter for C++/Rust/PowerShell/Python. This is attractive for uniformity, but there are tradeoffs:
- PowerShell already has a strong native AST (often more semantically useful than Tree-sitter)
- Python’s built-in `ast` is easy and accurate

**Recommended merge:**
- Use Tree-sitter primarily for **C++ and Rust** early (where native parsing integration is harder).
- Keep **PowerShell AST** and **Python `ast`** as first-class paths, with Tree-sitter as optional fallback if you want one unified extraction pipeline later.

---

### 3) Entropy-based “Magic string & secret scanner” (Agent 2) — **split into two scanners**
Entropy is great for secrets, but it muddies “magic strings” (low entropy config identifiers are the magic-string target; high entropy is “secret-like”).

**Recommended change:**
- Keep Magic Strings as you designed (rank implicit contracts)
- Add a separate **Secrets/Credential Hygiene** scanner (you already listed it in “Freestyle Goal”)
- Reuse entropy logic there, plus known key patterns

---

## Concrete “patch list” (what to edit where)

1) **§6 Scanner Framework & Rule System**
- Add `.reliabilityiq/` rule file layout, allowlists, precedence, `rules validate`.

2) **§8 Magic Strings**
- Add aggregation of literals → one finding with multiple locations.
- Add layered heuristic stack + scoring threshold.

3) **§9 Git Churn/Staleness**
- Add `.gitignore`-aware excludes.
- Add ownership concentration metric (Gini) and optional “inactive owner” rule.

4) **§11 EV2 + ADO**
- Add explicit reliability lint rules (bake time, health checks, latest tags, secrets in YAML, etc.).

5) **§12 SQLite Data Model**
- Add `metadata` JSON to findings (and optionally store `file_path` redundantly).
- Consider run IDs as ULIDs/strings (Agent 3) for easier merging across machines.

6) **§14 CLI**
- Adopt subcommand structure, `--fail-on`, exit codes, SARIF export.

7) **§15 Web UI**
- Add treemap visualization option and “Incidents vs Churn” report view.
- (Optional) add CODEOWNERS-derived “assigned team” column (Agent 2).

8) **§17 Performance**
- Add worker/ pipeline + single SQLite writer + batching.
