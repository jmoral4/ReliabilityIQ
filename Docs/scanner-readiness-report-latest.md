# Scanner Readiness Report (Latest)

## Scope
Reviewed scanner/analyzer code paths and scanner-focused tests for portability, deploy artifacts, config drift, dependencies, hygiene, magic strings, and git-history surfaces.

## Executive Summary
Current scanner readiness is **Medium-Low**. Core scanner functionality exists, but several paths can produce misleading output, silent false negatives, or operational instability.

## Findings

### 1) Scanner persistence layer keeps SQLite file locked (operational breakage)
- **Severity:** High
- **Evidence:** `ReliabilityIQ.Core\Persistence\SqliteResultsWriter.cs:27` enables `Pooling = true`; repeated scanner tests fail to clean up DB files with `The process cannot access the file ... because it is being used by another process`.
- **Observed in tests:** `Phase3PortabilityAnalyzerTests`, `Phase7GitHistoryTests`, `Phase9ArtifactScannerTests`, `Phase19ConfigDriftAndDependenciesTests`, `Phase25HygieneScannerTests` (test run output).
- **Risk:** Scanner runs/tests can leave databases locked, causing intermittent failures and reducing trust in scanner reliability.
- **Recommendation:** Disable pooling for local scanner DB writes (or aggressively clear pools/close handles) and add a regression test that deletes DB immediately after scan completion.

### 2) Tree-sitter scanner is heuristic-only, not true AST analysis
- **Severity:** High
- **Evidence:** `ReliabilityIQ.Analyzers.TreeSitter\TreeSitterPortabilityAnalyzer.cs:82-177` scans per-line with regex for literals/ports; `BuildMetadata` hardcodes `"nativeAstUsed":false` and engine `"tree-sitter-heuristic"` (`:232-235`).
- **Observed in tests:** `Phase3PortabilityAnalyzerTests.ScanRunner_RoutesToAstAndRegexAnalyzers` expects tree-sitter engine presence and currently fails.
- **Risk:** Higher false positives/negatives than AST-level analysis, while scanner naming can imply stronger guarantees.
- **Recommendation:** Either implement native parse-tree traversal or explicitly downgrade/rename scanner mode in UX/docs as heuristic portability scanning.

### 3) Artifact JSON findings use synthetic location (line/column = 1,1)
- **Severity:** Medium
- **Evidence:** `ReliabilityIQ.Analyzers.Artifacts\ArtifactAnalyzer.cs:382-393` (`CollectJsonScalars`) assigns line/column `1,1` to all JSON scalar findings.
- **Risk:** Findings appear precise but point to incorrect locations, slowing remediation and creating misleading output quality.
- **Recommendation:** Track JSON token positions (or clearly mark location as unavailable) instead of fixed `1,1`.

### 4) Dependency vulnerability/network failures are silently treated as “no issues”
- **Severity:** High
- **Evidence:** `ReliabilityIQ.Analyzers.Dependencies\HttpOsvClient.cs:63-66` catches all and returns `[]`; `:90-93` catches all and returns `null` for latest version.
- **Risk:** Transient/network/provider failures look identical to clean dependency results (false negatives without warning).
- **Recommendation:** Emit explicit scanner health/degraded findings when advisory/version lookups fail.

### 5) Config drift parser failures are silently dropped
- **Severity:** Medium
- **Evidence:** `ReliabilityIQ.Analyzers.ConfigDrift\ConfigDriftAnalyzer.cs:340-343` catches parse exceptions and returns `false`; caller (`:53-56`) skips file with no finding.
- **Risk:** Broken config files are excluded from drift analysis without visibility, causing hidden coverage gaps.
- **Recommendation:** Emit parse-error findings (similar to deploy scanner behavior) so users know drift analysis was incomplete.

### 6) Python dependency parsing misses common pyproject/poetry forms
- **Severity:** Medium
- **Evidence:** `ReliabilityIQ.Analyzers.Dependencies\DependencyFileParser.cs:282-332` only parses array-style `dependencies = [ ... ]`; no handling for common table/object styles like `[tool.poetry.dependencies]` key/value entries.
- **Risk:** Dependency scanner under-reports packages for many Python repositories.
- **Recommendation:** Support PEP 621/Poetry dependency table formats and add fixture tests for those manifests.

### 7) Artifact classifier has broad path marker that can over-classify files
- **Severity:** Medium
- **Evidence:** `ReliabilityIQ.Analyzers.Artifacts\ArtifactClassifier.cs:21-28` includes default ADO marker `"/build/"`.
- **Risk:** Non-pipeline files in build-related directories may be scanned as ADO artifacts, increasing false positives.
- **Recommendation:** Narrow marker defaults (e.g., explicit pipeline filenames/directories) and rely more on content signatures.

## Validation Performed
- Reviewed scanner/analyzer implementation code across analyzer projects and scan runners.
- Ran scanner-focused tests; observed failures including metadata mismatch and repeated DB-lock cleanup failures.

## Priority Remediation Order
1. Fix SQLite lock/pooling behavior in result writer.
2. Make tree-sitter scanner behavior explicit or implement true AST extraction.
3. Add degraded/parse-error findings for dependency/config drift failures.
4. Improve JSON location fidelity and Python dependency parser coverage.
5. Tighten artifact classification markers.
