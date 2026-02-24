# Scanner Readiness Report

Date: 2026-02-24

**Summary**
The scanners are generally wired up, but there are a few correctness gaps that can produce empty or misleading results. The most severe issue is in `GitHistoryAnalyzer`: the static cache key ignores the file set, so per-file analysis can return results for the wrong file and can poison subsequent runs. There are also several areas where scanners quietly skip files (config drift) or return low-fidelity locations (artifact JSON), plus missing suppression support for regex-based scanners.

**Critical**
1. `GitHistoryAnalyzer` cache key ignores the analyzed file set, causing incorrect or missing results for per-file analysis and any subsequent scan using the same repo/options.
   - `AnalyzeAsync` calls `AnalyzeRepository` with a single file, but the shared cache key only includes repo+options. After the first call, subsequent files reuse the cached result from the first file, so findings are wrong or empty. This also risks poisoning any later full-repo analysis that uses the same cache key. (`ReliabilityIQ.Analyzers.GitHistory/GitHistoryAnalyzer.cs:12,55-63,453-458`)

**High**
1. Config drift scanner never considers `.toml`, `.ini`, or `.config` files even though the analyzer’s default pattern includes them.
   - `ConfigDriftAnalyzer`’s default pattern explicitly allows `toml|ini|config` extensions, but `ConfigDriftScanRunner.IsConfigFile` filters strictly to JSON/YAML. This makes the scanner silently skip those formats, yielding false negatives. (`ReliabilityIQ.Analyzers.ConfigDrift/ConfigDriftAnalyzer.cs:20-22`, `ReliabilityIQ.Cli/ConfigDriftScanRunner.cs:133-146`)

**Medium**
1. Artifact scan results for JSON files always report line/column as `1:1`, which is misleading for remediation and suppressions.
   - `CollectJsonScalars` sets line/column to `1,1` for every scalar, so findings point to the wrong location. YAML has real line info, JSON does not. (`ReliabilityIQ.Analyzers.Artifacts/ArtifactAnalyzer.cs:362-393`)
2. Regex-based portability findings and custom regex rules do not honor inline suppressions or the suppressions file.
   - The regex analyzer and custom regex evaluator never load `FileSuppressionSet` nor parse inline suppressions, so suppressions configured in `reliabilityiq.suppressions.yaml` have no effect on these findings. (`ReliabilityIQ.Analyzers.Regex/PortabilityRegexAnalyzer.cs:103-145`, `ReliabilityIQ.Core/Configuration/CustomRegexRuleEvaluator.cs:9-55`, `ReliabilityIQ.Core/Portability/FileSuppressionSet.cs:16-78`)
3. Dependency vulnerability and “latest version” checks silently fall back to empty results on network/API errors, making scans appear clean when OSV/registry calls fail.
   - `HttpOsvClient` swallows non-success responses and exceptions, returning `[]`/`null` without a warning. This can mask outages or auth/proxy issues as “no vulnerabilities”. (`ReliabilityIQ.Analyzers.Dependencies/HttpOsvClient.cs:38-66,79-93`)

**Low**
1. Tree-sitter analyzer is heuristic-only even when the native parser is available, and emits an “unavailable” info finding per file when it is not.
   - The analyzer never invokes a native parse; it scans line-by-line with regexes. That is a valid fallback, but the analyzer name and metadata imply tree-sitter use while `nativeAstUsed` is always `false`. Also, when the native lib is missing, every file produces a redundant info finding. (`ReliabilityIQ.Analyzers.TreeSitter/TreeSitterPortabilityAnalyzer.cs:51-79,82-134`)
2. Hygiene TODO detection may mis-classify non-comment lines because `CCommentTokenRegex` matches any `*` character.
   - The comment extractor treats `*` as a comment token, so any line containing `*` is eligible for TODO scanning, which can include non-comment code. This is a low-probability false-positive vector but easy to tighten. (`ReliabilityIQ.Analyzers.Hygiene/HygieneAnalyzer.cs:63-65,748-749`)

**Notes / Test Gaps**
1. No tests currently appear to cover `GitHistoryAnalyzer.AnalyzeAsync` across multiple files or cache reuse behavior. Consider adding a regression test to validate per-file results are independent and that cache keys include the file set.
2. No tests appear to validate Config Drift coverage of TOML/INI/config formats at the CLI runner level.
3. Artifact JSON line/column fidelity is not covered by tests; this could be validated with a fixture JSON file and asserted positions.

