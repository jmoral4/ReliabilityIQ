# Proposal 2: Git Churn Scanning Performance Optimization

## Current Architecture

The scanner in `GitHistoryAnalyzer.cs` uses **LibGit2Sharp** (not shell git) and processes
commits sequentially on a single thread. For each commit in the time window it computes
**two full diffs** (TreeChanges + Patch), then runs an **N+1 per-file log query** at the end.

Key source files:
- `ReliabilityIQ.Analyzers.GitHistory/GitHistoryAnalyzer.cs` (551 lines) — main analyzer
- `ReliabilityIQ.Analyzers.GitHistory/GitHistoryAnalysisOptions.cs` — configurable options
- `ReliabilityIQ.Analyzers.GitHistory/GitHistoryMath.cs` — Gini, churn score, stale score formulas
- `ReliabilityIQ.Cli/ChurnScanRunner.cs` (312 lines) — CLI runner

---

## Identified Bottlenecks

| # | Bottleneck | Location | Severity |
|---|-----------|----------|----------|
| 1 | Dual diff per commit (TreeChanges + Patch) | Lines 74-84 | Critical |
| 2 | N+1 per-file log query | Line 128 | Critical |
| 3 | Entirely single-threaded | Whole method | Significant |
| 4 | Full commit list materialized via `.ToList()` | Line 64 | Minor |
| 5 | `FindPatchEntry` linear scan per file per commit | Lines 299-314 | Moderate |
| 6 | Cache key opens redundant `Repository` instance | Lines 292-297 | Minor |

---

## Proposed Options

### Option 1: Eliminate the N+1 Per-File Log Query
**Effort**: Small | **Impact**: High

Line 128 runs `repository.Commits.QueryBy(filePath).Take(2)` for **every discovered file**
solely to detect "never changed since import." This data is already available from Phase 1's
commit iteration — files with `Commits365d == 1` are single-commit files. Derive it from the
accumulated data instead of re-querying.

Eliminates thousands of individual git log walks.

### Option 2: Drop the Redundant TreeChanges Diff
**Effort**: Small | **Impact**: High

Every commit computes **both** `TreeChanges` (file list) and `Patch` (full diff with line
counts). `Patch` already contains file change info. Either:
- Use only `Patch` (it includes everything TreeChanges provides), or
- Use only `TreeChanges` and defer line counting to a batch step

Cuts per-commit diff work roughly in half.

### Option 3: Make Patch (Diff Stats) Lazy or Optional
**Effort**: Config change | **Impact**: Medium (~50% if disabled)

`IncludeDiffStats` defaults to `true`. If line-add/remove counts are not critical, flipping
this to `false` skips the expensive `Patch` computation entirely. Alternatively, compute
`Patch` only for files that exceed a churn-commit threshold (e.g., > 5 commits).

### Option 4: Parallelize Commit Processing
**Effort**: Medium | **Impact**: High (near-linear with core count)

The entire scan is single-threaded. Options:
- Partition commits into batches and process on multiple threads. LibGit2Sharp `Repository`
  is not thread-safe, but multiple instances can be opened against the same repo.
- Use `Parallel.ForEach` on commit batches, each with its own `Repository` handle, then
  merge accumulators.

### Option 5: Dictionary Lookup for Patch Entries
**Effort**: Trivial | **Impact**: Small-Medium

`FindPatchEntry` (lines 299-314) performs a **linear scan** of the Patch collection for each
file in each commit. Build a `Dictionary<string, PatchEntryChanges>` per commit for O(1)
lookup. Noticeable improvement on commits touching many files.

### Option 6: Stream Commits Instead of Materializing
**Effort**: Trivial | **Impact**: Small

Line 64 calls `.ToList()` on all commits in the window. Remove `.ToList()` and iterate the
`IEnumerable` directly — LibGit2Sharp lazily walks the commit graph. Reduces memory pressure
and provides a slight speed improvement.

### Option 7: Shell Out to `git log --numstat` Instead of LibGit2Sharp
**Effort**: Large (rewrite) | **Impact**: Highest

Replace LibGit2Sharp entirely with a single `git log --numstat --since=365.days` command:
- Gets commit metadata + file change lists + lines added/removed in **one pass**
- Heavily optimized in native git (pack file traversal, delta caching)
- Can be 5-10x faster than LibGit2Sharp's managed diff computation
- Parse the output stream line by line

Native git's bulk history traversal is fundamentally faster than LibGit2Sharp's
commit-by-commit managed diffing.

### Option 8: Incremental / Delta Scanning
**Effort**: Medium | **Impact**: High (for repeat scans)

Cache the last-scanned commit SHA. On subsequent runs, only process new commits since the
cached SHA and merge with stored results. Most of the 365-day window is already-scanned
history.

Makes repeat scans go from minutes to seconds.

---

## Recommended Approach

### Phase 1 — Quick Wins (do first)
Options 1, 2, 5, 6. Minimal code changes with significant cumulative improvement.
These are low-risk refactors within the existing architecture.

### Phase 2 — Best Single Investment
Option 7 (`git log --numstat`). Native git's bulk history traversal is fundamentally faster
than LibGit2Sharp's commit-by-commit diffing. This is the single highest-impact change but
requires the most rework.

### Phase 3 — Best for Ongoing Use
Option 8 (incremental scanning). Once the core scan is fast, incremental mode makes repeat
scans near-instant by only processing new commits.

---

## Comparison with Proposal 1

This proposal extends the original `git_churn_speedup_proposal.md` with additional options:

| Area | Proposal 1 | Proposal 2 (this) |
|------|-----------|-------------------|
| N+1 elimination | Remove or derive from window | Same — derive from accumulated data |
| Redundant diff | Consolidate TreeChanges + Patch | Same |
| Parallelism | Multi-threaded commit walker | Same, plus specific implementation guidance |
| Native git | Not considered | **New**: `git log --numstat` replacement |
| Incremental scan | Not considered | **New**: Delta scanning with cached SHA |
| Patch lookup | Not specifically called out | **New**: Dictionary for O(1) FindPatchEntry |
| Commit streaming | Not specifically called out | **New**: Remove `.ToList()` materialization |
| Lazy diff stats | Not specifically called out | **New**: Conditional Patch computation |
