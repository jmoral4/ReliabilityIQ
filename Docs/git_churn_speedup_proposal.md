# Proposal: Optimizing Git Churn Scanning Performance

## 1. Current Bottlenecks
The `GitHistoryAnalyzer` currently takes an "eternity" on large repositories due to several architectural inefficiencies:

1.  **N+1 History Queries (Critical)**: At the end of the scan, the analyzer iterates through *every tracked file* and executes `repository.Commits.QueryBy(filePath)`. This is done to determine if a file has "Never Changed Since Import". For a repo with 10k files, this launches 10k separate git log operations.
2.  **O(N * M) Commit Processing**: Inside the main commit walker loop, the code iterates through every change in a commit and performs a linear scan against the tracked file list to find matches. This complexity scales poorly as both the number of files and the number of commits grow.
3.  **Redundant Diffing**: The analyzer currently computes both `TreeChanges` (fast) and `Patch` (slow) for every commit. Since `Patch` contains a superset of the information in `TreeChanges`, the first computation is often redundant.
4.  **High Allocation Volume**: Path normalization and candidate path enumeration occur deep inside nested loops, leading to significant GC pressure during large scans.

---

## 2. Proposed Options

### Option 1: Remove "Never Changed Since Import" Logic (Highest Impact)
The most significant speedup comes from removing the per-file `QueryBy` loop.
-   **Change**: Eliminate the secondary loop over all files that checks for single-commit history.
-   **Trade-off**: The `NeverChangedSinceImport` flag will no longer be populated. Files not modified within the `--since` window will simply show as "Stale" (LastCommitAt = null).
-   **Estimated Gain**: 80%–95% reduction in scan time for large, deep-history repositories.

### Option 2: Inverted Lookup Optimization (Safe)
Refactor the commit processing loop to use O(1) lookups.
-   **Change**: Instead of checking every commit change against a list of files, iterate the commit's `Patch` entries directly and look up the paths in a `Dictionary<string, FileAccumulator>`.
-   **Change**: Eliminate the redundant `TreeChanges` diff when `IncludeDiffStats` is enabled; use only the `Patch`.
-   **Estimated Gain**: 10%–30% speedup in the commit-walking phase.

### Option 3: Incremental/Windowed Metadata (Feature Adjustment)
-   **Change**: Change the "Never Changed Since Import" feature to "Only Changed Once in Window". This allows calculating the signal using only the commits already being walked in the primary loop.
-   **Estimated Gain**: Restores the feature signal without the N+1 performance penalty.

### Option 4: Multi-threaded Commit Walker (Complex)
-   **Change**: Partition the commit history and process segments in parallel using `Parallel.ForEach`. 
-   **Constraint**: Requires one `LibGit2Sharp.Repository` instance per thread as the library is not thread-safe for concurrent access to the same instance.
-   **Estimated Gain**: Scales with available CPU cores.

---

## 3. Recommended Immediate Action
I recommend implementing **Option 1 and Option 2** immediately. This involves:
1.  Refactoring `AnalyzeRepository` to use a single pass over the commits.
2.  Removing the secondary per-file history query loop.
3.  Updating the inner loop to use dictionary-based path resolution.
4.  Consolidating `TreeChanges` and `Patch` diffing.
