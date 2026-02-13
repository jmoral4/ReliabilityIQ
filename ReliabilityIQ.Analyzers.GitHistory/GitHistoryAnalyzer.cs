using System.Collections.Concurrent;
using LibGit2Sharp;
using ReliabilityIQ.Core;

namespace ReliabilityIQ.Analyzers.GitHistory;

public sealed class GitHistoryAnalyzer : IAnalyzer
{
    private static readonly ConcurrentDictionary<string, GitHistoryAnalysisResult> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string[] ProjectMarkerNames = [".csproj", ".vcxproj", "Cargo.toml"];

    public string Name => "git-history";

    public string Version => "1.0.0";

    public IReadOnlyCollection<FileCategory> SupportedFileCategories =>
    [
        FileCategory.Source,
        FileCategory.Config,
        FileCategory.DeploymentArtifact,
        FileCategory.Docs,
        FileCategory.Unknown
    ];

    public Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Enumerable.Empty<Finding>());
    }

    public GitHistoryAnalysisResult AnalyzeRepository(
        string repoRoot,
        IReadOnlyList<GitHistoryFileInput> files,
        GitHistoryAnalysisOptions options,
        CancellationToken cancellationToken = default,
        Action<int>? progressCallback = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repoRoot);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(options);

        var cacheKey = BuildCacheKey(repoRoot, options);
        if (Cache.TryGetValue(cacheKey, out var cached))
        {
            return cached;
        }

        var normalizedInputs = files
            .Select(file => file with { FilePath = NormalizePath(file.FilePath) })
            .DistinctBy(file => file.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        using var repository = new Repository(repoRoot);
        var now = DateTimeOffset.UtcNow;
        var windowStart = now.AddDays(-options.SinceDays);

        var trackedSet = normalizedInputs.Select(f => f.FilePath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var byPath = normalizedInputs.ToDictionary(f => f.FilePath, f => new FileAccumulator(f.FilePath, f.Category), StringComparer.OrdinalIgnoreCase);
        var processedWorkItems = 0;
        var lastReportedPercent = -1;

        var filter = new CommitFilter { SortBy = CommitSortStrategies.Time | CommitSortStrategies.Topological };
        var commits = repository.Commits.QueryBy(filter)
            .Where(commit => commit.Author.When >= windowStart)
            .ToList();
        var totalWorkItems = Math.Max(1, commits.Count + normalizedInputs.Length);
        ReportProgress(progressCallback, totalWorkItems, processedWorkItems, ref lastReportedPercent);

        foreach (var commit in commits)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var commitWhen = commit.Author.When;

            var parent = commit.Parents.FirstOrDefault();
            var treeChanges = parent is null
                ? repository.Diff.Compare<TreeChanges>(null, commit.Tree)
                : repository.Diff.Compare<TreeChanges>(parent.Tree, commit.Tree);

            Patch? patch = null;
            if (options.IncludeDiffStats)
            {
                patch = parent is null
                    ? repository.Diff.Compare<Patch>(null, commit.Tree)
                    : repository.Diff.Compare<Patch>(parent.Tree, commit.Tree);
            }

            foreach (var change in treeChanges)
            {
                var candidatePaths = EnumerateCandidatePaths(change).ToArray();
                var matchPath = candidatePaths.FirstOrDefault(path => trackedSet.Contains(path));
                if (matchPath is null)
                {
                    continue;
                }

                if (!byPath.TryGetValue(matchPath, out var accumulator))
                {
                    continue;
                }

                var author = string.IsNullOrWhiteSpace(commit.Author.Email)
                    ? commit.Author.Name.Trim()
                    : commit.Author.Email.Trim();

                accumulator.RecordCommit(commitWhen, author, now);

                if (patch is null)
                {
                    continue;
                }

                var patchEntry = FindPatchEntry(patch, candidatePaths);
                if (patchEntry is not null)
                {
                    accumulator.AddLines(patchEntry.LinesAdded, patchEntry.LinesDeleted);
                }
            }

            processedWorkItems++;
            ReportProgress(progressCallback, totalWorkItems, processedWorkItems, ref lastReportedPercent);
        }

        var projectMarkers = BuildProjectMarkers(normalizedInputs);
        foreach (var input in normalizedInputs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var accumulator = byPath[input.FilePath];

            var log = repository.Commits.QueryBy(input.FilePath).Take(2).ToArray();
            if (log.Length > 0 && accumulator.LastCommitAt is null)
            {
                accumulator.LastCommitAt = log[0].Commit.Author.When;
            }

            var totalCommitCount = log.Length == 2 ? 2 : log.Length;
            if (totalCommitCount == 1 && accumulator.TotalLineChanges >= options.ImportCommitLargeChangeThreshold)
            {
                accumulator.NeverChangedSinceImport = true;
            }

            accumulator.SetModuleKeys(
                directoryKey: GetDirectoryModuleKey(input.FilePath),
                projectKey: GetProjectModuleKey(input.FilePath, projectMarkers),
                serviceKey: GetServiceModuleKey(input.FilePath, options.ServiceBoundaryMappings));

            processedWorkItems++;
            ReportProgress(progressCallback, totalWorkItems, processedWorkItems, ref lastReportedPercent);
        }

        var results = normalizedInputs
            .Select(file => byPath[file.FilePath].BuildResult(now, options))
            .OrderBy(r => r.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var directoryAggregates = AggregateModules(results, x => x.ModuleDirectory);
        var projectAggregates = AggregateModules(results, x => x.ModuleProject);
        var serviceAggregates = AggregateModules(
            results.Where(x => !string.Equals(x.ModuleService, ".", StringComparison.Ordinal)).ToArray(),
            x => x.ModuleService);

        var output = new GitHistoryAnalysisResult(
            Files: results,
            DirectoryAggregates: directoryAggregates,
            ProjectAggregates: projectAggregates,
            ServiceAggregates: serviceAggregates,
            HeadCommitSha: repository.Head?.Tip?.Sha);

        if (lastReportedPercent < 100)
        {
            progressCallback?.Invoke(100);
        }

        Cache.TryAdd(cacheKey, output);
        return output;
    }

    private static void ReportProgress(Action<int>? progressCallback, int totalWorkItems, int processedWorkItems, ref int lastReportedPercent)
    {
        if (progressCallback is null)
        {
            return;
        }

        var percent = (int)Math.Clamp(Math.Floor((double)processedWorkItems * 100d / totalWorkItems), 0d, 100d);
        if (percent == lastReportedPercent)
        {
            return;
        }

        lastReportedPercent = percent;
        progressCallback(percent);
    }

    public static IReadOnlyList<GitModuleAggregate> AggregateModules(
        IReadOnlyList<GitFileAnalysisResult> files,
        Func<GitFileAnalysisResult, string> keySelector)
    {
        return files
            .GroupBy(keySelector, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var churnValues = group.Select(x => x.ChurnScore).ToList();
                var staleValues = group.Select(x => x.StaleScore ?? 0d).ToList();
                var ownershipValues = group.Select(x => x.OwnershipConcentration).ToList();

                return new GitModuleAggregate(
                    ModuleKey: group.Key,
                    FileCount: group.Count(),
                    ChurnScoreP90: GitHistoryMath.Percentile(churnValues, 0.9d),
                    StaleScoreP90: GitHistoryMath.Percentile(staleValues, 0.9d),
                    OwnershipConcentrationP90: GitHistoryMath.Percentile(ownershipValues, 0.9d));
            })
            .OrderByDescending(x => x.ChurnScoreP90)
            .ThenBy(x => x.ModuleKey, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static string GetDirectoryModuleKey(string filePath)
    {
        var normalized = NormalizePath(filePath);
        var idx = normalized.IndexOf('/');
        if (idx <= 0)
        {
            return ".";
        }

        return normalized[..idx];
    }

    public static string GetProjectModuleKey(string filePath, IReadOnlyDictionary<string, string> projectMarkers)
    {
        var normalized = NormalizePath(filePath);
        var directory = Path.GetDirectoryName(normalized)?.Replace('\\', '/') ?? string.Empty;
        while (directory.Length > 0)
        {
            if (projectMarkers.TryGetValue(directory, out var marker))
            {
                return marker;
            }

            var nextSlash = directory.LastIndexOf('/');
            if (nextSlash < 0)
            {
                break;
            }

            directory = directory[..nextSlash];
        }

        return GetDirectoryModuleKey(normalized);
    }

    public static string GetServiceModuleKey(string filePath, IReadOnlyDictionary<string, string> serviceBoundaryMappings)
    {
        if (serviceBoundaryMappings.Count == 0)
        {
            return ".";
        }

        var normalized = NormalizePath(filePath);
        foreach (var mapping in serviceBoundaryMappings)
        {
            if (WildcardMatch(normalized, mapping.Value))
            {
                return mapping.Key;
            }
        }

        return ".";
    }

    private static IReadOnlyDictionary<string, string> BuildProjectMarkers(IReadOnlyList<GitHistoryFileInput> files)
    {
        var markers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            var fileName = Path.GetFileName(file.FilePath);
            if (!ProjectMarkerNames.Any(marker => fileName.EndsWith(marker, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var directory = Path.GetDirectoryName(file.FilePath)?.Replace('\\', '/') ?? string.Empty;
            if (!markers.ContainsKey(directory))
            {
                markers[directory] = file.FilePath;
            }
        }

        return markers;
    }

    private static string BuildCacheKey(string repoRoot, GitHistoryAnalysisOptions options)
    {
        using var repository = new Repository(repoRoot);
        var sha = repository.Head?.Tip?.Sha ?? "no-head";
        return $"{Path.GetFullPath(repoRoot)}|{sha}|{options.SinceDays}|{options.IncludeDiffStats}";
    }

    private static PatchEntryChanges? FindPatchEntry(Patch patch, IReadOnlyList<string> candidatePaths)
    {
        foreach (var candidate in candidatePaths)
        {
            var match = patch.FirstOrDefault(entry =>
                string.Equals(NormalizePath(entry.Path), candidate, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(NormalizePath(entry.OldPath), candidate, StringComparison.OrdinalIgnoreCase));

            if (match is not null)
            {
                return match;
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateCandidatePaths(TreeEntryChanges change)
    {
        if (!string.IsNullOrWhiteSpace(change.Path))
        {
            yield return NormalizePath(change.Path);
        }

        if (!string.IsNullOrWhiteSpace(change.OldPath))
        {
            yield return NormalizePath(change.OldPath);
        }
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/').TrimStart('/');
    }

    private static bool IsStaleIgnored(string filePath, IReadOnlyList<string> patterns)
    {
        foreach (var pattern in patterns)
        {
            if (WildcardMatch(filePath, pattern))
            {
                return true;
            }
        }

        return false;
    }

    private static bool WildcardMatch(string input, string pattern)
    {
        var text = input.AsSpan();
        var pat = pattern.AsSpan();
        var textIndex = 0;
        var patternIndex = 0;
        var starIndex = -1;
        var matchIndex = 0;

        while (textIndex < text.Length)
        {
            if (patternIndex < pat.Length && (pat[patternIndex] == '?' || char.ToLowerInvariant(pat[patternIndex]) == char.ToLowerInvariant(text[textIndex])))
            {
                textIndex++;
                patternIndex++;
            }
            else if (patternIndex < pat.Length && pat[patternIndex] == '*')
            {
                starIndex = patternIndex++;
                matchIndex = textIndex;
            }
            else if (starIndex >= 0)
            {
                patternIndex = starIndex + 1;
                textIndex = ++matchIndex;
            }
            else
            {
                return false;
            }
        }

        while (patternIndex < pat.Length && pat[patternIndex] == '*')
        {
            patternIndex++;
        }

        return patternIndex == pat.Length;
    }

    private sealed class FileAccumulator
    {
        private readonly Dictionary<string, int> _commitCountByAuthor = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTimeOffset> _lastCommitByAuthor = new(StringComparer.OrdinalIgnoreCase);
        private readonly FileCategory _category;

        public FileAccumulator(string path, FileCategory category)
        {
            FilePath = path;
            _category = category;
        }

        public string FilePath { get; }

        public DateTimeOffset? LastCommitAt { get; set; }

        public int Commits30d { get; private set; }

        public int Commits90d { get; private set; }

        public int Commits180d { get; private set; }

        public int Commits365d { get; private set; }

        public int LinesAdded365d { get; private set; }

        public int LinesRemoved365d { get; private set; }

        public int TotalLineChanges => LinesAdded365d + LinesRemoved365d;

        public bool NeverChangedSinceImport { get; set; }

        public string ModuleDirectory { get; private set; } = ".";

        public string ModuleProject { get; private set; } = ".";

        public string ModuleService { get; private set; } = ".";

        public void RecordCommit(DateTimeOffset commitWhen, string author, DateTimeOffset now)
        {
            if (LastCommitAt is null || commitWhen > LastCommitAt)
            {
                LastCommitAt = commitWhen;
            }

            var ageDays = (now - commitWhen).TotalDays;
            if (ageDays <= 365d)
            {
                Commits365d++;
                IncrementAuthor(author);
            }

            if (ageDays <= 180d)
            {
                Commits180d++;
            }

            if (ageDays <= 90d)
            {
                Commits90d++;
            }

            if (ageDays <= 30d)
            {
                Commits30d++;
            }

            if (_lastCommitByAuthor.TryGetValue(author, out var existing))
            {
                if (commitWhen > existing)
                {
                    _lastCommitByAuthor[author] = commitWhen;
                }
            }
            else
            {
                _lastCommitByAuthor[author] = commitWhen;
            }
        }

        public void AddLines(int linesAdded, int linesRemoved)
        {
            LinesAdded365d += Math.Max(0, linesAdded);
            LinesRemoved365d += Math.Max(0, linesRemoved);
        }

        public void SetModuleKeys(string directoryKey, string projectKey, string serviceKey)
        {
            ModuleDirectory = directoryKey;
            ModuleProject = projectKey;
            ModuleService = serviceKey;
        }

        public GitFileAnalysisResult BuildResult(DateTimeOffset now, GitHistoryAnalysisOptions options)
        {
            var totalAuthorCommits = _commitCountByAuthor.Values.Sum();
            var ownershipConcentration = GitHistoryMath.ComputeGiniCoefficient(_commitCountByAuthor.Values.ToArray());

            string? topAuthor = null;
            var topAuthorCount = 0;
            DateTimeOffset? topAuthorLastCommitAt = null;
            foreach (var pair in _commitCountByAuthor)
            {
                if (pair.Value <= topAuthorCount)
                {
                    continue;
                }

                topAuthor = pair.Key;
                topAuthorCount = pair.Value;
                topAuthorLastCommitAt = _lastCommitByAuthor.GetValueOrDefault(pair.Key);
            }

            var topAuthorPct = totalAuthorCommits == 0 ? 0d : (double)topAuthorCount / totalAuthorCommits;
            var churnScore = GitHistoryMath.ComputeChurnScore(Commits365d, LinesAdded365d, LinesRemoved365d);

            var staleEligible = options.StalenessCategories.Contains(_category) && !IsStaleIgnored(FilePath, options.StaleIgnorePatterns);
            double? staleScore = null;
            if (staleEligible)
            {
                var daysSinceLastCommit = LastCommitAt is null ? options.SinceDays : (int)Math.Max(0d, (now - LastCommitAt.Value).TotalDays);
                staleScore = GitHistoryMath.ComputeStaleScore(daysSinceLastCommit);
            }

            var inactiveTopAuthor = topAuthorLastCommitAt.HasValue &&
                                    (now - topAuthorLastCommitAt.Value).TotalDays > options.TopAuthorInactiveDays;

            var ownershipRisk = ownershipConcentration > options.OwnershipConcentrationThreshold && inactiveTopAuthor;

            return new GitFileAnalysisResult(
                FilePath,
                LastCommitAt,
                Commits30d,
                Commits90d,
                Commits180d,
                Commits365d,
                Authors365d: _commitCountByAuthor.Count,
                OwnershipConcentration: ownershipConcentration,
                LinesAdded365d,
                LinesRemoved365d,
                ChurnScore: churnScore,
                StaleScore: staleScore,
                TopAuthor: topAuthor,
                TopAuthorPct: topAuthorPct,
                TopAuthorLastCommitAt: topAuthorLastCommitAt,
                NeverChangedSinceImport,
                IsOwnershipRisk: ownershipRisk,
                ModuleDirectory,
                ModuleProject,
                ModuleService);
        }

        private void IncrementAuthor(string author)
        {
            if (_commitCountByAuthor.TryGetValue(author, out var count))
            {
                _commitCountByAuthor[author] = count + 1;
            }
            else
            {
                _commitCountByAuthor[author] = 1;
            }
        }
    }
}
