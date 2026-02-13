using System.Text.Json;
using ReliabilityIQ.Analyzers.GitHistory;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.GitHistory;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Cli;

public sealed record ChurnScanOptions(
    string RepoPath,
    string? DatabasePath,
    string Since,
    string? ServiceMapPath = null);

public static class ChurnScanRunner
{
    public static async Task<int> ExecuteAsync(
        ChurnScanOptions options,
        TextWriter output,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);

        try
        {
            if (string.IsNullOrWhiteSpace(options.RepoPath))
            {
                throw new ArgumentException("Repository path is required.", nameof(options));
            }

            var sinceDays = ParseSinceDays(options.Since);
            var startedAt = DateTimeOffset.UtcNow;
            var repoRoot = RepoDiscovery.FindRepoRoot(options.RepoPath);
            var files = RepoDiscovery.DiscoverFiles(repoRoot, options: new RepoDiscoveryOptions(ComputeContentHash: false));
            var progressReporter = CreateProgressReporter(output);

            var analyzer = new GitHistoryAnalyzer();
            var analysis = analyzer.AnalyzeRepository(
                repoRoot,
                files.Select(file => new GitHistoryFileInput(file.RelativePath, file.Category, file.SizeBytes, file.Language)).ToList(),
                GitHistoryAnalysisOptions.CreateDefault() with
                {
                    SinceDays = sinceDays,
                    ServiceBoundaryMappings = LoadServiceBoundaryMappings(options.ServiceMapPath, repoRoot)
                },
                cancellationToken,
                progressReporter);

            CompleteProgressReporter(output);

            var runId = $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
            var run = new ScanRun(
                RunId: runId,
                RepoRoot: repoRoot,
                CommitSha: analysis.HeadCommitSha ?? TryReadGitCommitSha(repoRoot),
                StartedAt: startedAt,
                EndedAt: DateTimeOffset.UtcNow,
                ToolVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.1.0",
                ConfigHash: $"since={sinceDays}d");

            var persistedFiles = files.Select(file => new PersistedFile(
                Path: file.RelativePath,
                Category: file.Category,
                SizeBytes: file.SizeBytes,
                Hash: file.ContentHash,
                Language: file.Language)).ToList();

            var metrics = analysis.Files.Select(metric => new GitFileMetric(
                FilePath: metric.FilePath,
                LastCommitAt: metric.LastCommitAt,
                Commits30d: metric.Commits30d,
                Commits90d: metric.Commits90d,
                Commits180d: metric.Commits180d,
                Commits365d: metric.Commits365d,
                Authors365d: metric.Authors365d,
                OwnershipConcentration: metric.OwnershipConcentration,
                LinesAdded365d: metric.LinesAdded365d,
                LinesRemoved365d: metric.LinesRemoved365d,
                ChurnScore: metric.ChurnScore,
                StaleScore: metric.StaleScore,
                TopAuthor: metric.TopAuthor,
                TopAuthorPct: metric.TopAuthorPct)).ToList();

            var findings = analysis.Files
                .Where(file => file.IsOwnershipRisk)
                .Select(file => new Finding
                {
                    RunId = runId,
                    RuleId = GitHistoryRuleDefinitions.OwnershipOrphanedKnowledgeRiskRuleId,
                    FilePath = file.FilePath,
                    Line = 1,
                    Column = 1,
                    Message = $"Ownership concentration is {file.OwnershipConcentration:0.00} and top author '{file.TopAuthor}' has been inactive.",
                    Snippet = null,
                    Severity = FindingSeverity.Warning,
                    Confidence = FindingConfidence.Medium,
                    Fingerprint = CreateOwnershipRiskFingerprint(file),
                    Metadata = JsonSerializer.Serialize(new
                    {
                        metric = "orphaned_knowledge_risk",
                        file.TopAuthor,
                        topAuthorPct = file.TopAuthorPct,
                        ownershipConcentration = file.OwnershipConcentration,
                        topAuthorLastCommitAt = file.TopAuthorLastCommitAt,
                        file.NeverChangedSinceImport,
                        moduleDirectory = file.ModuleDirectory,
                        moduleProject = file.ModuleProject,
                        moduleService = file.ModuleService
                    })
                })
                .ToList();

            var dbPath = ResolveDatabasePath(options.DatabasePath, repoRoot);
            var writer = new SqliteResultsWriter(dbPath);
            await writer.WriteAsync(run, persistedFiles, findings, GitHistoryRuleDefinitions.Rules, metrics, cancellationToken)
                .ConfigureAwait(false);

            await PrintSummaryAsync(output, run, dbPath, analysis).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await output.WriteLineAsync($"Churn scan failed: {ex.Message}").ConfigureAwait(false);
            return 2;
        }
    }

    internal static int ParseSinceDays(string? since)
    {
        if (string.IsNullOrWhiteSpace(since))
        {
            return 365;
        }

        var token = since.Trim().ToLowerInvariant();
        if (token.EndsWith('d') && int.TryParse(token[..^1], out var days) && days > 0)
        {
            return days;
        }

        throw new ArgumentException("Invalid --since format. Expected values like 90d, 180d, 365d.", nameof(since));
    }

    private static string ResolveDatabasePath(string? databasePath, string repoRoot)
    {
        if (!string.IsNullOrWhiteSpace(databasePath))
        {
            return Path.GetFullPath(databasePath);
        }

        return Path.Combine(repoRoot, "reliabilityiq-results.db");
    }

    private static string? TryReadGitCommitSha(string repoRoot)
    {
        try
        {
            var headPath = Path.Combine(repoRoot, ".git", "HEAD");
            if (!File.Exists(headPath))
            {
                return null;
            }

            var head = File.ReadAllText(headPath).Trim();
            if (head.StartsWith("ref:", StringComparison.OrdinalIgnoreCase))
            {
                var refPath = head[4..].Trim();
                var fullRefPath = Path.Combine(repoRoot, ".git", refPath.Replace('/', Path.DirectorySeparatorChar));
                return File.Exists(fullRefPath) ? File.ReadAllText(fullRefPath).Trim() : null;
            }

            return head;
        }
        catch
        {
            return null;
        }
    }

    private static string CreateOwnershipRiskFingerprint(GitFileAnalysisResult file)
    {
        var topAuthor = file.TopAuthor ?? "unknown";
        return $"{GitHistoryRuleDefinitions.OwnershipOrphanedKnowledgeRiskRuleId}:{file.FilePath}:{topAuthor}";
    }

    private static IReadOnlyDictionary<string, string> LoadServiceBoundaryMappings(string? serviceMapPath, string repoRoot)
    {
        if (string.IsNullOrWhiteSpace(serviceMapPath))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        var resolved = Path.IsPathRooted(serviceMapPath)
            ? serviceMapPath
            : Path.Combine(repoRoot, serviceMapPath);

        if (!File.Exists(resolved))
        {
            throw new FileNotFoundException($"Service mapping file not found: {resolved}");
        }

        var mappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in File.ReadLines(resolved))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator < 0)
            {
                separator = line.IndexOf(':');
            }

            if (separator <= 0 || separator == line.Length - 1)
            {
                continue;
            }

            var name = line[..separator].Trim();
            var glob = line[(separator + 1)..].Trim();
            if (name.Length == 0 || glob.Length == 0)
            {
                continue;
            }

            mappings[name] = glob;
        }

        return mappings;
    }

    private static async Task PrintSummaryAsync(TextWriter output, ScanRun run, string dbPath, GitHistoryAnalysisResult analysis)
    {
        await output.WriteLineAsync($"Run ID: {run.RunId}").ConfigureAwait(false);
        await output.WriteLineAsync($"Repo: {run.RepoRoot}").ConfigureAwait(false);
        await output.WriteLineAsync($"DB: {dbPath}").ConfigureAwait(false);
        await output.WriteLineAsync($"Git metrics rows: {analysis.Files.Count}").ConfigureAwait(false);

        await output.WriteLineAsync("Top churn hotspots:").ConfigureAwait(false);
        foreach (var item in analysis.Files.OrderByDescending(f => f.ChurnScore).ThenBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase).Take(10))
        {
            await output.WriteLineAsync($"  churn={item.ChurnScore,8:0.###} commits365={item.Commits365d,4} {item.FilePath}").ConfigureAwait(false);
        }

        await output.WriteLineAsync("Top stale files:").ConfigureAwait(false);
        foreach (var item in analysis.Files.Where(f => f.StaleScore.HasValue)
                     .OrderByDescending(f => f.StaleScore)
                     .ThenBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
                     .Take(10))
        {
            await output.WriteLineAsync($"  stale={item.StaleScore!.Value,8:0.###} last={item.LastCommitAt?.UtcDateTime:yyyy-MM-dd} {item.FilePath}").ConfigureAwait(false);
        }

        await output.WriteLineAsync("Top ownership risks:").ConfigureAwait(false);
        foreach (var item in analysis.Files.Where(f => f.IsOwnershipRisk)
                     .OrderByDescending(f => f.OwnershipConcentration)
                     .ThenBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
                     .Take(10))
        {
            await output.WriteLineAsync($"  gini={item.OwnershipConcentration,6:0.###} owner={item.TopAuthor} pct={item.TopAuthorPct:P0} {item.FilePath}").ConfigureAwait(false);
        }

        await output.WriteLineAsync("Top directory modules by churn (p90):").ConfigureAwait(false);
        foreach (var module in analysis.DirectoryAggregates.Take(10))
        {
            await output.WriteLineAsync($"  churn_p90={module.ChurnScoreP90,8:0.###} files={module.FileCount,4} {module.ModuleKey}").ConfigureAwait(false);
        }

        await output.WriteLineAsync("Top project modules by churn (p90):").ConfigureAwait(false);
        foreach (var module in analysis.ProjectAggregates.Take(10))
        {
            await output.WriteLineAsync($"  churn_p90={module.ChurnScoreP90,8:0.###} files={module.FileCount,4} {module.ModuleKey}").ConfigureAwait(false);
        }

        if (analysis.ServiceAggregates.Count > 0)
        {
            await output.WriteLineAsync("Top service modules by churn (p90):").ConfigureAwait(false);
            foreach (var module in analysis.ServiceAggregates.Take(10))
            {
                await output.WriteLineAsync($"  churn_p90={module.ChurnScoreP90,8:0.###} files={module.FileCount,4} {module.ModuleKey}").ConfigureAwait(false);
            }
        }
    }

    private static Action<int> CreateProgressReporter(TextWriter output)
    {
        var lastDisplayed = -10;
        return percent =>
        {
            var display = Math.Clamp((percent / 10) * 10, 0, 100);
            if (display <= lastDisplayed)
            {
                return;
            }

            lastDisplayed = display;
            output.Write($"\rScanning ...{display}%");
            output.Flush();
        };
    }

    private static void CompleteProgressReporter(TextWriter output)
    {
        output.WriteLine();
        output.Flush();
    }
}
