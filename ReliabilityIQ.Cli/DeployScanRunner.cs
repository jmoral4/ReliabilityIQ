using ReliabilityIQ.Analyzers.Artifacts;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Artifacts;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Cli;

public sealed record DeployScanOptions(
    string RepoPath,
    string? DatabasePath,
    string? Ev2PathMarkers,
    string? AdoPathMarkers);

public static class DeployScanRunner
{
    public static async Task<int> ExecuteAsync(
        DeployScanOptions options,
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

            var startedAt = DateTimeOffset.UtcNow;
            var repoRoot = RepoDiscovery.FindRepoRoot(options.RepoPath);
            var deploymentMarkers = MergeMarkers(options.Ev2PathMarkers, options.AdoPathMarkers);
            var classifier = new FileClassifier(deploymentMarkers);
            var files = RepoDiscovery.DiscoverFiles(repoRoot, classifier);

            var analyzer = new ArtifactAnalyzer();
            var analyzerConfig = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                ["repoRoot"] = repoRoot,
                ["deploy.ev2.pathMarkers"] = options.Ev2PathMarkers,
                ["deploy.ado.pathMarkers"] = options.AdoPathMarkers
            };

            var findings = new List<Finding>();
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var content = await File.ReadAllTextAsync(file.FullPath, cancellationToken).ConfigureAwait(false);
                var kind = ArtifactClassifier.DetectKind(file.RelativePath, content, analyzerConfig);
                if (kind == ArtifactKind.Unknown)
                {
                    continue;
                }

                var context = new AnalysisContext(
                    file.RelativePath,
                    content,
                    file.Category,
                    file.Language,
                    analyzerConfig);

                var batch = (await analyzer.AnalyzeAsync(context, cancellationToken).ConfigureAwait(false)).ToList();
                findings.AddRange(batch);
            }

            var runId = $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
            var run = new ScanRun(
                RunId: runId,
                RepoRoot: repoRoot,
                CommitSha: TryReadGitCommitSha(repoRoot),
                StartedAt: startedAt,
                EndedAt: DateTimeOffset.UtcNow,
                ToolVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.1.0",
                ConfigHash: BuildConfigHash(options));

            var persistedFiles = files.Select(file => new PersistedFile(
                Path: file.RelativePath,
                Category: file.Category,
                SizeBytes: file.SizeBytes,
                Hash: file.ContentHash,
                Language: file.Language)).ToList();

            var normalizedFindings = findings
                .Select(f => f with { RunId = runId })
                .OrderBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Line)
                .ThenBy(f => f.Column)
                .ToList();

            var dbPath = ResolveDatabasePath(options.DatabasePath, repoRoot);
            var writer = new SqliteResultsWriter(dbPath);
            await writer.WriteAsync(run, persistedFiles, normalizedFindings, ArtifactRuleDefinitions.Rules, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            await PrintSummaryAsync(output, run, dbPath, normalizedFindings).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await output.WriteLineAsync($"Deploy scan failed: {ex.Message}").ConfigureAwait(false);
            return 2;
        }
    }

    private static IReadOnlyCollection<string> MergeMarkers(string? ev2, string? ado)
    {
        var markers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddMarkers(markers, FileClassifier.DefaultDeploymentPathMarkers);
        AddMarkers(markers, SplitMarkers(ev2));
        AddMarkers(markers, SplitMarkers(ado));
        return markers;
    }

    private static void AddMarkers(ISet<string> target, IEnumerable<string> markers)
    {
        foreach (var marker in markers)
        {
            if (!string.IsNullOrWhiteSpace(marker))
            {
                target.Add(marker);
            }
        }
    }

    private static IEnumerable<string> SplitMarkers(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static string ResolveDatabasePath(string? databasePath, string repoRoot)
    {
        if (!string.IsNullOrWhiteSpace(databasePath))
        {
            return Path.GetFullPath(databasePath);
        }

        return Path.Combine(repoRoot, "reliabilityiq-results.db");
    }

    private static string BuildConfigHash(DeployScanOptions options)
    {
        var ev2 = options.Ev2PathMarkers ?? string.Empty;
        var ado = options.AdoPathMarkers ?? string.Empty;
        return $"ev2={ev2};ado={ado}";
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

    private static async Task PrintSummaryAsync(TextWriter output, ScanRun run, string dbPath, IReadOnlyList<Finding> findings)
    {
        await output.WriteLineAsync($"Run ID: {run.RunId}").ConfigureAwait(false);
        await output.WriteLineAsync($"Repo: {run.RepoRoot}").ConfigureAwait(false);
        await output.WriteLineAsync($"DB: {dbPath}").ConfigureAwait(false);

        var ev2Count = findings.Count(f => f.RuleId.StartsWith("deploy.ev2.", StringComparison.OrdinalIgnoreCase));
        var adoCount = findings.Count(f => f.RuleId.StartsWith("deploy.ado.", StringComparison.OrdinalIgnoreCase));
        var parseErrors = findings.Count(f => f.RuleId == ArtifactRuleDefinitions.ParseErrorRuleId);

        await output.WriteLineAsync("Deploy findings by artifact category:").ConfigureAwait(false);
        await output.WriteLineAsync($"  EV2: {ev2Count}").ConfigureAwait(false);
        await output.WriteLineAsync($"  ADO: {adoCount}").ConfigureAwait(false);
        await output.WriteLineAsync($"  Parse errors: {parseErrors}").ConfigureAwait(false);

        await output.WriteLineAsync("Top deploy rules:").ConfigureAwait(false);
        foreach (var entry in findings
                     .GroupBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
                     .Select(g => new { RuleId = g.Key, Count = g.Count() })
                     .OrderByDescending(x => x.Count)
                     .ThenBy(x => x.RuleId, StringComparer.OrdinalIgnoreCase)
                     .Take(10))
        {
            await output.WriteLineAsync($"  {entry.Count,4}  {entry.RuleId}").ConfigureAwait(false);
        }
    }
}
