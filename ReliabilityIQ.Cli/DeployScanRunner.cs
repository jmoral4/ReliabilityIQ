using ReliabilityIQ.Analyzers.Artifacts;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Artifacts;
using ReliabilityIQ.Core.Configuration;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Cli;

public sealed record DeployScanOptions(
    string RepoPath,
    string? DatabasePath,
    string? Ev2PathMarkers,
    string? AdoPathMarkers,
    string? RunId = null,
    bool AppendToRun = false);

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
            var config = RuleConfigurationLoader.LoadForRepo(
                repoRoot,
                new CliRuleOverrides(
                    PortabilityFailOn: null,
                    MagicMinOccurrences: null,
                    MagicTop: null,
                    ChurnSinceDays: null,
                    DeployEv2PathMarkers: SplitMarkers(options.Ev2PathMarkers).ToList(),
                    DeployAdoPathMarkers: SplitMarkers(options.AdoPathMarkers).ToList()));

            var effectiveEv2Markers = options.Ev2PathMarkers;
            if (string.IsNullOrWhiteSpace(effectiveEv2Markers) &&
                config.ScanSettings.TryGetValue("deploy.ev2.pathMarkers", out var configuredEv2))
            {
                effectiveEv2Markers = configuredEv2;
            }

            var effectiveAdoMarkers = options.AdoPathMarkers;
            if (string.IsNullOrWhiteSpace(effectiveAdoMarkers) &&
                config.ScanSettings.TryGetValue("deploy.ado.pathMarkers", out var configuredAdo))
            {
                effectiveAdoMarkers = configuredAdo;
            }

            var deploymentMarkers = MergeMarkers(effectiveEv2Markers, effectiveAdoMarkers);
            var classifier = new FileClassifier(deploymentMarkers);
            var files = RepoDiscovery.DiscoverFiles(
                repoRoot,
                classifier,
                new RepoDiscoveryOptions(
                    UseGitIgnore: config.Scan.UseGitIgnore ?? true,
                    MaxFileSizeBytes: config.Scan.MaxFileSizeBytes ?? 2 * 1024 * 1024,
                    AdditionalExcludeDirectories: config.Scan.Excludes,
                    ExcludeDotDirectories: config.Scan.ExcludeDotDirectories ?? true,
                    ComputeContentHash: true));

            var analyzer = new ArtifactAnalyzer();
            var analyzerConfig = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                ["repoRoot"] = repoRoot,
                ["deploy.ev2.pathMarkers"] = effectiveEv2Markers,
                ["deploy.ado.pathMarkers"] = effectiveAdoMarkers
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

            var runId = string.IsNullOrWhiteSpace(options.RunId)
                ? $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"
                : options.RunId;
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
            normalizedFindings = FindingPolicyEngine.Apply(normalizedFindings, config)
                .Select(f => f with { RunId = runId })
                .OrderBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Line)
                .ThenBy(f => f.Column)
                .ToList();

            var dbPath = ResolveDatabasePath(options.DatabasePath, repoRoot);
            var writer = new SqliteResultsWriter(dbPath);
            await writer.WriteAsync(
                    run,
                    persistedFiles,
                    normalizedFindings,
                    ArtifactRuleDefinitions.Rules,
                    clearRunData: !options.AppendToRun,
                    cancellationToken: cancellationToken)
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
