using System.Collections.Concurrent;
using ReliabilityIQ.Analyzers.Regex;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Cli;

public sealed record PortabilityScanOptions(string RepoPath, string? DatabasePath, FindingSeverity FailOnSeverity);

public static class PortabilityScanRunner
{
    public static async Task<int> ExecuteAsync(
        PortabilityScanOptions options,
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
            var files = RepoDiscovery.DiscoverFiles(repoRoot);

            var analyzer = new PortabilityRegexAnalyzer();
            var findings = new ConcurrentBag<Finding>();

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var content = await File.ReadAllTextAsync(file.FullPath, cancellationToken).ConfigureAwait(false);
                var context = new AnalysisContext(file.RelativePath, content, file.Category, file.Language, Configuration: null);
                var fileFindings = await analyzer.AnalyzeAsync(context, cancellationToken).ConfigureAwait(false);

                foreach (var finding in fileFindings)
                {
                    findings.Add(finding with { RunId = string.Empty });
                }
            }

            var runId = $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
            var run = new ScanRun(
                RunId: runId,
                RepoRoot: repoRoot,
                CommitSha: TryReadGitCommitSha(repoRoot),
                StartedAt: startedAt,
                EndedAt: DateTimeOffset.UtcNow,
                ToolVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.1.0",
                ConfigHash: null);

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
            await writer.WriteAsync(run, persistedFiles, normalizedFindings, PortabilityRegexAnalyzer.BuiltInRuleDefinitions, cancellationToken)
                .ConfigureAwait(false);

            await PrintSummaryAsync(output, run, dbPath, normalizedFindings).ConfigureAwait(false);

            var shouldFail = normalizedFindings.Any(f => IsAtOrAboveSeverity(f.Severity, options.FailOnSeverity));
            return shouldFail ? 1 : 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await output.WriteLineAsync($"Scan failed: {ex.Message}").ConfigureAwait(false);
            return 2;
        }
    }

    private static string ResolveDatabasePath(string? databasePath, string repoRoot)
    {
        if (!string.IsNullOrWhiteSpace(databasePath))
        {
            return Path.GetFullPath(databasePath);
        }

        return Path.Combine(repoRoot, "reliabilityiq-results.db");
    }

    private static bool IsAtOrAboveSeverity(FindingSeverity findingSeverity, FindingSeverity threshold)
        => (int)findingSeverity <= (int)threshold;

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

        var bySeverity = findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var errorCount = bySeverity.GetValueOrDefault(FindingSeverity.Error);
        var warningCount = bySeverity.GetValueOrDefault(FindingSeverity.Warning);
        var infoCount = bySeverity.GetValueOrDefault(FindingSeverity.Info);

        await output.WriteLineAsync("Findings by severity:").ConfigureAwait(false);
        await output.WriteLineAsync($"  Error: {errorCount}").ConfigureAwait(false);
        await output.WriteLineAsync($"  Warning: {warningCount}").ConfigureAwait(false);
        await output.WriteLineAsync($"  Info: {infoCount}").ConfigureAwait(false);

        await output.WriteLineAsync("Top files by finding count:").ConfigureAwait(false);
        foreach (var entry in findings
                     .GroupBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
                     .Select(g => new { FilePath = g.Key, Count = g.Count() })
                     .OrderByDescending(x => x.Count)
                     .ThenBy(x => x.FilePath, StringComparer.OrdinalIgnoreCase)
                     .Take(10))
        {
            await output.WriteLineAsync($"  {entry.Count,4}  {entry.FilePath}").ConfigureAwait(false);
        }
    }
}
