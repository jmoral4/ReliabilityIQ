using ReliabilityIQ.Analyzers.Dependencies;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Configuration;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Cli;

public sealed record DependenciesScanOptions(
    string RepoPath,
    string? DatabasePath,
    string? RunId = null,
    bool AppendToRun = false);

public static class DependenciesScanRunner
{
    public static async Task<int> ExecuteAsync(
        DependenciesScanOptions options,
        TextWriter output,
        IOsvClient? osvClient = null,
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
                    DeployEv2PathMarkers: null,
                    DeployAdoPathMarkers: null));

            var files = RepoDiscovery.DiscoverFiles(
                repoRoot,
                options: new RepoDiscoveryOptions(
                    UseGitIgnore: config.Scan.UseGitIgnore ?? true,
                    MaxFileSizeBytes: config.Scan.MaxFileSizeBytes ?? 2 * 1024 * 1024,
                    AdditionalExcludeDirectories: config.Scan.Excludes,
                    ExcludeDotDirectories: config.Scan.ExcludeDotDirectories ?? true,
                    ComputeContentHash: true));

            var dependencyFiles = files.Where(IsDependencyFile).ToList();

            var input = new List<DependencyFileInput>(dependencyFiles.Count);
            foreach (var file in dependencyFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var content = await File.ReadAllTextAsync(file.FullPath, cancellationToken).ConfigureAwait(false);
                input.Add(new DependencyFileInput(file.RelativePath, content));
            }

            var analyzer = new DependencyAnalyzer(osvClient: osvClient);
            var findings = (await analyzer.AnalyzeRepositoryAsync(input, cancellationToken).ConfigureAwait(false))
                .Select(f => f with { RunId = string.Empty })
                .ToList();

            var runId = string.IsNullOrWhiteSpace(options.RunId)
                ? $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"
                : options.RunId;
            findings = FindingPolicyEngine.Apply(findings, config)
                .Select(f => f with { RunId = runId })
                .OrderBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Line)
                .ThenBy(f => f.Column)
                .ToList();

            var run = new ScanRun(
                RunId: runId,
                RepoRoot: repoRoot,
                CommitSha: TryReadGitCommitSha(repoRoot),
                StartedAt: startedAt,
                EndedAt: DateTimeOffset.UtcNow,
                ToolVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.1.0",
                ConfigHash: null);

            var persistedFiles = dependencyFiles.Select(file => new PersistedFile(
                Path: file.RelativePath,
                Category: file.Category,
                SizeBytes: file.SizeBytes,
                Hash: file.ContentHash,
                Language: file.Language)).ToList();

            var dbPath = ResolveDatabasePath(options.DatabasePath, repoRoot);
            var writer = new SqliteResultsWriter(dbPath);
            var ruleDefinitions = RuleCatalog.GetBuiltInDefinitions()
                .Concat(config.Rules.CustomRules.Select(r => new RuleDefinition(r.Id, r.Title ?? r.Id, r.Severity, r.Description ?? r.Message)))
                .GroupBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();

            await writer.WriteAsync(
                    run,
                    persistedFiles,
                    findings,
                    ruleDefinitions,
                    clearRunData: !options.AppendToRun,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            await output.WriteLineAsync($"Run ID: {runId}").ConfigureAwait(false);
            await output.WriteLineAsync($"Repo: {repoRoot}").ConfigureAwait(false);
            await output.WriteLineAsync($"DB: {dbPath}").ConfigureAwait(false);
            await output.WriteLineAsync($"Dependency findings: {findings.Count}").ConfigureAwait(false);
            foreach (var entry in findings.GroupBy(f => f.RuleId).OrderByDescending(g => g.Count()))
            {
                await output.WriteLineAsync($"  {entry.Key}: {entry.Count()}").ConfigureAwait(false);
            }

            return 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await output.WriteLineAsync($"Dependencies scan failed: {ex.Message}").ConfigureAwait(false);
            return 2;
        }
    }

    private static bool IsDependencyFile(DiscoveredFile file)
    {
        var name = Path.GetFileName(file.RelativePath);
        var extension = Path.GetExtension(name);

        if (extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("packages.config", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("setup.py", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Cargo.toml", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("package.json", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
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
}
