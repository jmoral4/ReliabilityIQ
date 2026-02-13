using System.Collections.Concurrent;
using System.Threading.Channels;
using ReliabilityIQ.Analyzers.CSharp;
using ReliabilityIQ.Analyzers.PowerShell;
using ReliabilityIQ.Analyzers.Regex;
using ReliabilityIQ.Analyzers.TreeSitter;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.Persistence;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Cli;

public sealed record PortabilityScanOptions(string RepoPath, string? DatabasePath, FindingSeverity FailOnSeverity, string? SuppressionsPath = null);

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

            var csharpAnalyzer = new CSharpPortabilityAnalyzer();
            var treeSitterAnalyzer = new TreeSitterPortabilityAnalyzer();
            var powerShellAnalyzer = new PowerShellPortabilityAnalyzer();
            var regexAnalyzer = new PortabilityRegexAnalyzer();

            var fileWorkChannel = Channel.CreateBounded<FileWork>(new BoundedChannelOptions(256)
            {
                SingleReader = false,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });

            var csharpChannel = Channel.CreateUnbounded<FileWork>();
            var treeSitterChannel = Channel.CreateUnbounded<FileWork>();
            var powerShellChannel = Channel.CreateUnbounded<FileWork>();
            var regexChannel = Channel.CreateUnbounded<FileWork>();
            var findingsChannel = Channel.CreateUnbounded<IReadOnlyList<Finding>>();

            var findings = new ConcurrentBag<Finding>();
            var findingCollector = Task.Run(async () =>
            {
                await foreach (var batch in findingsChannel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    foreach (var finding in batch)
                    {
                        findings.Add(finding with { RunId = string.Empty });
                    }
                }
            }, cancellationToken);

            var router = Task.Run(async () =>
            {
                await foreach (var work in fileWorkChannel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    var target = SelectTargetChannel(work.File, csharpChannel.Writer, treeSitterChannel.Writer, powerShellChannel.Writer, regexChannel.Writer);
                    await target.WriteAsync(work, cancellationToken).ConfigureAwait(false);
                }

                csharpChannel.Writer.TryComplete();
                treeSitterChannel.Writer.TryComplete();
                powerShellChannel.Writer.TryComplete();
                regexChannel.Writer.TryComplete();
            }, cancellationToken);

            var csharpWorkers = StartWorkers(csharpChannel.Reader, csharpAnalyzer, findingsChannel.Writer, Environment.ProcessorCount >= 4 ? 2 : 1, cancellationToken);
            var treeSitterWorkers = StartWorkers(treeSitterChannel.Reader, treeSitterAnalyzer, findingsChannel.Writer, Environment.ProcessorCount >= 4 ? 2 : 1, cancellationToken);
            var powerShellWorkers = StartWorkers(powerShellChannel.Reader, powerShellAnalyzer, findingsChannel.Writer, 1, cancellationToken);
            var regexWorkers = StartWorkers(regexChannel.Reader, regexAnalyzer, findingsChannel.Writer, Environment.ProcessorCount >= 8 ? 2 : 1, cancellationToken);

            var sharedConfig = BuildAnalyzerConfiguration(repoRoot, options.SuppressionsPath);
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var content = await File.ReadAllTextAsync(file.FullPath, cancellationToken).ConfigureAwait(false);
                await fileWorkChannel.Writer.WriteAsync(new FileWork(file, content, sharedConfig), cancellationToken).ConfigureAwait(false);
            }

            fileWorkChannel.Writer.TryComplete();
            await router.ConfigureAwait(false);
            await Task.WhenAll(csharpWorkers.Concat(treeSitterWorkers).Concat(powerShellWorkers).Concat(regexWorkers)).ConfigureAwait(false);
            findingsChannel.Writer.TryComplete();
            await findingCollector.ConfigureAwait(false);

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
            await writer.WriteAsync(run, persistedFiles, normalizedFindings, PortabilityRuleDefinitions.Rules, cancellationToken: cancellationToken)
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

    private static ChannelWriter<FileWork> SelectTargetChannel(
        DiscoveredFile file,
        ChannelWriter<FileWork> csharpWriter,
        ChannelWriter<FileWork> treeSitterWriter,
        ChannelWriter<FileWork> powerShellWriter,
        ChannelWriter<FileWork> regexWriter)
    {
        if (file.Category == FileCategory.Source)
        {
            return file.Language?.ToLowerInvariant() switch
            {
                "csharp" => csharpWriter,
                "cpp" or "python" or "rust" => treeSitterWriter,
                "powershell" => powerShellWriter,
                _ => regexWriter
            };
        }

        return regexWriter;
    }

    private static List<Task> StartWorkers(
        ChannelReader<FileWork> reader,
        IAnalyzer analyzer,
        ChannelWriter<IReadOnlyList<Finding>> findingsWriter,
        int workerCount,
        CancellationToken cancellationToken)
    {
        var workers = new List<Task>(workerCount);
        for (var i = 0; i < workerCount; i++)
        {
            workers.Add(Task.Run(async () =>
            {
                await foreach (var work in reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    var context = new AnalysisContext(
                        work.File.RelativePath,
                        work.Content,
                        work.File.Category,
                        work.File.Language,
                        work.Configuration);

                    var batch = (await analyzer.AnalyzeAsync(context, cancellationToken).ConfigureAwait(false)).ToList();
                    if (batch.Count == 0)
                    {
                        continue;
                    }

                    await findingsWriter.WriteAsync(batch, cancellationToken).ConfigureAwait(false);
                }
            }, cancellationToken));
        }

        return workers;
    }

    private static IReadOnlyDictionary<string, string?> BuildAnalyzerConfiguration(string repoRoot, string? suppressionsPath)
    {
        var config = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["repoRoot"] = repoRoot
        };

        if (!string.IsNullOrWhiteSpace(suppressionsPath))
        {
            config["suppressionsPath"] = Path.GetFullPath(suppressionsPath);
        }

        return config;
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

    private sealed record FileWork(DiscoveredFile File, string Content, IReadOnlyDictionary<string, string?> Configuration);
}
