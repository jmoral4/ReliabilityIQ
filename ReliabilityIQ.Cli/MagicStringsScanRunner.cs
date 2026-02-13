using ReliabilityIQ.Analyzers.MagicStrings;
using ReliabilityIQ.Core.Configuration;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.MagicStrings;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Cli;

public sealed record MagicStringsScanOptions(
    string RepoPath,
    string? DatabasePath,
    int MinOccurrences,
    int Top,
    string? ConfigPath,
    string? RunId = null,
    bool AppendToRun = false);

public static class MagicStringsScanRunner
{
    public static async Task<int> ExecuteAsync(
        MagicStringsScanOptions options,
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

            if (options.MinOccurrences < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(options), "minOccurrences must be >= 0.");
            }

            var startedAt = DateTimeOffset.UtcNow;
            var repoRoot = RepoDiscovery.FindRepoRoot(options.RepoPath);
            var config = RuleConfigurationLoader.LoadForRepo(
                repoRoot,
                new CliRuleOverrides(
                    PortabilityFailOn: null,
                    MagicMinOccurrences: options.MinOccurrences > 0 ? options.MinOccurrences : null,
                    MagicTop: options.Top > 0 ? options.Top : null,
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

            var analyzer = new MagicStringAnalyzer();
            var analyzerOptions = BuildAnalyzerOptions(repoRoot, options, config.ScanSettings);

            var fileInputs = new List<MagicStringFileInput>(files.Count);
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var content = await File.ReadAllTextAsync(file.FullPath, cancellationToken).ConfigureAwait(false);
                fileInputs.Add(new MagicStringFileInput(file.RelativePath, content, file.Category, file.Language));
            }

            var candidates = analyzer.AnalyzeRepository(fileInputs, analyzerOptions, cancellationToken);
            var runId = string.IsNullOrWhiteSpace(options.RunId)
                ? $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"
                : options.RunId;

            var findings = candidates.Select(candidate => new Finding
            {
                RunId = runId,
                RuleId = candidate.RuleId,
                FilePath = candidate.TopFilePath,
                Line = candidate.TopLine,
                Column = candidate.TopColumn,
                Message = $"Magic string candidate '{candidate.NormalizedText}' score={candidate.MagicScore:0.###} occurrences={candidate.OccurrenceCount}.",
                Snippet = TryGetSnippet(fileInputs, candidate.TopFilePath, candidate.TopLine),
                Severity = candidate.Severity,
                Confidence = candidate.Confidence,
                Fingerprint = MagicStringAnalyzer.CreateFingerprint(candidate.RuleId, candidate.NormalizedText, candidate.OccurrenceCount),
                Metadata = candidate.Metadata
            }).ToList();

            findings = FindingPolicyEngine.Apply(findings, config).ToList();

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

            await PrintSummaryAsync(output, run, dbPath, candidates, options.Top).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await output.WriteLineAsync($"Magic strings scan failed: {ex.Message}").ConfigureAwait(false);
            return 2;
        }
    }

    private static async Task PrintSummaryAsync(TextWriter output, ScanRun run, string dbPath, IReadOnlyList<MagicStringCandidate> candidates, int top)
    {
        await output.WriteLineAsync($"Run ID: {run.RunId}").ConfigureAwait(false);
        await output.WriteLineAsync($"Repo: {run.RepoRoot}").ConfigureAwait(false);
        await output.WriteLineAsync($"DB: {dbPath}").ConfigureAwait(false);
        await output.WriteLineAsync($"Magic string candidates: {candidates.Count}").ConfigureAwait(false);

        await output.WriteLineAsync($"Top {Math.Min(top, 20)} magic string candidates:").ConfigureAwait(false);
        foreach (var entry in candidates.Take(Math.Min(top, 20)))
        {
            await output.WriteLineAsync(
                $"  score={entry.MagicScore,6:0.###} count={entry.OccurrenceCount,4} {entry.TopFilePath}:{entry.TopLine} '{Truncate(entry.NormalizedText, 64)}'").ConfigureAwait(false);
        }
    }

    private static MagicStringsAnalysisOptions BuildAnalyzerOptions(string repoRoot, MagicStringsScanOptions options, IReadOnlyDictionary<string, string> settings)
    {
        var defaults = MagicStringsAnalysisOptions.CreateDefault();
        var configPath = ResolveConfigPath(repoRoot, options.ConfigPath);
        var fromConfig = File.Exists(configPath)
            ? MagicStringsConfigParser.Parse(configPath, defaults)
            : defaults;

        var mergedMin = options.MinOccurrences > 0
            ? options.MinOccurrences
            : TryReadIntSetting(settings, "magic.minOccurrences") ?? fromConfig.MinOccurrences;

        var maxFindingsTotal = options.Top > 0
            ? options.Top
            : TryReadIntSetting(settings, "magic.top") ?? fromConfig.MaxFindingsTotal;

        return fromConfig with
        {
            MinOccurrences = mergedMin,
            MaxFindingsTotal = maxFindingsTotal
        };
    }

    private static int? TryReadIntSetting(IReadOnlyDictionary<string, string> settings, string key)
    {
        if (settings.TryGetValue(key, out var value) &&
            int.TryParse(value, out var parsed) &&
            parsed > 0)
        {
            return parsed;
        }

        return null;
    }

    private static string ResolveConfigPath(string repoRoot, string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return Path.GetFullPath(explicitPath);
        }

        return Path.Combine(repoRoot, "reliabilityiq.magicstrings.yaml");
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

    private static string? TryGetSnippet(IReadOnlyList<MagicStringFileInput> files, string filePath, int line)
    {
        var file = files.FirstOrDefault(f => string.Equals(f.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
        if (file is null)
        {
            return null;
        }

        var lines = file.Content.Split('\n');
        if (line <= 0 || line > lines.Length)
        {
            return null;
        }

        return lines[line - 1].TrimEnd('\r');
    }

    private static string Truncate(string value, int max)
    {
        if (value.Length <= max)
        {
            return value;
        }

        return value[..(max - 1)] + "...";
    }
}

internal static class MagicStringsConfigParser
{
    public static MagicStringsAnalysisOptions Parse(string path, MagicStringsAnalysisOptions defaults)
    {
        var minOccurrences = defaults.MinOccurrences;
        var maxPerDirectory = defaults.MaxFindingsPerDirectory;
        var maxTotal = defaults.MaxFindingsTotal;
        var entropyThreshold = defaults.EntropyThreshold;
        var allowlist = defaults.AllowlistPatterns.ToList();
        var denylist = defaults.DenylistPatterns.ToList();
        var logging = defaults.LoggingSinks.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToList() as IReadOnlyList<string>, StringComparer.OrdinalIgnoreCase);

        var section = string.Empty;
        var currentLanguage = string.Empty;

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.TrimEnd();
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            var indent = rawLine.TakeWhile(ch => ch == ' ').Count();
            var trimmed = line.Trim();

            if (indent == 0 && TryReadScalar(trimmed, "minOccurrences", out var minValue) && int.TryParse(minValue, out var parsedMin))
            {
                minOccurrences = Math.Max(1, parsedMin);
                continue;
            }

            if (indent == 0 && TryReadScalar(trimmed, "maxFindingsPerDirectory", out var maxDirValue) && int.TryParse(maxDirValue, out var parsedMaxDir))
            {
                maxPerDirectory = Math.Max(1, parsedMaxDir);
                continue;
            }

            if (indent == 0 && TryReadScalar(trimmed, "maxFindingsTotal", out var maxTotalValue) && int.TryParse(maxTotalValue, out var parsedMaxTotal))
            {
                maxTotal = Math.Max(1, parsedMaxTotal);
                continue;
            }

            if (indent == 0 && TryReadScalar(trimmed, "entropyThreshold", out var entropyValue) && double.TryParse(entropyValue, out var parsedEntropy))
            {
                entropyThreshold = Math.Max(0d, parsedEntropy);
                continue;
            }

            if (trimmed.Equals("allowlist:", StringComparison.OrdinalIgnoreCase))
            {
                section = "allowlist";
                currentLanguage = string.Empty;
                continue;
            }

            if (trimmed.Equals("denylist:", StringComparison.OrdinalIgnoreCase))
            {
                section = "denylist";
                currentLanguage = string.Empty;
                continue;
            }

            if (trimmed.Equals("loggingSinks:", StringComparison.OrdinalIgnoreCase))
            {
                section = "logging";
                currentLanguage = string.Empty;
                continue;
            }

            if (section == "logging" && indent >= 2 && trimmed.EndsWith(':'))
            {
                currentLanguage = trimmed[..^1].Trim();
                if (!logging.ContainsKey(currentLanguage))
                {
                    logging[currentLanguage] = [];
                }

                continue;
            }

            if (!trimmed.StartsWith("- ", StringComparison.Ordinal))
            {
                continue;
            }

            var value = trimmed[2..].Trim().Trim('"', '\'');
            if (value.Length == 0)
            {
                continue;
            }

            if (section == "allowlist")
            {
                allowlist.Add(value);
            }
            else if (section == "denylist")
            {
                denylist.Add(value);
            }
            else if (section == "logging" && currentLanguage.Length > 0)
            {
                var updated = logging[currentLanguage].ToList();
                updated.Add(value);
                logging[currentLanguage] = updated;
            }
        }

        var normalizedLogging = logging.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.Distinct(StringComparer.OrdinalIgnoreCase).ToList() as IReadOnlyList<string>,
            StringComparer.OrdinalIgnoreCase);

        return defaults with
        {
            MinOccurrences = minOccurrences,
            MaxFindingsPerDirectory = maxPerDirectory,
            MaxFindingsTotal = maxTotal,
            EntropyThreshold = entropyThreshold,
            AllowlistPatterns = allowlist.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            DenylistPatterns = denylist.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            LoggingSinks = normalizedLogging
        };
    }

    private static bool TryReadScalar(string line, string key, out string value)
    {
        value = string.Empty;
        var prefix = key + ":";
        if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        value = line[prefix.Length..].Trim().Trim('"', '\'');
        return true;
    }
}
