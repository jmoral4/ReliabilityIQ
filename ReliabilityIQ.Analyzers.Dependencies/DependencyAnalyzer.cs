using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Dependencies;

namespace ReliabilityIQ.Analyzers.Dependencies;

public sealed record DependencyFileInput(string FilePath, string Content);

public sealed class DependencyAnalyzer
{
    private readonly DependencyFileParser _parser;
    private readonly IOsvClient _osvClient;

    public DependencyAnalyzer(DependencyFileParser? parser = null, IOsvClient? osvClient = null)
    {
        _parser = parser ?? new DependencyFileParser();
        _osvClient = osvClient ?? new HttpOsvClient();
    }

    public async Task<IReadOnlyList<Finding>> AnalyzeRepositoryAsync(
        IReadOnlyList<DependencyFileInput> files,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);

        var findings = new List<Finding>();

        var dependencies = new List<DependencyRecord>();
        var eolMatches = new List<EolFrameworkMatch>();

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            dependencies.AddRange(_parser.ParseDependencies(file.FilePath, file.Content));
            eolMatches.AddRange(_parser.ParseEolFrameworks(file.FilePath, file.Content));
        }

        var centralNuGetVersions = dependencies
            .Where(d => Path.GetFileName(d.FilePath).Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase))
            .Where(d => !string.IsNullOrWhiteSpace(d.ExactVersion))
            .GroupBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().ExactVersion!, StringComparer.OrdinalIgnoreCase);

        var normalizedDependencies = dependencies
            .Select(d => NormalizeDependency(d, centralNuGetVersions))
            .DistinctBy(d => $"{d.Ecosystem}:{d.Name}:{d.FilePath}:{d.Line}:{d.VersionSpec}", StringComparer.OrdinalIgnoreCase)
            .ToList();
        var latestVersionByPackage = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var eol in eolMatches)
        {
            findings.Add(CreateFinding(
                DependencyRuleDefinitions.EolFrameworkRuleId,
                eol.FilePath,
                eol.Line,
                $"EOL framework detected: {eol.Framework}.",
                FindingConfidence.High,
                new
                {
                    engine = "deps",
                    type = "framework",
                    framework = eol.Framework,
                    reason = eol.Reason
                }));
        }

        foreach (var dependency in normalizedDependencies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var packageKey = $"{dependency.Ecosystem}:{dependency.Name}";
            if (!latestVersionByPackage.TryGetValue(packageKey, out var latestVersion))
            {
                latestVersion = await _osvClient.QueryLatestVersionAsync(
                        dependency.Ecosystem,
                        dependency.Name,
                        cancellationToken)
                    .ConfigureAwait(false);
                latestVersionByPackage[packageKey] = latestVersion;
            }

            if (!dependency.IsPinned)
            {
                findings.Add(CreateFinding(
                    DependencyRuleDefinitions.UnpinnedVersionRuleId,
                    dependency.FilePath,
                    dependency.Line,
                    $"Dependency '{dependency.Name}' is not pinned (version spec '{dependency.VersionSpec}').",
                    FindingConfidence.High,
                    new
                    {
                        engine = "deps",
                        dependency = dependency.Name,
                        ecosystem = dependency.Ecosystem.ToString(),
                        versionSpec = dependency.VersionSpec,
                        latestVersion
                    }));
            }

            if (string.IsNullOrWhiteSpace(dependency.ExactVersion))
            {
                continue;
            }

            var vulns = await _osvClient.QueryVulnerabilitiesAsync(
                    dependency.Ecosystem,
                    dependency.Name,
                    dependency.ExactVersion,
                    cancellationToken)
                .ConfigureAwait(false);

            if (vulns.Count == 0)
            {
                continue;
            }

            var highest = HighestSeverity(vulns);
            var ruleId = highest switch
            {
                DependencyVulnerabilitySeverity.Critical => DependencyRuleDefinitions.VulnerableCriticalRuleId,
                DependencyVulnerabilitySeverity.High => DependencyRuleDefinitions.VulnerableHighRuleId,
                _ => DependencyRuleDefinitions.VulnerableMediumRuleId
            };

            findings.Add(CreateFinding(
                ruleId,
                dependency.FilePath,
                dependency.Line,
                $"Dependency '{dependency.Name} {dependency.ExactVersion}' has {vulns.Count} known vulnerabilities.",
                highest == DependencyVulnerabilitySeverity.Critical ? FindingConfidence.High : FindingConfidence.Medium,
                new
                {
                    engine = "deps",
                    dependency = dependency.Name,
                    ecosystem = dependency.Ecosystem.ToString(),
                    version = dependency.ExactVersion,
                    latestVersion,
                    vulnerabilities = vulns.Select(v => new
                    {
                        id = v.AdvisoryId,
                        severity = v.Severity.ToString(),
                        summary = v.Summary
                    })
                }));
        }

        return findings
            .GroupBy(f => f.Fingerprint, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Line)
            .ThenBy(f => f.Column)
            .ToList();
    }

    private static DependencyRecord NormalizeDependency(DependencyRecord dependency, IReadOnlyDictionary<string, string> centralNuGetVersions)
    {
        if (dependency.Ecosystem != DependencyEcosystem.NuGet)
        {
            return dependency;
        }

        if (!string.IsNullOrWhiteSpace(dependency.VersionSpec))
        {
            return dependency;
        }

        if (!centralNuGetVersions.TryGetValue(dependency.Name, out var version))
        {
            return dependency;
        }

        return dependency with
        {
            VersionSpec = version,
            IsPinned = true,
            ExactVersion = version
        };
    }

    private static DependencyVulnerabilitySeverity HighestSeverity(IReadOnlyList<DependencyVulnerability> vulnerabilities)
    {
        if (vulnerabilities.Any(v => v.Severity == DependencyVulnerabilitySeverity.Critical))
        {
            return DependencyVulnerabilitySeverity.Critical;
        }

        if (vulnerabilities.Any(v => v.Severity == DependencyVulnerabilitySeverity.High))
        {
            return DependencyVulnerabilitySeverity.High;
        }

        return DependencyVulnerabilitySeverity.Medium;
    }

    private static Finding CreateFinding(
        string ruleId,
        string filePath,
        int line,
        string message,
        FindingConfidence confidence,
        object metadata)
    {
        var serializedMetadata = JsonSerializer.Serialize(metadata);

        return new Finding
        {
            RuleId = ruleId,
            FilePath = filePath,
            Line = Math.Max(1, line),
            Column = 1,
            Message = message,
            Snippet = null,
            Severity = DependencyRuleDefinitions.ById[ruleId].DefaultSeverity,
            Confidence = confidence,
            Fingerprint = CreateFingerprint(ruleId, filePath, line.ToString(), message),
            Metadata = serializedMetadata
        };
    }

    private static string CreateFingerprint(params string[] parts)
    {
        var raw = string.Join('|', parts);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash);
    }
}
