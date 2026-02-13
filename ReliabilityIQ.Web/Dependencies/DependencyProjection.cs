using System.Globalization;
using System.Text.Json;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Dependencies;

public static class DependencyProjection
{
    public static DependencyHealthDto Build(IReadOnlyList<FindingListItem> findings)
    {
        var packageByKey = new Dictionary<string, MutableDependency>(StringComparer.OrdinalIgnoreCase);
        var frameworks = new List<EolFrameworkDto>();

        foreach (var finding in findings)
        {
            var metadata = ParseMetadata(finding.Metadata);
            var metadataType = ReadString(metadata, "type");

            if (string.Equals(metadataType, "framework", StringComparison.OrdinalIgnoreCase))
            {
                var framework = ReadString(metadata, "framework");
                var reason = ReadString(metadata, "reason");
                if (!string.IsNullOrWhiteSpace(framework))
                {
                    frameworks.Add(new EolFrameworkDto(framework, reason ?? "Out-of-support framework/runtime detected."));
                }

                continue;
            }

            var dependency = ReadString(metadata, "dependency");
            if (string.IsNullOrWhiteSpace(dependency))
            {
                continue;
            }

            var ecosystem = ReadString(metadata, "ecosystem") ?? "Unknown";
            var key = $"{ecosystem}:{dependency}";

            if (!packageByKey.TryGetValue(key, out var package))
            {
                package = new MutableDependency(dependency, ecosystem);
                packageByKey[key] = package;
            }

            var version = ReadString(metadata, "version");
            var versionSpec = ReadString(metadata, "versionSpec");
            var latestVersion = ReadString(metadata, "latestVersion");

            if (!string.IsNullOrWhiteSpace(version))
            {
                package.CurrentVersion = version;
            }
            else if (!string.IsNullOrWhiteSpace(versionSpec) && string.IsNullOrWhiteSpace(package.CurrentVersion))
            {
                package.CurrentVersion = versionSpec;
            }

            if (!string.IsNullOrWhiteSpace(latestVersion))
            {
                package.LatestVersion = latestVersion;
            }

            if (string.Equals(finding.RuleId, "deps.unpinned_version", StringComparison.OrdinalIgnoreCase))
            {
                package.Pinned = false;
                package.UnpinnedVersionSpec = versionSpec;
            }

            foreach (var vulnerability in ReadVulnerabilities(metadata))
            {
                package.Vulnerabilities[vulnerability.Id] = vulnerability;
            }
        }

        var packageRows = packageByKey.Values
            .Select(ToDto)
            .OrderByDescending(row => row.CveCount)
            .ThenByDescending(row => row.HighestSeverityRank)
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var eolFrameworks = frameworks
            .GroupBy(item => item.Framework, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(item => item.Framework, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new DependencyHealthDto(packageRows, eolFrameworks);
    }

    public static DependencyHealthDto ApplyFiltersAndSort(
        DependencyHealthDto health,
        string? search,
        string? pinned,
        bool cveOnly,
        bool eolOnly,
        string? sortBy,
        bool descending)
    {
        IEnumerable<DependencyPackageRowDto> rows = health.Packages;

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            rows = rows.Where(row =>
                row.Name.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                row.Ecosystem.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                (row.CurrentVersion?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        if (!string.IsNullOrWhiteSpace(pinned))
        {
            if (pinned.Equals("yes", StringComparison.OrdinalIgnoreCase))
            {
                rows = rows.Where(row => row.Pinned);
            }
            else if (pinned.Equals("no", StringComparison.OrdinalIgnoreCase))
            {
                rows = rows.Where(row => !row.Pinned);
            }
        }

        if (cveOnly)
        {
            rows = rows.Where(row => row.CveCount > 0);
        }

        if (eolOnly)
        {
            rows = rows.Where(row => row.EolStatus);
        }

        rows = sortBy?.Trim().ToLowerInvariant() switch
        {
            "staleness" => descending
                ? rows.OrderByDescending(row => row.StalenessScore).ThenByDescending(row => row.HighestSeverityRank).ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(row => row.StalenessScore).ThenByDescending(row => row.HighestSeverityRank).ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase),
            "name" => descending
                ? rows.OrderByDescending(row => row.Name, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase),
            _ => descending
                ? rows.OrderByDescending(row => row.HighestSeverityRank).ThenByDescending(row => row.CveCount).ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(row => row.HighestSeverityRank).ThenBy(row => row.CveCount).ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
        };

        return new DependencyHealthDto(rows.ToList(), health.EolFrameworks);
    }

    private static DependencyPackageRowDto ToDto(MutableDependency package)
    {
        var vulnerabilities = package.Vulnerabilities.Values
            .OrderByDescending(v => SeverityRank(v.Severity))
            .ThenBy(v => v.Id, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var highestSeverity = vulnerabilities.FirstOrDefault()?.Severity ?? "None";
        var highestSeverityRank = SeverityRank(highestSeverity);

        var pinned = package.Pinned;
        var currentVersion = string.IsNullOrWhiteSpace(package.CurrentVersion)
            ? package.UnpinnedVersionSpec
            : package.CurrentVersion;

        return new DependencyPackageRowDto(
            package.Name,
            package.Ecosystem,
            currentVersion,
            package.LatestVersion,
            pinned,
            vulnerabilities.Count,
            highestSeverity,
            highestSeverityRank,
            StalenessScore(currentVersion, package.LatestVersion),
            false,
            vulnerabilities);
    }

    private static double StalenessScore(string? currentVersion, string? latestVersion)
    {
        if (string.IsNullOrWhiteSpace(currentVersion) || string.IsNullOrWhiteSpace(latestVersion))
        {
            return 0;
        }

        if (!TryParseNumericVersion(currentVersion, out var current) || !TryParseNumericVersion(latestVersion, out var latest))
        {
            return 0;
        }

        if (latest <= current)
        {
            return 0;
        }

        return latest - current;
    }

    private static bool TryParseNumericVersion(string value, out double version)
    {
        version = 0;
        var token = value.Trim().TrimStart('=', '~', '^', '>', '<');
        var parts = token.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(3)
            .ToList();

        if (parts.Count == 0)
        {
            return false;
        }

        var weighted = new double[] { 1.0, 0.01, 0.0001 };
        var total = 0d;

        for (var i = 0; i < parts.Count && i < weighted.Length; i++)
        {
            var numericChars = new string(parts[i].TakeWhile(char.IsDigit).ToArray());
            if (string.IsNullOrWhiteSpace(numericChars))
            {
                return false;
            }

            if (!double.TryParse(numericChars, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                return false;
            }

            total += parsed * weighted[i];
        }

        version = total;
        return true;
    }

    private static int SeverityRank(string? severity)
    {
        return severity?.Trim().ToLowerInvariant() switch
        {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0
        };
    }

    private static JsonElement? ParseMetadata(string? metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(metadata);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadString(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!metadata.Value.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return property.GetString();
    }

    private static IReadOnlyList<DependencyVulnerabilityDto> ReadVulnerabilities(JsonElement? metadata)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<DependencyVulnerabilityDto>();
        }

        if (!metadata.Value.TryGetProperty("vulnerabilities", out var property) || property.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<DependencyVulnerabilityDto>();
        }

        var vulnerabilities = new List<DependencyVulnerabilityDto>();
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var id = item.TryGetProperty("id", out var idProp) ? idProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var severity = item.TryGetProperty("severity", out var severityProp)
                ? (severityProp.GetString() ?? "Medium")
                : "Medium";
            var summary = item.TryGetProperty("summary", out var summaryProp)
                ? summaryProp.GetString()
                : null;

            vulnerabilities.Add(new DependencyVulnerabilityDto(id, severity, summary));
        }

        return vulnerabilities;
    }

    private sealed class MutableDependency
    {
        public MutableDependency(string name, string ecosystem)
        {
            Name = name;
            Ecosystem = ecosystem;
        }

        public string Name { get; }

        public string Ecosystem { get; }

        public string? CurrentVersion { get; set; }

        public string? LatestVersion { get; set; }

        public bool Pinned { get; set; } = true;

        public string? UnpinnedVersionSpec { get; set; }

        public Dictionary<string, DependencyVulnerabilityDto> Vulnerabilities { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}

public sealed record DependencyHealthDto(
    IReadOnlyList<DependencyPackageRowDto> Packages,
    IReadOnlyList<EolFrameworkDto> EolFrameworks);

public sealed record DependencyPackageRowDto(
    string Name,
    string Ecosystem,
    string? CurrentVersion,
    string? LatestVersion,
    bool Pinned,
    int CveCount,
    string HighestSeverity,
    int HighestSeverityRank,
    double StalenessScore,
    bool EolStatus,
    IReadOnlyList<DependencyVulnerabilityDto> Vulnerabilities);

public sealed record DependencyVulnerabilityDto(
    string Id,
    string Severity,
    string? Summary);

public sealed record EolFrameworkDto(
    string Framework,
    string Reason);
