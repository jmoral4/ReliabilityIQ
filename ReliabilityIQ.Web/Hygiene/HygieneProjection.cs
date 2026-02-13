using System.Globalization;
using System.Text.Json;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Hygiene;

public static class HygieneProjection
{
    private static readonly HashSet<string> FeatureFlagRuleIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "hygiene.stale_feature_flag",
        "hygiene.dead_feature_flag"
    };

    private static readonly HashSet<string> TechDebtRuleIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "hygiene.todo_old",
        "hygiene.fixme",
        "hygiene.hack"
    };

    public static HygieneViewModel Build(
        IReadOnlyList<FindingListItem> hygieneFindings,
        IReadOnlyList<FindingListItem> asyncFindings,
        IReadOnlyList<FindingListItem> threadFindings)
    {
        var featureFlags = BuildFeatureFlags(hygieneFindings);
        var techDebt = BuildTechDebt(hygieneFindings);
        var asyncIssues = BuildAsyncIssues(asyncFindings, threadFindings);
        var agingBuckets = BuildAgingBuckets(techDebt);

        return new HygieneViewModel(
            featureFlags,
            techDebt,
            asyncIssues,
            agingBuckets,
            techDebt.Count,
            asyncIssues.Count);
    }

    private static IReadOnlyList<FeatureFlagRowDto> BuildFeatureFlags(IReadOnlyList<FindingListItem> findings)
    {
        var rows = new List<FeatureFlagRowDto>();

        foreach (var finding in findings)
        {
            if (!FeatureFlagRuleIds.Contains(finding.RuleId))
            {
                continue;
            }

            var metadata = ParseMetadata(finding.Metadata);
            var flagName = ReadString(metadata, "flagName") ?? "[unknown]";
            var referenceCount = ReadLong(metadata, "referenceCount") ?? 0;
            var definitionCount = ReadLong(metadata, "definitionCount") ?? 0;

            var introducedDays = ReadRoundedInt(metadata, "introducedDaysAgo");
            var lastChangedDays = ReadRoundedInt(metadata, "lastChangedDaysAgo");
            var ageDays = introducedDays ?? lastChangedDays;

            var locations = ReadLocations(metadata, finding.FilePath, finding.Line);
            var status = finding.RuleId.Equals("hygiene.dead_feature_flag", StringComparison.OrdinalIgnoreCase)
                ? "Dead"
                : "Stale";

            rows.Add(new FeatureFlagRowDto(
                finding.RuleId,
                flagName,
                referenceCount,
                definitionCount,
                ageDays,
                status,
                finding.FilePath,
                finding.Line,
                finding.Message,
                locations));
        }

        return rows
            .OrderByDescending(row => row.Status, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(row => row.AgeDays ?? -1)
            .ThenBy(row => row.FlagName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<TechDebtRowDto> BuildTechDebt(IReadOnlyList<FindingListItem> findings)
    {
        var rows = new List<TechDebtRowDto>();

        foreach (var finding in findings)
        {
            if (!TechDebtRuleIds.Contains(finding.RuleId))
            {
                continue;
            }

            var metadata = ParseMetadata(finding.Metadata);
            var keyword = ReadString(metadata, "keyword") ?? "TODO";
            var author = ReadString(metadata, "author") ?? "unknown";
            var ageDays = ReadInt(metadata, "ageDays");

            rows.Add(new TechDebtRowDto(
                finding.FindingId,
                finding.RuleId,
                keyword,
                ageDays,
                author,
                finding.FilePath,
                finding.Line,
                finding.Message));
        }

        return rows
            .OrderByDescending(row => row.AgeDays ?? -1)
            .ThenBy(row => row.Keyword, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.Line)
            .ToList();
    }

    private static IReadOnlyList<AsyncIssueRowDto> BuildAsyncIssues(
        IReadOnlyList<FindingListItem> asyncFindings,
        IReadOnlyList<FindingListItem> threadFindings)
    {
        var rows = new List<AsyncIssueRowDto>(asyncFindings.Count + threadFindings.Count);
        foreach (var finding in asyncFindings.Concat(threadFindings))
        {
            var metadata = ParseMetadata(finding.Metadata);
            var pattern = ReadString(metadata, "pattern") ?? finding.RuleId;
            rows.Add(new AsyncIssueRowDto(
                finding.RuleId,
                pattern,
                finding.FilePath,
                finding.Line,
                finding.Message));
        }

        return rows
            .OrderBy(row => row.PatternType, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.Line)
            .ToList();
    }

    private static IReadOnlyList<TechDebtAgingBucketDto> BuildAgingBuckets(IReadOnlyList<TechDebtRowDto> techDebtRows)
    {
        var buckets = new[]
        {
            new TechDebtAgingBucketDto("< 30d", 0),
            new TechDebtAgingBucketDto("30-90d", 0),
            new TechDebtAgingBucketDto("90-180d", 0),
            new TechDebtAgingBucketDto("180d-1y", 0),
            new TechDebtAgingBucketDto("> 1y", 0)
        };

        foreach (var row in techDebtRows)
        {
            if (!row.AgeDays.HasValue)
            {
                continue;
            }

            var age = row.AgeDays.Value;
            var index = age switch
            {
                < 30 => 0,
                <= 90 => 1,
                <= 180 => 2,
                <= 365 => 3,
                _ => 4
            };

            buckets[index] = buckets[index] with { Count = buckets[index].Count + 1 };
        }

        return buckets;
    }

    private static JsonElement? ParseMetadata(string? metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(metadata);
            return document.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyList<FeatureFlagLocationDto> ReadLocations(JsonElement? metadata, string fallbackFilePath, long fallbackLine)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return [new FeatureFlagLocationDto(fallbackFilePath, fallbackLine)];
        }

        if (!TryGetProperty(metadata.Value, "locations", out var locationsElement) || locationsElement.ValueKind != JsonValueKind.Array)
        {
            return [new FeatureFlagLocationDto(fallbackFilePath, fallbackLine)];
        }

        var rows = new List<FeatureFlagLocationDto>();
        foreach (var location in locationsElement.EnumerateArray())
        {
            if (location.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var filePath = ReadString(location, "FilePath") ?? ReadString(location, "filePath") ?? fallbackFilePath;
            var line = ReadLong(location, "Line") ?? ReadLong(location, "line") ?? fallbackLine;
            rows.Add(new FeatureFlagLocationDto(filePath, line));
        }

        if (rows.Count == 0)
        {
            rows.Add(new FeatureFlagLocationDto(fallbackFilePath, fallbackLine));
        }

        return rows;
    }

    private static int? ReadRoundedInt(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!TryGetProperty(metadata.Value, propertyName, out var property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out var doubleValue))
        {
            return (int)Math.Round(doubleValue);
        }

        if (property.ValueKind == JsonValueKind.String &&
            double.TryParse(property.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
        {
            return (int)Math.Round(parsed);
        }

        return null;
    }

    private static int? ReadInt(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!TryGetProperty(metadata.Value, propertyName, out var property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var intValue))
        {
            return intValue;
        }

        if (property.ValueKind == JsonValueKind.String &&
            int.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static long? ReadLong(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return ReadLong(metadata.Value, propertyName);
    }

    private static long? ReadLong(JsonElement element, string propertyName)
    {
        if (!TryGetProperty(element, propertyName, out var property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out var longValue))
        {
            return longValue;
        }

        if (property.ValueKind == JsonValueKind.String &&
            long.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static string? ReadString(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return ReadString(metadata.Value, propertyName);
    }

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (!TryGetProperty(element, propertyName, out var property))
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : property.ToString();
    }

    private static bool TryGetProperty(JsonElement element, string propertyName, out JsonElement value)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            value = default;
            return false;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }
}

public sealed record HygieneViewModel(
    IReadOnlyList<FeatureFlagRowDto> FeatureFlags,
    IReadOnlyList<TechDebtRowDto> TechDebt,
    IReadOnlyList<AsyncIssueRowDto> AsyncIssues,
    IReadOnlyList<TechDebtAgingBucketDto> TechDebtAging,
    int TechDebtCount,
    int AsyncIssueCount);

public sealed record FeatureFlagRowDto(
    string RuleId,
    string FlagName,
    long ReferenceCount,
    long DefinitionCount,
    int? AgeDays,
    string Status,
    string FilePath,
    long Line,
    string Message,
    IReadOnlyList<FeatureFlagLocationDto> Locations);

public sealed record FeatureFlagLocationDto(
    string FilePath,
    long Line);

public sealed record TechDebtRowDto(
    long FindingId,
    string RuleId,
    string Keyword,
    int? AgeDays,
    string Author,
    string FilePath,
    long Line,
    string Message);

public sealed record AsyncIssueRowDto(
    string RuleId,
    string PatternType,
    string FilePath,
    long Line,
    string Explanation);

public sealed record TechDebtAgingBucketDto(
    string Label,
    int Count);
