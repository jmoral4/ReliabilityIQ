using System.Text.Json;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.ConfigDrift;

public static class ConfigDriftProjection
{
    private static readonly Regex SensitiveKeyRegex = new(
        "(password|passwd|secret|token|apikey|api_key|connectionstring|connstr|privatekey|clientsecret)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static ConfigDriftMatrixDto BuildMatrix(IReadOnlyList<FindingListItem> findings)
    {
        var byCompositeKey = new Dictionary<string, MutableRow>(StringComparer.OrdinalIgnoreCase);
        var environmentSet = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var finding in findings)
        {
            var metadata = ParseMetadata(finding.Metadata);
            if (!TryReadMetadataString(metadata, "key", out var key) ||
                !TryReadMetadataString(metadata, "configSet", out var configSet))
            {
                continue;
            }

            var environments = ReadStringArray(metadata, "environments");
            var presentEnvironments = ReadStringArray(metadata, "presentEnvironments");
            var missingEnvironments = ReadStringArray(metadata, "missingEnvironments");
            var valueDiffers = ReadBoolean(metadata, "valueDiffers");
            var previews = ReadValuePreviews(metadata);

            foreach (var environment in environments)
            {
                environmentSet.Add(environment);
            }

            var compositeKey = $"{configSet}::{key}";
            if (!byCompositeKey.TryGetValue(compositeKey, out var row))
            {
                row = new MutableRow(configSet, key);
                byCompositeKey[compositeKey] = row;
            }

            foreach (var environment in environments)
            {
                row.Environments.Add(environment);
            }

            foreach (var environment in presentEnvironments)
            {
                row.PresentEnvironments.Add(environment);
            }

            foreach (var environment in missingEnvironments)
            {
                row.MissingEnvironments.Add(environment);
            }

            foreach (var preview in previews)
            {
                row.PreviewByEnvironment[preview.Environment] = preview.Value;
                if (valueDiffers)
                {
                    row.DiffersEnvironments.Add(preview.Environment);
                }
            }

            row.RuleIds.Add(finding.RuleId);
        }

        var environmentsOrdered = environmentSet.ToList();
        var rows = byCompositeKey.Values
            .OrderBy(r => r.ConfigSet, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
            .Select(r => ToDto(r, environmentsOrdered))
            .ToList();

        return new ConfigDriftMatrixDto(
            environmentsOrdered,
            rows,
            rows.Select(row => row.ConfigSet)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                .ToList());
    }

    public static ConfigDriftMatrixDto ApplyFiltersAndSort(
        ConfigDriftMatrixDto matrix,
        string? search,
        string? configSet,
        bool issuesOnly,
        string? sortBy,
        bool descending)
    {
        IEnumerable<ConfigDriftMatrixRowDto> rows = matrix.Rows;

        if (!string.IsNullOrWhiteSpace(configSet))
        {
            rows = rows.Where(row => row.ConfigSet.Equals(configSet.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            rows = rows.Where(row =>
                row.Key.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                row.ConfigSet.Contains(term, StringComparison.OrdinalIgnoreCase));
        }

        if (issuesOnly)
        {
            rows = rows.Where(row => row.MissingCount > 0 || row.DiffersCount > 0);
        }

        rows = sortBy?.Trim().ToLowerInvariant() switch
        {
            "missing" => descending
                ? rows.OrderByDescending(r => r.MissingCount).ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(r => r.MissingCount).ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase),
            "differs" => descending
                ? rows.OrderByDescending(r => r.DiffersCount).ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(r => r.DiffersCount).ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase),
            "configset" => descending
                ? rows.OrderByDescending(r => r.ConfigSet, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(r => r.ConfigSet, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase),
            _ => descending
                ? rows.OrderByDescending(r => r.Key, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
        };

        return new ConfigDriftMatrixDto(matrix.Environments, rows.ToList(), matrix.ConfigSets);
    }

    private static ConfigDriftMatrixRowDto ToDto(MutableRow row, IReadOnlyList<string> allEnvironments)
    {
        var sensitive = SensitiveKeyRegex.IsMatch(row.Key);
        var cells = new List<ConfigDriftMatrixCellDto>(allEnvironments.Count);

        foreach (var environment in allEnvironments)
        {
            var isPresent = row.PresentEnvironments.Contains(environment);
            var isMissing = row.MissingEnvironments.Contains(environment) || !isPresent;
            var differs = row.DiffersEnvironments.Contains(environment);

            var status = isMissing
                ? "missing"
                : differs
                    ? "differs"
                    : "present";

            row.PreviewByEnvironment.TryGetValue(environment, out var preview);
            var displayValue = sensitive && !string.IsNullOrWhiteSpace(preview)
                ? "[REDACTED]"
                : preview;

            cells.Add(new ConfigDriftMatrixCellDto(
                environment,
                status,
                displayValue,
                sensitive));
        }

        return new ConfigDriftMatrixRowDto(
            row.ConfigSet,
            row.Key,
            cells,
            cells.Count(cell => cell.Status == "missing"),
            cells.Count(cell => cell.Status == "differs"),
            row.RuleIds.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList());
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

    private static bool TryReadMetadataString(JsonElement? metadata, string propertyName, out string value)
    {
        value = string.Empty;
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!metadata.Value.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool ReadBoolean(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!metadata.Value.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.True && property.ValueKind != JsonValueKind.False)
        {
            return false;
        }

        return property.GetBoolean();
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement? metadata, string propertyName)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<string>();
        }

        if (!metadata.Value.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        return property.EnumerateArray()
            .Where(element => element.ValueKind == JsonValueKind.String)
            .Select(element => element.GetString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<ValuePreviewDto> ReadValuePreviews(JsonElement? metadata)
    {
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<ValuePreviewDto>();
        }

        if (!metadata.Value.TryGetProperty("valuePreviews", out var property) || property.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<ValuePreviewDto>();
        }

        var previews = new List<ValuePreviewDto>();
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (!item.TryGetProperty("Environment", out var envProperty) && !item.TryGetProperty("environment", out envProperty))
            {
                continue;
            }

            if (!item.TryGetProperty("Value", out var valueProperty) && !item.TryGetProperty("value", out valueProperty))
            {
                continue;
            }

            var environment = envProperty.GetString();
            var value = valueProperty.GetString();
            if (string.IsNullOrWhiteSpace(environment) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            previews.Add(new ValuePreviewDto(environment, value));
        }

        return previews;
    }

    private sealed class MutableRow
    {
        public MutableRow(string configSet, string key)
        {
            ConfigSet = configSet;
            Key = key;
        }

        public string ConfigSet { get; }

        public string Key { get; }

        public HashSet<string> Environments { get; } = new(StringComparer.OrdinalIgnoreCase);

        public HashSet<string> PresentEnvironments { get; } = new(StringComparer.OrdinalIgnoreCase);

        public HashSet<string> MissingEnvironments { get; } = new(StringComparer.OrdinalIgnoreCase);

        public HashSet<string> DiffersEnvironments { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<string, string> PreviewByEnvironment { get; } = new(StringComparer.OrdinalIgnoreCase);

        public HashSet<string> RuleIds { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}

public sealed record ConfigDriftMatrixDto(
    IReadOnlyList<string> Environments,
    IReadOnlyList<ConfigDriftMatrixRowDto> Rows,
    IReadOnlyList<string> ConfigSets);

public sealed record ConfigDriftMatrixRowDto(
    string ConfigSet,
    string Key,
    IReadOnlyList<ConfigDriftMatrixCellDto> Cells,
    int MissingCount,
    int DiffersCount,
    IReadOnlyList<string> RuleIds);

public sealed record ConfigDriftMatrixCellDto(
    string Environment,
    string Status,
    string? ValuePreview,
    bool Sensitive);

public sealed record ValuePreviewDto(string Environment, string Value);
