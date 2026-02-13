using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.MagicStrings;

public static partial class MagicStringsProjection
{
    public static IReadOnlyList<MagicStringCandidateDto> BuildCandidates(IReadOnlyList<FindingListItem> findings)
    {
        var candidates = new List<MagicStringCandidateDto>(findings.Count);

        foreach (var finding in findings)
        {
            var metadata = ParseMetadata(finding.Metadata);
            var occurrences = ParseOccurrences(metadata, finding);

            var magicScore = ReadMagicScore(metadata, finding.Message);
            var occurrenceCount = occurrences.Count > 0
                ? occurrences.Count
                : Math.Max(1, ReadOccurrenceCount(finding.Message));

            var literal = ExtractLiteral(finding.Message, occurrences, finding.Snippet);
            var top = ReadTopLocation(metadata, occurrences, finding);

            var languages = occurrences
                .Select(o => o.Language)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (languages.Count == 0 && !string.IsNullOrWhiteSpace(finding.Language))
            {
                languages.Add(finding.Language);
            }

            candidates.Add(new MagicStringCandidateDto
            {
                FindingId = finding.FindingId,
                RuleId = finding.RuleId,
                Literal = literal,
                MagicScore = magicScore,
                OccurrenceCount = occurrenceCount,
                TopFilePath = top.File,
                TopLine = top.Line,
                TopColumn = top.Column,
                Module = GetModule(top.File),
                ContextSummary = ReadString(metadata, "contextSummary"),
                Languages = languages,
                Occurrences = occurrences
            });
        }

        return candidates
            .OrderByDescending(c => c.MagicScore)
            .ThenByDescending(c => c.OccurrenceCount)
            .ThenBy(c => c.Literal, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static IReadOnlyList<MagicStringCandidateDto> ApplyFilters(
        IReadOnlyList<MagicStringCandidateDto> candidates,
        double minScore,
        int minOccurrences,
        string? language,
        string? pathPrefix)
    {
        var normalizedPrefix = NormalizePrefix(pathPrefix);
        var normalizedLanguage = language?.Trim();

        return candidates
            .Where(c => c.MagicScore >= minScore)
            .Where(c => c.OccurrenceCount >= minOccurrences)
            .Where(c => string.IsNullOrWhiteSpace(normalizedLanguage) || c.Languages.Any(l => string.Equals(l, normalizedLanguage, StringComparison.OrdinalIgnoreCase)))
            .Where(c =>
                string.IsNullOrWhiteSpace(normalizedPrefix) ||
                c.Occurrences.Any(o => o.File.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase)) ||
                c.TopFilePath.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(c => c.MagicScore)
            .ThenByDescending(c => c.OccurrenceCount)
            .ThenBy(c => c.Literal, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static IReadOnlyList<MagicStringCandidateDto> ApplyScope(
        IReadOnlyList<MagicStringCandidateDto> candidates,
        string scope,
        int topN)
    {
        if (string.Equals(scope, "module", StringComparison.OrdinalIgnoreCase))
        {
            return candidates
                .GroupBy(c => c.Module, StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .SelectMany(g => g.Take(topN))
                .ToList();
        }

        return candidates.Take(topN).ToList();
    }

    public static IReadOnlyList<MagicStringModuleGroupDto> BuildModuleGroups(
        IReadOnlyList<MagicStringCandidateDto> candidates,
        int topN)
    {
        return candidates
            .GroupBy(c => c.Module, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new MagicStringModuleGroupDto
            {
                Module = g.Key,
                TotalCandidates = g.Count(),
                Candidates = g.Take(topN).ToList()
            })
            .ToList();
    }

    private static List<MagicStringOccurrenceDto> ParseOccurrences(JsonElement? metadata, FindingListItem finding)
    {
        var occurrences = new List<MagicStringOccurrenceDto>();
        if (!metadata.HasValue || metadata.Value.ValueKind != JsonValueKind.Object)
        {
            return occurrences;
        }

        if (!metadata.Value.TryGetProperty("allOccurrences", out var allOccurrences) || allOccurrences.ValueKind != JsonValueKind.Array)
        {
            return occurrences;
        }

        foreach (var entry in allOccurrences.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var file = ReadString(entry, "file") ?? finding.FilePath;
            var line = ReadInt(entry, "line", finding.Line);
            var column = ReadInt(entry, "column", finding.Column);
            occurrences.Add(new MagicStringOccurrenceDto
            {
                File = file,
                Line = line,
                Column = column,
                Language = ReadString(entry, "language") ?? finding.Language ?? string.Empty,
                AstParent = ReadString(entry, "astParent") ?? string.Empty,
                Callsite = ReadString(entry, "callsite") ?? string.Empty,
                Comparison = ReadBool(entry, "comparison"),
                Conditional = ReadBool(entry, "conditional"),
                Exception = ReadBool(entry, "exception"),
                AstConfirmed = ReadBool(entry, "astConfirmed"),
                TestCode = ReadBool(entry, "testCode"),
                Raw = ReadString(entry, "raw") ?? string.Empty
            });
        }

        return occurrences;
    }

    private static (string File, long Line, long Column) ReadTopLocation(
        JsonElement? metadata,
        IReadOnlyList<MagicStringOccurrenceDto> occurrences,
        FindingListItem finding)
    {
        if (metadata.HasValue &&
            metadata.Value.ValueKind == JsonValueKind.Object &&
            metadata.Value.TryGetProperty("topLocations", out var topLocations) &&
            topLocations.ValueKind == JsonValueKind.Array)
        {
            var first = topLocations.EnumerateArray().FirstOrDefault();
            if (first.ValueKind == JsonValueKind.Object)
            {
                return (
                    ReadString(first, "file") ?? finding.FilePath,
                    ReadInt(first, "line", finding.Line),
                    ReadInt(first, "column", finding.Column));
            }
        }

        if (occurrences.Count > 0)
        {
            var top = occurrences[0];
            return (top.File, top.Line, top.Column);
        }

        return (finding.FilePath, finding.Line, finding.Column);
    }

    private static double ReadMagicScore(JsonElement? metadata, string message)
    {
        if (metadata.HasValue &&
            metadata.Value.ValueKind == JsonValueKind.Object &&
            metadata.Value.TryGetProperty("scoring", out var scoring) &&
            scoring.ValueKind == JsonValueKind.Object &&
            scoring.TryGetProperty("magicScore", out var scoreElement))
        {
            if (scoreElement.TryGetDouble(out var score))
            {
                return score;
            }

            if (scoreElement.ValueKind == JsonValueKind.String &&
                double.TryParse(scoreElement.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var stringScore))
            {
                return stringScore;
            }
        }

        var match = ScoreRegex().Match(message);
        if (match.Success &&
            double.TryParse(match.Groups["score"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return 0d;
    }

    private static int ReadOccurrenceCount(string message)
    {
        var match = OccurrenceRegex().Match(message);
        return match.Success && int.TryParse(match.Groups["count"].Value, out var count)
            ? count
            : 1;
    }

    private static string ExtractLiteral(string message, IReadOnlyList<MagicStringOccurrenceDto> occurrences, string? snippet)
    {
        var match = LiteralRegex().Match(message);
        if (match.Success)
        {
            return match.Groups["literal"].Value;
        }

        if (occurrences.Count > 0 && !string.IsNullOrWhiteSpace(occurrences[0].Raw))
        {
            return occurrences[0].Raw;
        }

        return snippet ?? "n/a";
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

    private static string GetModule(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return ".";
        }

        var normalized = filePath.Replace('\\', '/');
        var index = normalized.LastIndexOf('/');
        return index <= 0 ? "." : normalized[..index];
    }

    private static string? NormalizePrefix(string? pathPrefix)
    {
        if (string.IsNullOrWhiteSpace(pathPrefix))
        {
            return null;
        }

        return pathPrefix.Trim().Replace('\\', '/');
    }

    private static string? ReadString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static string? ReadString(JsonElement? element, string property)
    {
        return element.HasValue && element.Value.ValueKind == JsonValueKind.Object
            ? ReadString(element.Value, property)
            : null;
    }

    private static long ReadInt(JsonElement element, string property, long fallback)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return fallback;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt64(out var parsed) => parsed,
            JsonValueKind.String when long.TryParse(value.GetString(), out var parsed) => parsed,
            _ => fallback
        };
    }

    private static bool ReadBool(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return false;
        }

        if (value.ValueKind == JsonValueKind.True)
        {
            return true;
        }

        if (value.ValueKind == JsonValueKind.String && bool.TryParse(value.GetString(), out var parsed))
        {
            return parsed;
        }

        return false;
    }

    [GeneratedRegex("score=(?<score>[0-9]+(?:\\.[0-9]+)?)", RegexOptions.CultureInvariant)]
    private static partial Regex ScoreRegex();

    [GeneratedRegex("occurrences=(?<count>[0-9]+)", RegexOptions.CultureInvariant)]
    private static partial Regex OccurrenceRegex();

    [GeneratedRegex("^Magic string candidate '(?<literal>.*)' score=", RegexOptions.CultureInvariant)]
    private static partial Regex LiteralRegex();
}

public sealed class MagicStringCandidateDto
{
    public long FindingId { get; init; }

    public string RuleId { get; init; } = string.Empty;

    public string Literal { get; init; } = string.Empty;

    public double MagicScore { get; init; }

    public int OccurrenceCount { get; init; }

    public string TopFilePath { get; init; } = string.Empty;

    public long TopLine { get; init; }

    public long TopColumn { get; init; }

    public string Module { get; init; } = ".";

    public string? ContextSummary { get; init; }

    public IReadOnlyList<string> Languages { get; init; } = [];

    public IReadOnlyList<MagicStringOccurrenceDto> Occurrences { get; init; } = [];
}

public sealed class MagicStringOccurrenceDto
{
    public string File { get; init; } = string.Empty;

    public long Line { get; init; }

    public long Column { get; init; }

    public string Language { get; init; } = string.Empty;

    public string AstParent { get; init; } = string.Empty;

    public string Callsite { get; init; } = string.Empty;

    public bool Comparison { get; init; }

    public bool Conditional { get; init; }

    public bool Exception { get; init; }

    public bool AstConfirmed { get; init; }

    public bool TestCode { get; init; }

    public string Raw { get; init; } = string.Empty;
}

public sealed class MagicStringModuleGroupDto
{
    public string Module { get; init; } = ".";

    public int TotalCandidates { get; init; }

    public IReadOnlyList<MagicStringCandidateDto> Candidates { get; init; } = [];
}
