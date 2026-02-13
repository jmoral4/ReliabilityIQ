namespace ReliabilityIQ.Core.Persistence.Queries;

public sealed record RunListItem(
    string RunId,
    string RepoRoot,
    string? CommitSha,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    string ToolVersion,
    int ErrorCount,
    int WarningCount,
    int InfoCount)
{
    public int TotalFindings => ErrorCount + WarningCount + InfoCount;
}

public sealed record RunDetails(
    string RunId,
    string RepoRoot,
    string? CommitSha,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    string ToolVersion,
    int ErrorCount,
    int WarningCount,
    int InfoCount)
{
    public int TotalFindings => ErrorCount + WarningCount + InfoCount;
}

public sealed record FindingsQueryFilters(
    string? Severity = null,
    string? RuleId = null,
    string? RulePrefix = null,
    string? Confidence = null,
    string? FileCategory = null,
    string? Language = null,
    string? PathPrefix = null,
    bool IncludeSuppressed = false);

public enum FindingsSortField
{
    Severity,
    RuleId,
    FilePath,
    Line,
    Confidence
}

public sealed record FindingsQueryRequest(
    int Offset,
    int Limit,
    FindingsSortField SortField,
    bool SortDescending,
    FindingsQueryFilters Filters)
{
    public static FindingsQueryRequest Default { get; } = new(
        Offset: 0,
        Limit: 50,
        SortField: FindingsSortField.Severity,
        SortDescending: false,
        Filters: new FindingsQueryFilters());
}

public sealed class FindingListItem
{
    public long FindingId { get; init; }

    public long FileId { get; init; }

    public string RuleId { get; init; } = string.Empty;

    public string RuleTitle { get; init; } = string.Empty;

    public string RuleDescription { get; init; } = string.Empty;

    public string FilePath { get; init; } = string.Empty;

    public long Line { get; init; }

    public long Column { get; init; }

    public string Message { get; init; } = string.Empty;

    public string? Snippet { get; init; }

    public string Severity { get; init; } = string.Empty;

    public string Confidence { get; init; } = string.Empty;

    public string? FileCategory { get; init; }

    public string? Language { get; init; }

    public string? Metadata { get; init; }

    public bool AstConfirmed { get; init; }

    public bool IsSuppressed { get; init; }

    public string? SuppressionReason { get; init; }
}

public sealed record FindingsPage(
    int TotalCount,
    int FilteredCount,
    IReadOnlyList<FindingListItem> Items);

public sealed record FileSummaryItem(
    long FileId,
    string FilePath,
    string? Category,
    string? Language,
    long FindingCount,
    long ErrorCount,
    long WarningCount,
    long InfoCount);

public sealed record RuleSummaryItem(
    string RuleId,
    string Title,
    string? Description,
    long FindingCount,
    long ErrorCount,
    long WarningCount,
    long InfoCount);

public sealed record FileDetailItem(
    long FileId,
    string FilePath,
    string Category,
    string? Language,
    long SizeBytes,
    string Hash);

public sealed record ConfidenceSummaryItem(
    string Confidence,
    long FindingCount);

public sealed record LanguageSummaryItem(
    string Language,
    long FindingCount);

public sealed record AstSummary(
    long AstConfirmedCount,
    long RegexOnlyCount)
{
    public long TotalCount => AstConfirmedCount + RegexOnlyCount;
}
