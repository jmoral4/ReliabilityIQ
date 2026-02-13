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
    string? FileCategory = null,
    string? Language = null,
    string? PathPrefix = null);

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

public sealed record FindingListItem(
    long FindingId,
    string RuleId,
    string FilePath,
    long Line,
    long Column,
    string Message,
    string? Snippet,
    string Severity,
    string Confidence,
    string? FileCategory,
    string? Language);

public sealed record FindingsPage(
    int TotalCount,
    int FilteredCount,
    IReadOnlyList<FindingListItem> Items);

public sealed record FileSummaryItem(
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
    long FindingCount,
    long ErrorCount,
    long WarningCount,
    long InfoCount);
