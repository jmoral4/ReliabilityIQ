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

public sealed record DeployFindingsQueryFilters(
    string? ArtifactType = null,
    string? RuleSubcategory = null,
    string? Severity = null,
    bool IncludeSuppressed = false);

public enum DeployFindingsSortField
{
    ArtifactType,
    Severity,
    RuleId,
    FilePath,
    LocationPath
}

public sealed record DeployFindingsQueryRequest(
    int Offset,
    int Limit,
    DeployFindingsSortField SortField,
    bool SortDescending,
    DeployFindingsQueryFilters Filters)
{
    public static DeployFindingsQueryRequest Default { get; } = new(
        Offset: 0,
        Limit: 50,
        SortField: DeployFindingsSortField.Severity,
        SortDescending: false,
        Filters: new DeployFindingsQueryFilters());
}

public sealed class DeployFindingListItem
{
    public long FindingId { get; init; }

    public long FileId { get; init; }

    public string ArtifactType { get; init; } = string.Empty;

    public string RuleSubcategory { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public string RuleTitle { get; init; } = string.Empty;

    public string RuleDescription { get; init; } = string.Empty;

    public string FilePath { get; init; } = string.Empty;

    public long Line { get; init; }

    public long Column { get; init; }

    public string Severity { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string? Snippet { get; init; }

    public string? LocationPath { get; init; }

    public string? Metadata { get; init; }

    public bool IsSuppressed { get; init; }
}

public sealed record DeployFindingsPage(
    int TotalCount,
    int FilteredCount,
    IReadOnlyList<DeployFindingListItem> Items);

public sealed record DeploymentSeveritySummaryItem(
    string ArtifactType,
    long ErrorCount,
    long WarningCount,
    long InfoCount)
{
    public long TotalCount => ErrorCount + WarningCount + InfoCount;
}

public sealed record DeploymentArtifactRiskItem(
    long FileId,
    string FilePath,
    string ArtifactType,
    long ErrorCount,
    long WarningCount,
    long InfoCount,
    double RiskScore)
{
    public long TotalCount => ErrorCount + WarningCount + InfoCount;
}

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

public enum GitMetricsSortField
{
    FilePath,
    ChurnScore,
    StaleScore,
    Commits90d,
    Authors365d,
    OwnershipConcentration,
    LastCommitAt
}

public sealed record GitMetricsQueryFilters(
    double? MinChurnScore = null,
    double? MaxStaleScore = null,
    string? PathPrefix = null);

public sealed record GitMetricsQueryRequest(
    int Offset,
    int Limit,
    GitMetricsSortField SortField,
    bool SortDescending,
    GitMetricsQueryFilters Filters)
{
    public static GitMetricsQueryRequest Default { get; } = new(
        Offset: 0,
        Limit: 50,
        SortField: GitMetricsSortField.ChurnScore,
        SortDescending: true,
        Filters: new GitMetricsQueryFilters());
}

public sealed class GitMetricListItem
{
    public long FileId { get; set; }

    public string FilePath { get; set; } = string.Empty;

    public double ChurnScore { get; set; }

    public double? StaleScore { get; set; }

    public long Commits90d { get; set; }

    public long Authors365d { get; set; }

    public double OwnershipConcentration { get; set; }

    public string? TopAuthor { get; set; }

    public double TopAuthorPct { get; set; }

    public string? LastCommitAt { get; set; }

    public long IsOrphaned { get; set; }
}

public sealed record GitMetricsPage(
    int TotalCount,
    int FilteredCount,
    IReadOnlyList<GitMetricListItem> Items);

public enum HeatmapMetric
{
    ChurnHotspots,
    StaleRisk,
    OwnershipRisk,
    PortabilityBlockers,
    FindingDensity
}

public sealed record HeatmapFileMetricRow(
    long FileId,
    string FilePath,
    long SizeBytes,
    double ChurnScore,
    double StaleScore,
    double OwnershipRisk,
    long PortabilityFindingCount,
    long FindingCount)
{
    public double PortabilityBlockers => PortabilityFindingCount;

    public double FindingDensity => FindingCount;

    public double GetMetricValue(HeatmapMetric metric) => metric switch
    {
        HeatmapMetric.ChurnHotspots => ChurnScore,
        HeatmapMetric.StaleRisk => StaleScore,
        HeatmapMetric.OwnershipRisk => OwnershipRisk,
        HeatmapMetric.PortabilityBlockers => PortabilityBlockers,
        HeatmapMetric.FindingDensity => FindingDensity,
        _ => ChurnScore
    };
}

public sealed record DirectoryAggregateItem(
    string DirectoryPath,
    int Depth,
    long FileCount,
    long TotalSizeBytes,
    double MetricValue,
    double ChurnScore,
    double StaleScore,
    double OwnershipRisk,
    double PortabilityBlockers,
    double FindingDensity);

public sealed class TreemapNode
{
    public string Name { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public bool IsDirectory { get; init; }

    public long? FileId { get; init; }

    public long SizeBytes { get; set; }

    public long FileCount { get; set; }

    public double MetricValue { get; set; }

    public double ChurnScore { get; set; }

    public double StaleScore { get; set; }

    public double OwnershipRisk { get; set; }

    public double PortabilityBlockers { get; set; }

    public double FindingDensity { get; set; }

    public List<TreemapNode> Children { get; } = [];
}

public sealed record DirectoryDrilldown(
    string DirectoryPath,
    long FileCount,
    long TotalSizeBytes,
    double MetricValue,
    IReadOnlyList<FileSummaryItem> TopFiles,
    IReadOnlyList<RuleSummaryItem> TopRules);

public sealed record RuleCatalogItem(
    string RuleId,
    string Title,
    string DefaultSeverity,
    string Description,
    string Category,
    string EffectiveState,
    long TotalFindings);

public sealed record RuleFindingAcrossRunsItem(
    string RunId,
    string RepoRoot,
    DateTimeOffset StartedAt,
    string FilePath,
    long Line,
    long Column,
    string Severity,
    string Message,
    string Confidence,
    string? Fingerprint);

public sealed record SuppressedFindingItem(
    long FindingId,
    long FileId,
    string FilePath,
    string RuleId,
    string RuleTitle,
    string Severity,
    string Confidence,
    string Message,
    string? SuppressionReason,
    string SuppressionSource,
    string? Metadata);

public sealed record SuppressionSummary(
    string RuleId,
    string Title,
    long SuppressedCount);

public sealed record SuppressionOverview(
    long ActiveFindingCount,
    long SuppressedFindingCount,
    long WhatIfTotalFindingCount,
    IReadOnlyList<SuppressionSummary> CountsByRule,
    IReadOnlyList<SuppressedFindingItem> SuppressedFindings);

public sealed record RunComparisonRequest(
    string BaselineRunId,
    string TargetRunId);

public sealed record RunComparisonFinding(
    string Fingerprint,
    string RuleId,
    string FilePath,
    long Line,
    string Severity,
    string Message,
    string Confidence);

public sealed record RunComparisonResult(
    string BaselineRunId,
    string TargetRunId,
    long NewCount,
    long FixedCount,
    long UnchangedCount,
    IReadOnlyList<RunComparisonFinding> NewFindings,
    IReadOnlyList<RunComparisonFinding> FixedFindings);

public sealed record ExportFindingItem(
    long FindingId,
    string RunId,
    long FileId,
    string RuleId,
    string RuleTitle,
    string RuleDescription,
    string FilePath,
    long Line,
    long Column,
    string Message,
    string? Snippet,
    string Severity,
    string Confidence,
    string? FileCategory,
    string? Language,
    string? Fingerprint,
    string? Metadata,
    bool AstConfirmed,
    bool IsSuppressed,
    string? SuppressionReason,
    string? SuppressionSource);
