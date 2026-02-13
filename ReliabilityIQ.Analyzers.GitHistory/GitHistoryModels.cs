using ReliabilityIQ.Core;

namespace ReliabilityIQ.Analyzers.GitHistory;

public sealed record GitHistoryFileInput(
    string FilePath,
    FileCategory Category,
    long SizeBytes,
    string? Language);

public sealed record GitFileAnalysisResult(
    string FilePath,
    DateTimeOffset? LastCommitAt,
    int Commits30d,
    int Commits90d,
    int Commits180d,
    int Commits365d,
    int Authors365d,
    double OwnershipConcentration,
    int LinesAdded365d,
    int LinesRemoved365d,
    double ChurnScore,
    double? StaleScore,
    string? TopAuthor,
    double TopAuthorPct,
    DateTimeOffset? TopAuthorLastCommitAt,
    bool NeverChangedSinceImport,
    bool IsOwnershipRisk,
    string ModuleDirectory,
    string ModuleProject,
    string ModuleService);

public sealed record GitModuleAggregate(
    string ModuleKey,
    int FileCount,
    double ChurnScoreP90,
    double StaleScoreP90,
    double OwnershipConcentrationP90);

public sealed record GitHistoryAnalysisResult(
    IReadOnlyList<GitFileAnalysisResult> Files,
    IReadOnlyList<GitModuleAggregate> DirectoryAggregates,
    IReadOnlyList<GitModuleAggregate> ProjectAggregates,
    IReadOnlyList<GitModuleAggregate> ServiceAggregates,
    string? HeadCommitSha);
