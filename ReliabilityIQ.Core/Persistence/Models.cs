namespace ReliabilityIQ.Core.Persistence;

public sealed record ScanRun(
    string RunId,
    string RepoRoot,
    string? CommitSha,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    string ToolVersion,
    string? ConfigHash);

public sealed record PersistedFile(
    string Path,
    FileCategory Category,
    long SizeBytes,
    string Hash,
    string? Language);

public sealed record RuleDefinition(
    string RuleId,
    string Title,
    FindingSeverity DefaultSeverity,
    string Description);

public sealed record GitFileMetric(
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
    double TopAuthorPct);
