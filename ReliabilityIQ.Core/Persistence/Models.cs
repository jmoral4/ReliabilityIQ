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
