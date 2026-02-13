using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.Configuration;

public sealed record ScanConfig(
    string? RepoRoot,
    IReadOnlyList<string> Excludes,
    string? SnippetMode,
    IReadOnlyList<string> ScanTargets,
    bool? UseGitIgnore,
    bool? ExcludeDotDirectories,
    long? MaxFileSizeBytes);

public sealed record RuleConfig(
    IReadOnlyDictionary<string, RuleOverrideConfig> RuleOverrides,
    IReadOnlyList<CustomRegexRuleConfig> CustomRules);

public sealed record RuleOverrideConfig(
    bool? Enabled,
    FindingSeverity? Severity,
    string SourceFile,
    int Precedence);

public sealed record AllowlistConfig(IReadOnlyList<AllowlistEntryConfig> Entries);

public sealed record AllowlistEntryConfig(
    string PathGlob,
    string RuleId,
    string? Pattern,
    string SourceFile);

public sealed record SuppressionConfig(IReadOnlyList<SuppressionEntryConfig> Entries);

public sealed record SuppressionEntryConfig(
    string PathGlob,
    string RuleId,
    string? Fingerprint,
    string SourceFile);

public sealed record CustomRegexRuleConfig(
    string Id,
    string Pattern,
    IReadOnlySet<FileCategory> FileCategories,
    FindingSeverity Severity,
    string Message,
    bool Enabled,
    string SourceFile,
    string? Title,
    string? Description);

public sealed record EffectiveRuleEntry(
    RuleDefinition Definition,
    bool Enabled,
    FindingSeverity Severity,
    string Source);

public sealed record CliRuleOverrides(
    FindingSeverity? PortabilityFailOn,
    int? MagicMinOccurrences,
    int? MagicTop,
    int? ChurnSinceDays,
    IReadOnlyList<string>? DeployEv2PathMarkers,
    IReadOnlyList<string>? DeployAdoPathMarkers);

public enum ValidationIssueSeverity
{
    Error = 0,
    Warning = 1
}

public sealed record ValidationIssue(
    ValidationIssueSeverity Severity,
    string File,
    string Message);

public sealed record RuleValidationResult(
    IReadOnlyList<ValidationIssue> Issues)
{
    public bool IsValid => Issues.All(i => i.Severity != ValidationIssueSeverity.Error);
}
