using ReliabilityIQ.Core;

namespace ReliabilityIQ.Analyzers.GitHistory;

public sealed record GitHistoryAnalysisOptions(
    int SinceDays,
    bool IncludeDiffStats,
    IReadOnlyList<string> StaleIgnorePatterns,
    IReadOnlySet<FileCategory> StalenessCategories,
    IReadOnlyDictionary<string, string> ServiceBoundaryMappings,
    int TopAuthorInactiveDays,
    double OwnershipConcentrationThreshold,
    int ImportCommitLargeChangeThreshold)
{
    public static GitHistoryAnalysisOptions CreateDefault() => new(
        SinceDays: 365,
        IncludeDiffStats: true,
        StaleIgnorePatterns:
        [
            "*.designer.cs",
            "*.g.cs",
            "*.generated.*",
            "packages.lock.json",
            "yarn.lock",
            "RolloutSpec.generated.json"
        ],
        StalenessCategories: new HashSet<FileCategory>
        {
            FileCategory.Source,
            FileCategory.DeploymentArtifact
        },
        ServiceBoundaryMappings: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        TopAuthorInactiveDays: 90,
        OwnershipConcentrationThreshold: 0.8d,
        ImportCommitLargeChangeThreshold: 500);
}
