using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.GitHistory;

public static class GitHistoryRuleDefinitions
{
    public const string OwnershipOrphanedKnowledgeRiskRuleId = "churn.ownership.orphaned_knowledge_risk";
    public const string StaleFileRiskRuleId = "churn.stale.file_risk";
    public const string NeverChangedSinceImportRuleId = "churn.ownership.never_changed_since_import";
    public const string AnalyzerUnavailableRuleId = "churn.analysis.unavailable";

    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            OwnershipOrphanedKnowledgeRiskRuleId,
            "Orphaned Knowledge Risk",
            FindingSeverity.Warning,
            "File has concentrated ownership and the top contributor has been inactive recently, increasing bus-factor risk."),
        new(
            StaleFileRiskRuleId,
            "Stale File Risk",
            FindingSeverity.Info,
            "File appears stale based on recency and category-adjusted stale scoring."),
        new(
            NeverChangedSinceImportRuleId,
            "Never Changed Since Import",
            FindingSeverity.Info,
            "File appears to have never changed since a likely import commit."),
        new(
            AnalyzerUnavailableRuleId,
            "Churn Analysis Unavailable",
            FindingSeverity.Info,
            "Git history analyzer could not run for this file and emitted a fallback diagnostic.")
    ];
}
