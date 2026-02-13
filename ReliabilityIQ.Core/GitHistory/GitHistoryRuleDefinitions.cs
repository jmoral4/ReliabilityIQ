using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.GitHistory;

public static class GitHistoryRuleDefinitions
{
    public const string OwnershipOrphanedKnowledgeRiskRuleId = "churn.ownership.orphaned_knowledge_risk";

    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            OwnershipOrphanedKnowledgeRiskRuleId,
            "Orphaned Knowledge Risk",
            FindingSeverity.Warning,
            "File has concentrated ownership and the top contributor has been inactive recently, increasing bus-factor risk.")
    ];
}
