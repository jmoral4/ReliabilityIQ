using ReliabilityIQ.Core.Artifacts;
using ReliabilityIQ.Core.GitHistory;
using ReliabilityIQ.Core.MagicStrings;
using ReliabilityIQ.Core.Persistence;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Core.Configuration;

public static class RuleCatalog
{
    public static IReadOnlyList<RuleDefinition> GetBuiltInDefinitions()
    {
        var byId = new Dictionary<string, RuleDefinition>(StringComparer.OrdinalIgnoreCase);

        Add(byId, PortabilityRuleDefinitions.Rules);
        Add(byId, MagicStringRuleDefinitions.Rules);
        Add(byId, GitHistoryRuleDefinitions.Rules);
        Add(byId, ArtifactRuleDefinitions.Rules);

        return byId.Values
            .OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static string GetCategory(string ruleId)
    {
        if (ruleId.StartsWith("portability.", StringComparison.OrdinalIgnoreCase))
        {
            return "portability";
        }

        if (ruleId.StartsWith("magic-string.", StringComparison.OrdinalIgnoreCase))
        {
            return "magic-strings";
        }

        if (ruleId.StartsWith("churn.", StringComparison.OrdinalIgnoreCase))
        {
            return "churn";
        }

        if (ruleId.StartsWith("deploy.ev2.", StringComparison.OrdinalIgnoreCase))
        {
            return "deploy-ev2";
        }

        if (ruleId.StartsWith("deploy.ado.", StringComparison.OrdinalIgnoreCase) ||
            ruleId.StartsWith("deploy.artifact.", StringComparison.OrdinalIgnoreCase))
        {
            return "deploy-ado";
        }

        if (ruleId.StartsWith("incident.", StringComparison.OrdinalIgnoreCase))
        {
            return "incidents";
        }

        if (ruleId.StartsWith("custom.", StringComparison.OrdinalIgnoreCase))
        {
            return "custom";
        }

        return "other";
    }

    private static void Add(IDictionary<string, RuleDefinition> target, IEnumerable<RuleDefinition> rules)
    {
        foreach (var rule in rules)
        {
            target[rule.RuleId] = rule;
        }
    }
}
