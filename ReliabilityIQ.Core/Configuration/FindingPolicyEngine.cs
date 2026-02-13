using System.Text.RegularExpressions;

namespace ReliabilityIQ.Core.Configuration;

public static class FindingPolicyEngine
{
    public static IReadOnlyList<Finding> Apply(IReadOnlyList<Finding> findings, RuleConfigurationBundle config)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(config);

        var filtered = new List<Finding>(findings.Count);
        foreach (var finding in findings)
        {
            if (config.EffectiveRules.TryGetValue(finding.RuleId, out var rule) && !rule.Enabled)
            {
                continue;
            }

            if (IsAllowlisted(finding, config.Allowlists.Entries))
            {
                continue;
            }

            if (rule is not null && finding.Severity != rule.Severity)
            {
                filtered.Add(finding with { Severity = rule.Severity });
                continue;
            }

            filtered.Add(finding);
        }

        return filtered;
    }

    private static bool IsAllowlisted(Finding finding, IReadOnlyList<AllowlistEntryConfig> entries)
    {
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.RuleId, finding.RuleId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!GlobUtility.IsMatch(finding.FilePath, entry.PathGlob))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(entry.Pattern))
            {
                return true;
            }

            var targetText = $"{finding.Message}\n{finding.Snippet}";
            if (Regex.IsMatch(targetText, entry.Pattern, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
