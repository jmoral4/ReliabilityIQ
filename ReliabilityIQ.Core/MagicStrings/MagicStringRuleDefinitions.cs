using System.Collections.Frozen;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.MagicStrings;

public static class MagicStringRuleDefinitions
{
    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            "magic-string.high-frequency",
            "High Frequency Magic String",
            FindingSeverity.Info,
            "Repeated string literal used across the repository; consider extracting to constants/configuration."),
        new(
            "magic-string.comparison-used",
            "Magic String Used In Comparisons",
            FindingSeverity.Info,
            "String literal is used in comparisons or branching logic and is a strong candidate for centralization."),
        new(
            "magic-string.candidate",
            "Magic String Candidate",
            FindingSeverity.Info,
            "Potential magic string opportunity ranked by frequency and usage context.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } =
        Rules.ToFrozenDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<RuleDefinition> AllRules =>
        Portability.PortabilityRuleDefinitions.Rules.Concat(Rules).ToList();
}
