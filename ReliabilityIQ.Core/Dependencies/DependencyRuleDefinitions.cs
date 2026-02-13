using System.Collections.Frozen;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.Dependencies;

public static class DependencyRuleDefinitions
{
    public const string VulnerableCriticalRuleId = "deps.vulnerable.critical";
    public const string VulnerableHighRuleId = "deps.vulnerable.high";
    public const string VulnerableMediumRuleId = "deps.vulnerable.medium";
    public const string EolFrameworkRuleId = "deps.eol.framework";
    public const string UnpinnedVersionRuleId = "deps.unpinned_version";

    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            VulnerableCriticalRuleId,
            "Dependency Vulnerability Critical",
            FindingSeverity.Error,
            "Dependency has a known critical vulnerability from an advisory source."),
        new(
            VulnerableHighRuleId,
            "Dependency Vulnerability High",
            FindingSeverity.Error,
            "Dependency has a known high-severity vulnerability from an advisory source."),
        new(
            VulnerableMediumRuleId,
            "Dependency Vulnerability Medium",
            FindingSeverity.Warning,
            "Dependency has a known medium-severity vulnerability from an advisory source."),
        new(
            EolFrameworkRuleId,
            "End-of-Life Framework",
            FindingSeverity.Warning,
            "Project targets a framework/runtime version that is out of support."),
        new(
            UnpinnedVersionRuleId,
            "Unpinned Dependency Version",
            FindingSeverity.Warning,
            "Dependency version is not pinned to an exact version and may drift unexpectedly.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } =
        Rules.ToFrozenDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
}
