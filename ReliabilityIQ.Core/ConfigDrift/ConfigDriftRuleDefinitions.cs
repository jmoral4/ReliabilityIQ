using System.Collections.Frozen;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.ConfigDrift;

public static class ConfigDriftRuleDefinitions
{
    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            "config.drift.missing_key",
            "Configuration Drift Missing Key",
            FindingSeverity.Warning,
            "A configuration key exists in one environment config file but is missing in another environment."),
        new(
            "config.drift.orphan_key",
            "Configuration Drift Orphan Key",
            FindingSeverity.Warning,
            "A configuration key exists in only one environment-specific config file."),
        new(
            "config.drift.hardcoded_env_value",
            "Configuration Drift Hardcoded Environment Value",
            FindingSeverity.Warning,
            "A configuration value differs by environment and appears hardcoded instead of parameterized.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } =
        Rules.ToFrozenDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
}
