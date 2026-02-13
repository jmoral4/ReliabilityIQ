using System.Collections.Frozen;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Analyzers.Regex;

public static class PortabilityRuleCatalog
{
    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new RuleDefinition(
            "portability.hardcoded.ipv4",
            "Hardcoded IPv4 Address",
            FindingSeverity.Warning,
            "Replace hardcoded IP addresses with configuration-based endpoints."),
        new RuleDefinition(
            "portability.hardcoded.dns",
            "Hardcoded Cloud DNS",
            FindingSeverity.Warning,
            "Move cloud-specific DNS names to configuration so deployment can target multiple environments."),
        new RuleDefinition(
            "portability.hardcoded.filepath.windows",
            "Hardcoded Windows Path",
            FindingSeverity.Warning,
            "Avoid hardcoded Windows paths; use platform-safe path handling and configuration."),
        new RuleDefinition(
            "portability.hardcoded.filepath.linux",
            "Suspicious Linux Absolute Path",
            FindingSeverity.Warning,
            "Move Linux absolute paths to configuration and prefer runtime path resolution."),
        new RuleDefinition(
            "portability.hardcoded.guid",
            "Hardcoded Subscription/Tenant GUID",
            FindingSeverity.Warning,
            "Avoid embedding tenant, subscription, or resource-group GUIDs directly in code."),
        new RuleDefinition(
            "portability.hardcoded.region",
            "Hardcoded Cloud Region",
            FindingSeverity.Warning,
            "Use environment or deployment configuration for cloud regions."),
        new RuleDefinition(
            "portability.hardcoded.endpoint",
            "Hardcoded Cloud Management Endpoint",
            FindingSeverity.Warning,
            "Externalize management and metadata endpoints through configuration abstractions.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } = Rules.ToFrozenDictionary(r => r.RuleId, StringComparer.OrdinalIgnoreCase);
}
