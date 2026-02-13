using System.Collections.Frozen;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.Portability;

public static class PortabilityRuleDefinitions
{
    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            "portability.hardcoded.ipv4",
            "Hardcoded IPv4 Address",
            FindingSeverity.Warning,
            "Replace hardcoded IP addresses with configuration-based endpoints."),
        new(
            "portability.hardcoded.dns",
            "Hardcoded Cloud DNS",
            FindingSeverity.Warning,
            "Move cloud-specific DNS names to configuration so deployment can target multiple environments."),
        new(
            "portability.hardcoded.filepath.windows",
            "Hardcoded Windows Path",
            FindingSeverity.Warning,
            "Avoid hardcoded Windows paths; use platform-safe path handling and configuration."),
        new(
            "portability.hardcoded.filepath.linux",
            "Suspicious Linux Absolute Path",
            FindingSeverity.Warning,
            "Move Linux absolute paths to configuration and prefer runtime path resolution."),
        new(
            "portability.hardcoded.guid",
            "Hardcoded Subscription/Tenant GUID",
            FindingSeverity.Warning,
            "Avoid embedding tenant, subscription, or resource-group GUIDs directly in code."),
        new(
            "portability.hardcoded.region",
            "Hardcoded Cloud Region",
            FindingSeverity.Warning,
            "Use environment or deployment configuration for cloud regions."),
        new(
            "portability.hardcoded.endpoint",
            "Hardcoded Cloud Management Endpoint",
            FindingSeverity.Warning,
            "Externalize management and metadata endpoints through configuration abstractions."),
        new(
            "portability.hardcoded.connectionstring",
            "Hardcoded Connection String",
            FindingSeverity.Error,
            "Move connection strings into secure configuration providers and avoid source-embedded secrets."),
        new(
            "portability.hardcoded.localhost",
            "Hardcoded Localhost Binding",
            FindingSeverity.Warning,
            "Avoid localhost-only bindings for container/cloud workloads; prefer configuration and 0.0.0.0 where needed."),
        new(
            "portability.hardcoded.registrykey",
            "Hardcoded Windows Registry Key",
            FindingSeverity.Warning,
            "Avoid hardcoded registry keys and move machine-specific settings into environment-aware configuration."),
        new(
            "portability.cloud.sdk.no_abstraction",
            "Direct Cloud SDK Usage Without Abstraction",
            FindingSeverity.Warning,
            "Prefer interface-based adapters around cloud SDK clients to reduce cloud lock-in and improve testability."),
        new(
            "portability.hardcoded.port",
            "Hardcoded Non-Standard Port",
            FindingSeverity.Warning,
            "Move non-standard ports to configuration so deployment environments can override them safely.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } =
        Rules.ToFrozenDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
}
