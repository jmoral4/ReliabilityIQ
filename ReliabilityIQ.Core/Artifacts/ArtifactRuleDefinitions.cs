using System.Collections.Frozen;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.Artifacts;

public static class ArtifactRuleDefinitions
{
    public const string ParseErrorRuleId = "deploy.artifact.parse_error";

    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            "deploy.ev2.hardcoded.subscription",
            "EV2 Hardcoded Subscription",
            FindingSeverity.Warning,
            "Parameterize subscription identifiers in EV2 artifacts instead of hardcoding concrete values."),
        new(
            "deploy.ev2.hardcoded.tenant",
            "EV2 Hardcoded Tenant",
            FindingSeverity.Warning,
            "Parameterize tenant identifiers in EV2 artifacts instead of hardcoding concrete values."),
        new(
            "deploy.ev2.hardcoded.endpoint",
            "EV2 Hardcoded Endpoint",
            FindingSeverity.Warning,
            "Move environment-specific cloud endpoints into deployment parameters or external configuration."),
        new(
            "deploy.ev2.hardcoded.region",
            "EV2 Hardcoded Region",
            FindingSeverity.Warning,
            "Avoid region pinning in EV2 specs unless explicitly parameterized for multi-region deployments."),
        new(
            "deploy.ev2.zero_bake_time",
            "EV2 Zero Bake Time",
            FindingSeverity.Error,
            "Add a non-zero wait duration between deployment steps to allow safe validation and rollback windows."),
        new(
            "deploy.ev2.no_health_check",
            "EV2 Missing Health Check",
            FindingSeverity.Warning,
            "Add explicit post-deploy health checks before considering EV2 rollout steps successful."),
        new(
            "deploy.ev2.single_region",
            "EV2 Single-Region Binding",
            FindingSeverity.Warning,
            "Add failover-aware region bindings to avoid single-region deployment coupling."),
        new(
            "deploy.ev2.inline_secret",
            "EV2 Inline Secret",
            FindingSeverity.Error,
            "Replace inline secrets in EV2 artifacts with Key Vault references or secure variable resolution."),
        new(
            "deploy.ev2.env_constant",
            "EV2 Environment Constant",
            FindingSeverity.Warning,
            "Replace environment-specific hardcoded constants with EV2 parameters or environment mapping."),
        new(
            "deploy.ado.hardcoded.agentpool",
            "ADO Hardcoded Agent Pool",
            FindingSeverity.Warning,
            "Use variables or templates for pool names to keep ADO pipelines portable across orgs/environments."),
        new(
            "deploy.ado.hardcoded.path",
            "ADO Hardcoded Script Path",
            FindingSeverity.Warning,
            "Avoid hardcoded absolute paths in pipeline scripts; use variables and platform-agnostic path composition."),
        new(
            "deploy.ado.hardcoded.endpoint",
            "ADO Hardcoded Service Endpoint",
            FindingSeverity.Warning,
            "Externalize service connection names and endpoint identifiers through pipeline variables or templates."),
        new(
            "deploy.ado.inline_secret",
            "ADO Inline Secret",
            FindingSeverity.Error,
            "Move inline secrets to secret variable groups, Key Vault, or secure pipeline inputs."),
        new(
            "deploy.ado.platform_assumption",
            "ADO Platform Assumption",
            FindingSeverity.Warning,
            "Avoid Windows-specific path assumptions in scripts intended to run cross-platform."),
        new(
            "deploy.ado.missing_approval",
            "ADO Missing Production Approval",
            FindingSeverity.Warning,
            "Add approval checks for production deployments to reduce unsafe direct rollout risk."),
        new(
            "deploy.ado.container_latest",
            "ADO Container Tag Uses Latest",
            FindingSeverity.Warning,
            "Pin container images to immutable versions or digests instead of latest tags."),
        new(
            ParseErrorRuleId,
            "Artifact Parse Error",
            FindingSeverity.Warning,
            "Artifact file failed structured parsing; fix syntax to restore rule coverage for deployment safety checks.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } =
        Rules.ToFrozenDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
}
