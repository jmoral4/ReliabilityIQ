using System.Collections.Frozen;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.Hygiene;

public static class HygieneRuleDefinitions
{
    public const string StaleFeatureFlagRuleId = "hygiene.stale_feature_flag";
    public const string DeadFeatureFlagRuleId = "hygiene.dead_feature_flag";
    public const string TodoOldRuleId = "hygiene.todo_old";
    public const string FixmeRuleId = "hygiene.fixme";
    public const string HackRuleId = "hygiene.hack";
    public const string SyncOverAsyncRuleId = "async.sync_over_async";
    public const string AsyncVoidRuleId = "async.async_void";
    public const string NestedRuntimeRuleId = "async.nested_runtime";
    public const string BadLockTargetRuleId = "thread.bad_lock_target";

    public static IReadOnlyList<RuleDefinition> Rules { get; } =
    [
        new(
            StaleFeatureFlagRuleId,
            "Stale Feature Flag",
            FindingSeverity.Warning,
            "Feature flag appears stale based on age and lack of recent changes."),
        new(
            DeadFeatureFlagRuleId,
            "Dead Feature Flag",
            FindingSeverity.Warning,
            "Feature flag appears defined but has no observed runtime references."),
        new(
            TodoOldRuleId,
            "Old TODO Tech Debt",
            FindingSeverity.Warning,
            "TODO-like comment is older than configured age threshold."),
        new(
            FixmeRuleId,
            "FIXME Tech Debt",
            FindingSeverity.Warning,
            "FIXME comment indicates acknowledged defect or risky behavior."),
        new(
            HackRuleId,
            "HACK Tech Debt",
            FindingSeverity.Warning,
            "HACK/WORKAROUND/TEMP marker indicates admitted technical debt."),
        new(
            SyncOverAsyncRuleId,
            "Sync-over-Async Anti-pattern",
            FindingSeverity.Warning,
            "Synchronous wait on async operation may cause deadlocks or thread starvation."),
        new(
            AsyncVoidRuleId,
            "async void Usage",
            FindingSeverity.Warning,
            "async void methods outside event handlers are difficult to observe and handle."),
        new(
            NestedRuntimeRuleId,
            "Nested Async Runtime",
            FindingSeverity.Warning,
            "Nested runtime invocation in async context can break event loop semantics."),
        new(
            BadLockTargetRuleId,
            "Bad Lock Target",
            FindingSeverity.Error,
            "Lock target is unsafe (this/typeof/string literal) and can cause deadlocks.")
    ];

    public static FrozenDictionary<string, RuleDefinition> ById { get; } =
        Rules.ToFrozenDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
}
