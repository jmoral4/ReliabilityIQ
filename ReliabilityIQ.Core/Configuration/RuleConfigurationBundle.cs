using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Core.Configuration;

public sealed record RuleConfigurationBundle(
    string RepoRoot,
    ScanConfig Scan,
    RuleConfig Rules,
    AllowlistConfig Allowlists,
    SuppressionConfig Suppressions,
    IReadOnlyDictionary<string, EffectiveRuleEntry> EffectiveRules,
    IReadOnlyDictionary<string, string> ScanSettings,
    IReadOnlyList<ValidationIssue> MergeWarnings,
    string SchemaJson,
    string ConfigHash)
{
    public static RuleConfigurationBundle Empty(string repoRoot)
    {
        var defaults = RuleCatalog.GetBuiltInDefinitions();
        var effective = defaults.ToDictionary(
            r => r.RuleId,
            r => new EffectiveRuleEntry(r, Enabled: true, Severity: r.DefaultSeverity, Source: "built-in"),
            StringComparer.OrdinalIgnoreCase);

        return new RuleConfigurationBundle(
            RepoRoot: repoRoot,
            Scan: new ScanConfig(repoRoot, [], null, [], UseGitIgnore: null, ExcludeDotDirectories: null, MaxFileSizeBytes: null),
            Rules: new RuleConfig(new Dictionary<string, RuleOverrideConfig>(StringComparer.OrdinalIgnoreCase), []),
            Allowlists: new AllowlistConfig([]),
            Suppressions: new SuppressionConfig([]),
            EffectiveRules: effective,
            ScanSettings: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            MergeWarnings: [],
            SchemaJson: RuleConfigurationLoader.LoadEmbeddedSchema(),
            ConfigHash: "defaults");
    }
}
