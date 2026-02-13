namespace ReliabilityIQ.Core.Configuration;

public static class RuleInitScaffolder
{
    public static IReadOnlyList<string> Initialize(string repoRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repoRoot);

        var created = new List<string>();
        var configRoot = Path.Combine(repoRoot, ".reliabilityiq");
        var rulesRoot = Path.Combine(configRoot, "rules");
        var customRoot = Path.Combine(rulesRoot, "custom");
        var allowlistsRoot = Path.Combine(configRoot, "allowlists");

        EnsureDirectory(configRoot, created);
        EnsureDirectory(rulesRoot, created);
        EnsureDirectory(customRoot, created);
        EnsureDirectory(allowlistsRoot, created);

        EnsureFile(Path.Combine(configRoot, "config.yaml"), DefaultConfigYaml, created);
        EnsureFile(Path.Combine(rulesRoot, "portability.yaml"), DefaultPortabilityYaml, created);
        EnsureFile(Path.Combine(rulesRoot, "magic-strings.yaml"), DefaultMagicStringsYaml, created);
        EnsureFile(Path.Combine(rulesRoot, "churn.yaml"), DefaultChurnYaml, created);
        EnsureFile(Path.Combine(rulesRoot, "incidents.yaml"), DefaultIncidentsYaml, created);
        EnsureFile(Path.Combine(rulesRoot, "deploy-ev2.yaml"), DefaultDeployEv2Yaml, created);
        EnsureFile(Path.Combine(rulesRoot, "deploy-ado.yaml"), DefaultDeployAdoYaml, created);
        EnsureFile(Path.Combine(rulesRoot, "hygiene.yaml"), DefaultHygieneYaml, created);
        EnsureFile(Path.Combine(customRoot, "custom-template.yaml"), DefaultCustomRuleYaml, created);
        EnsureFile(Path.Combine(allowlistsRoot, "default.yaml"), DefaultAllowlistYaml, created);

        return created;
    }

    private static void EnsureDirectory(string path, ICollection<string> created)
    {
        if (Directory.Exists(path))
        {
            return;
        }

        Directory.CreateDirectory(path);
        created.Add(path);
    }

    private static void EnsureFile(string path, string content, ICollection<string> created)
    {
        if (File.Exists(path))
        {
            return;
        }

        File.WriteAllText(path, content);
        created.Add(path);
    }

    private const string DefaultConfigYaml =
        """
        # Global scanner settings
        useGitIgnore: true
        excludeDotDirectories: true
        # maxFileSizeBytes: 2097152
        excludes:
          - "node_modules/**"
          - "bin/**"
          - "obj/**"
        scanTargets: []
        # snippetMode: compact
        """;

    private const string DefaultPortabilityYaml =
        """
        # Portability rule overrides
        # failOn: warning
        rules:
          portability.hardcoded.connectionstring:
            severity: Error
        """;

    private const string DefaultMagicStringsYaml =
        """
        # Magic-strings tuning
        # minOccurrences: 2
        # top: 500
        rules: {}
        """;

    private const string DefaultChurnYaml =
        """
        # Churn tuning
        # sinceDays: 365
        rules: {}
        """;

    private const string DefaultIncidentsYaml =
        """
        # Incident linking config placeholder
        rules: {}
        """;

    private const string DefaultDeployEv2Yaml =
        """
        # EV2 deployment rule overrides
        # ev2PathMarkers: "deploy/ev2;rollout"
        rules: {}
        """;

    private const string DefaultDeployAdoYaml =
        """
        # ADO deployment rule overrides
        # adoPathMarkers: "pipelines;azure-pipelines"
        rules: {}
        """;

    private const string DefaultHygieneYaml =
        """
        # Code hygiene scanner tuning
        # featureFlagStaleDays: 180
        # featureFlagRecentChangeDays: 90
        # todoOldDays: 180
        # todoKeywords: "TODO;FIXME;HACK;XXX;WORKAROUND;TEMP"
        rules: {}
        """;

    private const string DefaultCustomRuleYaml =
        """
        # Team-specific custom regex rules
        rules:
          - id: custom.my-org.forbidden-endpoint
            pattern: "internal\\.myorg\\.com"
            fileCategories: [Source, Config]
            severity: Warning
            message: "Replace with config-driven endpoint"
        """;

    private const string DefaultAllowlistYaml =
        """
        allowlist:
          - path: "tests/**"
            ruleId: portability.hardcoded.endpoint
        """;
}
