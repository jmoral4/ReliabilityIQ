using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Cli;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Configuration;

namespace ReliabilityIQ.Tests;

public sealed class Phase11RuleConfigurationTests : IDisposable
{
    private readonly string _tempDir;

    public Phase11RuleConfigurationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase11-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void Init_IsIdempotent_AndCreatesExpectedStructure()
    {
        var repo = Path.Combine(_tempDir, "repo-init");
        Directory.CreateDirectory(repo);

        var first = RuleInitScaffolder.Initialize(repo);
        var second = RuleInitScaffolder.Initialize(repo);

        Assert.NotEmpty(first);
        Assert.Empty(second);

        Assert.True(File.Exists(Path.Combine(repo, ".reliabilityiq", "config.yaml")));
        Assert.True(File.Exists(Path.Combine(repo, ".reliabilityiq", "rules", "portability.yaml")));
        Assert.True(File.Exists(Path.Combine(repo, ".reliabilityiq", "rules", "custom", "custom-template.yaml")));
        Assert.True(File.Exists(Path.Combine(repo, ".reliabilityiq", "allowlists", "default.yaml")));
    }

    [Fact]
    public void Validate_CatchesInvalidYaml_UnknownRules_AndBadGlobs()
    {
        var repo = Path.Combine(_tempDir, "repo-validate");
        Directory.CreateDirectory(repo);
        RuleInitScaffolder.Initialize(repo);

        File.WriteAllText(Path.Combine(repo, ".reliabilityiq", "allowlists", "bad.yaml"),
            """
            allowlist:
              - path: "src/[*.cs"
                ruleId: does.not.exist
            """);

        File.WriteAllText(Path.Combine(repo, ".reliabilityiq", "rules", "custom", "broken.yaml"),
            """
            rules:
              - id: custom.broken
                pattern: "(oops"
                message: "bad"
            """);

        var result = RuleConfigurationValidator.Validate(repo);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Message.Contains("unknown rule ID", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Issues, i => i.Message.Contains("Invalid allowlist glob", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Issues, i => i.Message.Contains("invalid regex pattern", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task PortabilityScan_CustomRegexRule_FiresFromYaml()
    {
        var repo = Path.Combine(_tempDir, "repo-custom");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        Directory.CreateDirectory(Path.Combine(repo, "src"));

        File.WriteAllText(Path.Combine(repo, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");
        File.WriteAllText(Path.Combine(repo, "src", "app.cs"), "var endpoint = \"internal.myorg.com\";");

        RuleInitScaffolder.Initialize(repo);
        File.WriteAllText(Path.Combine(repo, ".reliabilityiq", "rules", "custom", "custom.yaml"),
            """
            rules:
              - id: custom.my-org.forbidden-endpoint
                pattern: "internal\\.myorg\\.com"
                fileCategories: [Source, Config]
                severity: Warning
                message: "Replace with config-driven endpoint"
            """);

        var db = Path.Combine(_tempDir, "custom.db");
        var exitCode = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repo, db, FindingSeverity.Error),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = db }.ToString());
        await connection.OpenAsync();

        var count = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM findings WHERE rule_id = 'custom.my-org.forbidden-endpoint';");

        Assert.True(count > 0);
    }

    [Fact]
    public async Task PortabilityScan_Allowlist_SuppressesMatchingFinding()
    {
        var repo = Path.Combine(_tempDir, "repo-allowlist");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        Directory.CreateDirectory(Path.Combine(repo, "src"));

        File.WriteAllText(Path.Combine(repo, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");
        File.WriteAllText(Path.Combine(repo, "src", "app.cs"), "var endpoint = \"management.azure.com\";");

        RuleInitScaffolder.Initialize(repo);
        File.WriteAllText(Path.Combine(repo, ".reliabilityiq", "allowlists", "portability.yaml"),
            """
            allowlist:
              - path: "src/*.cs"
                ruleId: portability.hardcoded.endpoint
                pattern: "management\\.azure\\.com"
            """);

        var db = Path.Combine(_tempDir, "allowlist.db");
        _ = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repo, db, FindingSeverity.Warning),
            TextWriter.Null);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = db }.ToString());
        await connection.OpenAsync();

        var count = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM findings WHERE rule_id = 'portability.hardcoded.endpoint';");

        Assert.Equal(0, count);
    }

    [Fact]
    public async Task CliStyleFailOn_OverridesYamlFailOn()
    {
        var repo = Path.Combine(_tempDir, "repo-failon");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        Directory.CreateDirectory(Path.Combine(repo, "src"));

        File.WriteAllText(Path.Combine(repo, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");
        File.WriteAllText(Path.Combine(repo, "src", "app.cs"), "var endpoint = \"management.azure.com\";");

        RuleInitScaffolder.Initialize(repo);
        File.WriteAllText(Path.Combine(repo, ".reliabilityiq", "rules", "portability.yaml"),
            """
            failOn: error
            rules: {}
            """);

        var db = Path.Combine(_tempDir, "failon.db");

        var codeFromYaml = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repo, db, null),
            TextWriter.Null);

        var codeFromCliOverride = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repo, db, FindingSeverity.Warning),
            TextWriter.Null);

        Assert.Equal(0, codeFromYaml);
        Assert.Equal(1, codeFromCliOverride);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
