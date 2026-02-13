using ReliabilityIQ.Analyzers.Regex;
using ReliabilityIQ.Core;

namespace ReliabilityIQ.Tests;

public sealed class PortabilityRegexAnalyzerTests
{
    private readonly PortabilityRegexAnalyzer _analyzer = new();

    [Fact]
    public async Task AnalyzeAsync_FindsExpectedRuleIds_ForRepresentativeMatches()
    {
        const string content = """
                               var ip = "10.20.30.40";
                               var dns = "service.core.windows.net";
                               var win = @"C:\temp\artifact.txt";
                               var linux = "/etc/hosts";
                               var tenant = "tenant 123e4567-e89b-12d3-a456-426614174000";
                               var region = "eastus2";
                               var endpoint = "management.azure.com";
                               """;

        var findings = (await _analyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "src/app.cs",
            Content: content,
            FileCategory: FileCategory.Source,
            Language: "csharp",
            Configuration: null))).ToList();

        var ruleIds = findings.Select(f => f.RuleId).Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);

        Assert.Contains("portability.hardcoded.ipv4", ruleIds);
        Assert.Contains("portability.hardcoded.dns", ruleIds);
        Assert.Contains("portability.hardcoded.filepath.windows", ruleIds);
        Assert.Contains("portability.hardcoded.filepath.linux", ruleIds);
        Assert.Contains("portability.hardcoded.guid", ruleIds);
        Assert.Contains("portability.hardcoded.region", ruleIds);
        Assert.Contains("portability.hardcoded.endpoint", ruleIds);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotFlagAllowlistedIpAddresses()
    {
        const string content = """
                               var any = "0.0.0.0";
                               var loopback = "127.0.0.1";
                               """;

        var findings = (await _analyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "src/host.cs",
            Content: content,
            FileCategory: FileCategory.Source,
            Language: "csharp",
            Configuration: null))).ToList();

        Assert.DoesNotContain(findings, f => f.RuleId == "portability.hardcoded.ipv4");
    }

    [Theory]
    [InlineData(FileCategory.Generated)]
    [InlineData(FileCategory.Vendor)]
    [InlineData(FileCategory.IDE)]
    public async Task AnalyzeAsync_SkipsGeneratedVendorAndIde(FileCategory category)
    {
        var findings = await _analyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "ignored/file.cs",
            Content: "10.1.2.3 management.azure.com",
            FileCategory: category,
            Language: "csharp",
            Configuration: null));

        Assert.Empty(findings);
    }

    [Fact]
    public async Task AnalyzeAsync_OnlyAppliesLinuxPathRuleToSourceFiles()
    {
        var findings = (await _analyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "config/settings.yaml",
            Content: "path: /etc/ssl/certs",
            FileCategory: FileCategory.Config,
            Language: "yaml",
            Configuration: null))).ToList();

        Assert.DoesNotContain(findings, f => f.RuleId == "portability.hardcoded.filepath.linux");
    }

    [Fact]
    public void BuiltInRules_ExposeExpectedCatalogForSeeding()
    {
        var rules = PortabilityRegexAnalyzer.BuiltInRuleDefinitions;

        Assert.Equal(7, rules.Count);
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.ipv4");
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.dns");
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.filepath.windows");
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.filepath.linux");
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.guid");
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.region");
        Assert.Contains(rules, r => r.RuleId == "portability.hardcoded.endpoint");
    }
}
