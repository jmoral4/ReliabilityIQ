using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Persistence;
using Match = System.Text.RegularExpressions.Match;
using RegexPattern = System.Text.RegularExpressions.Regex;

namespace ReliabilityIQ.Analyzers.Regex;

public sealed class PortabilityRegexAnalyzer : IAnalyzer
{
    private static readonly FrozenSet<string> AllowedIpv4Addresses = new[]
    {
        "0.0.0.0",
        "127.0.0.1"
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly RegexPattern Ipv4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly RegexPattern CloudDnsRegex = new(
        @"\b(?:[a-z0-9-]+\.)+(?:windows\.net|azure\.com|core\.windows\.net|database\.windows\.net|azurewebsites\.net|azure-api\.net|microsoftonline\.com)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly RegexPattern WindowsPathRegex = new(
        @"(?<![A-Za-z0-9_])(?:[A-Za-z]:\\(?:[^\\\r\n:*?""<>|]+\\?)+|\\\\[A-Za-z0-9._$ -]+\\[^\r\n]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly RegexPattern LinuxPathRegex = new(
        @"\B/(?:var|etc|opt)/(?:[^\s""'`]+)?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly RegexPattern GuidNearKeywordRegex = new(
        @"\b(?:subscription|tenant|resourcegroup)\b[^\r\n]{0,50}\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly RegexPattern AzureRegionRegex = new(
        @"\b(?:eastus|eastus2|westus|westus2|westus3|centralus|northcentralus|southcentralus|westeurope|northeurope|uksouth|ukwest|southeastasia|eastasia|australiaeast|australiasoutheast|japaneast|japanwest|koreacentral|koreasouth|canadacentral|canadaeast)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly RegexPattern EndpointRegex = new(
        @"\b(?:management\.azure\.com|login\.microsoftonline\.com|169\.254\.169\.254|metadata\.azure\.internal)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly IReadOnlyList<RegexRule> Rules =
    [
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.ipv4"],
            Pattern: Ipv4Regex,
            AppliesTo: [FileCategory.Source, FileCategory.Config, FileCategory.DeploymentArtifact],
            MessageFactory: m => $"Hardcoded IPv4 address '{m.Value}' found.",
            IsMatchAllowed: m => !AllowedIpv4Addresses.Contains(m.Value)),
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.dns"],
            Pattern: CloudDnsRegex,
            AppliesTo: [FileCategory.Source, FileCategory.Config, FileCategory.DeploymentArtifact],
            MessageFactory: m => $"Hardcoded cloud-specific DNS value '{m.Value}' found."),
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.filepath.windows"],
            Pattern: WindowsPathRegex,
            AppliesTo: [FileCategory.Source, FileCategory.Config, FileCategory.DeploymentArtifact],
            MessageFactory: m => $"Hardcoded Windows path '{m.Value}' found."),
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.filepath.linux"],
            Pattern: LinuxPathRegex,
            AppliesTo: [FileCategory.Source],
            MessageFactory: m => $"Suspicious Linux absolute path '{m.Value}' found."),
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.guid"],
            Pattern: GuidNearKeywordRegex,
            AppliesTo: [FileCategory.Source, FileCategory.Config, FileCategory.DeploymentArtifact],
            MessageFactory: _ => "Subscription, tenant, or resource-group GUID appears hardcoded."),
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.region"],
            Pattern: AzureRegionRegex,
            AppliesTo: [FileCategory.Source, FileCategory.Config, FileCategory.DeploymentArtifact],
            MessageFactory: m => $"Hardcoded cloud region '{m.Value}' found."),
        new RegexRule(
            Rule: PortabilityRuleCatalog.ById["portability.hardcoded.endpoint"],
            Pattern: EndpointRegex,
            AppliesTo: [FileCategory.Source, FileCategory.Config, FileCategory.DeploymentArtifact],
            MessageFactory: m => $"Hardcoded cloud management endpoint '{m.Value}' found.")
    ];

    public string Name => "Portability.Regex";

    public string Version => "1.0.0";

    public IReadOnlyCollection<FileCategory> SupportedFileCategories { get; } =
    [
        FileCategory.Source,
        FileCategory.Config,
        FileCategory.DeploymentArtifact,
        FileCategory.Docs,
        FileCategory.Unknown
    ];

    public static IReadOnlyList<RuleDefinition> BuiltInRuleDefinitions => PortabilityRuleCatalog.Rules;

    public Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default)
    {
        if (context.FileCategory is FileCategory.Generated or FileCategory.Vendor or FileCategory.IDE)
        {
            return Task.FromResult<IEnumerable<Finding>>([]);
        }

        var findings = new List<Finding>();
        foreach (var rule in Rules)
        {
            if (!rule.AppliesTo.Contains(context.FileCategory))
            {
                continue;
            }

            foreach (Match match in rule.Pattern.Matches(context.Content))
            {
                if (!match.Success || !rule.IsMatchAllowed(match))
                {
                    continue;
                }

                cancellationToken.ThrowIfCancellationRequested();

                var (line, column) = GetLineAndColumn(context.Content, match.Index);
                findings.Add(new Finding
                {
                    RuleId = rule.Rule.RuleId,
                    FilePath = context.FilePath,
                    Line = line,
                    Column = column,
                    Message = rule.MessageFactory(match),
                    Snippet = GetSnippet(context.Content, line),
                    Severity = rule.Rule.DefaultSeverity,
                    Confidence = FindingConfidence.Medium,
                    Fingerprint = CreateFingerprint(rule.Rule.RuleId, context.FilePath, line, column, match.Value),
                    Metadata = $$"""{"engine":"regex","ruleVersion":"{{Version}}","matchedValue":"{{EscapeForJson(match.Value)}}"}"""
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static (int Line, int Column) GetLineAndColumn(string content, int index)
    {
        var line = 1;
        var column = 1;
        for (var i = 0; i < index && i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                line++;
                column = 1;
            }
            else
            {
                column++;
            }
        }

        return (line, column);
    }

    private static string? GetSnippet(string content, int line)
    {
        var lines = content.Split('\n');
        if (line <= 0 || line > lines.Length)
        {
            return null;
        }

        return lines[line - 1].TrimEnd('\r');
    }

    private static string CreateFingerprint(string ruleId, string filePath, int line, int column, string value)
    {
        var raw = $"{ruleId}|{filePath}|{line}|{column}|{value}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash);
    }

    private static string EscapeForJson(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }

    private sealed record RegexRule(
        RuleDefinition Rule,
        RegexPattern Pattern,
        IReadOnlyCollection<FileCategory> AppliesTo,
        Func<Match, string> MessageFactory,
        Func<Match, bool>? IsMatchAllowed = null)
    {
        public Func<Match, bool> IsMatchAllowed { get; } = IsMatchAllowed ?? (_ => true);
    }
}
