using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ReliabilityIQ.Core.Portability;

public static class PortabilityPatternMatcher
{
    private static readonly HashSet<string> AllowedIpv4Addresses = new(StringComparer.Ordinal)
    {
        "0.0.0.0",
        "127.0.0.1"
    };

    private static readonly Regex Ipv4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CloudDnsRegex = new(
        @"\b(?:[a-z0-9-]+\.)+(?:windows\.net|azure\.com|core\.windows\.net|database\.windows\.net|azurewebsites\.net|azure-api\.net|microsoftonline\.com)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex WindowsPathRegex = new(
        @"(?<![A-Za-z0-9_])(?:[A-Za-z]:\\(?:[^\\\r\n:*?""<>|]+\\?)+|\\\\[A-Za-z0-9._$ -]+\\[^\r\n]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex LinuxPathRegex = new(
        @"\B/(?:var|etc|opt)/(?:[^\s""'`]+)?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex GuidNearKeywordRegex = new(
        @"\b(?:subscription|tenant|resourcegroup)\b[^\r\n]{0,50}\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex GuidRegex = new(
        @"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex AzureRegionRegex = new(
        @"\b(?:eastus|eastus2|westus|westus2|westus3|centralus|northcentralus|southcentralus|westeurope|northeurope|uksouth|ukwest|southeastasia|eastasia|australiaeast|australiasoutheast|japaneast|japanwest|koreacentral|koreasouth|canadacentral|canadaeast)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex EndpointRegex = new(
        @"\b(?:management\.azure\.com|login\.microsoftonline\.com|169\.254\.169\.254|metadata\.azure\.internal)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex ConnectionStringRegex = new(
        @"\b(?:server|data source|accountkey)\s*=",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public static IReadOnlyList<string> MatchRuleIds(string literalValue)
    {
        if (string.IsNullOrWhiteSpace(literalValue))
        {
            return [];
        }

        var matched = new List<string>();

        var ipMatch = Ipv4Regex.Match(literalValue);
        if (ipMatch.Success && !AllowedIpv4Addresses.Contains(ipMatch.Value))
        {
            matched.Add("portability.hardcoded.ipv4");
        }

        if (CloudDnsRegex.IsMatch(literalValue))
        {
            matched.Add("portability.hardcoded.dns");
        }

        if (WindowsPathRegex.IsMatch(literalValue))
        {
            matched.Add("portability.hardcoded.filepath.windows");
        }

        if (LinuxPathRegex.IsMatch(literalValue))
        {
            matched.Add("portability.hardcoded.filepath.linux");
        }

        if (GuidNearKeywordRegex.IsMatch(literalValue) ||
            (GuidRegex.IsMatch(literalValue) &&
             (literalValue.Contains("subscription", StringComparison.OrdinalIgnoreCase) ||
              literalValue.Contains("tenant", StringComparison.OrdinalIgnoreCase) ||
              literalValue.Contains("resourcegroup", StringComparison.OrdinalIgnoreCase))))
        {
            matched.Add("portability.hardcoded.guid");
        }

        if (AzureRegionRegex.IsMatch(literalValue))
        {
            matched.Add("portability.hardcoded.region");
        }

        if (EndpointRegex.IsMatch(literalValue))
        {
            matched.Add("portability.hardcoded.endpoint");
        }

        if (ConnectionStringRegex.IsMatch(literalValue))
        {
            matched.Add("portability.hardcoded.connectionstring");
        }

        if (literalValue.Contains("localhost", StringComparison.OrdinalIgnoreCase))
        {
            matched.Add("portability.hardcoded.localhost");
        }

        return matched;
    }

    public static string CreateFingerprint(string ruleId, string filePath, int line, int column, string rawValue)
    {
        var raw = $"{ruleId}|{filePath}|{line}|{column}|{rawValue}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash);
    }

    public static string? GetSnippet(string content, int line)
    {
        var lines = content.Split('\n');
        if (line <= 0 || line > lines.Length)
        {
            return null;
        }

        return lines[line - 1].TrimEnd('\r');
    }
}
