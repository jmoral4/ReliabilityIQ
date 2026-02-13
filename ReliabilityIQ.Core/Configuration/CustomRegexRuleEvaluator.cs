using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ReliabilityIQ.Core.Configuration;

public static class CustomRegexRuleEvaluator
{
    public static IReadOnlyList<Finding> Evaluate(
        string filePath,
        string content,
        FileCategory category,
        RuleConfigurationBundle config)
    {
        if (config.Rules.CustomRules.Count == 0)
        {
            return [];
        }

        var findings = new List<Finding>();

        foreach (var rule in config.Rules.CustomRules)
        {
            if (!rule.Enabled || !rule.FileCategories.Contains(category))
            {
                continue;
            }

            foreach (Match match in Regex.Matches(content, rule.Pattern, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase))
            {
                if (!match.Success)
                {
                    continue;
                }

                var (line, column) = GetLineAndColumn(content, match.Index);
                var snippet = GetSnippet(content, line);

                findings.Add(new Finding
                {
                    RuleId = rule.Id,
                    FilePath = filePath,
                    Line = line,
                    Column = column,
                    Message = rule.Message,
                    Snippet = snippet,
                    Severity = rule.Severity,
                    Confidence = FindingConfidence.Medium,
                    Fingerprint = CreateFingerprint(rule.Id, filePath, line, column, match.Value),
                    Metadata = $$"""{"engine":"custom-regex","source":"{{Escape(rule.SourceFile)}}","match":"{{Escape(match.Value)}}"}"""
                });
            }
        }

        return findings;
    }

    private static (int Line, int Column) GetLineAndColumn(string content, int index)
    {
        var line = 1;
        var column = 1;

        for (var i = 0; i < content.Length && i < index; i++)
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

    private static string Escape(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }
}
