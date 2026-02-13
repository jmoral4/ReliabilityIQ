using System.Text.RegularExpressions;

namespace ReliabilityIQ.Core.Portability;

public sealed class FileSuppressionSet
{
    private readonly List<Entry> _entries;

    private FileSuppressionSet(List<Entry> entries)
    {
        _entries = entries;
    }

    public static FileSuppressionSet Empty { get; } = new([]);

    public static FileSuppressionSet Load(AnalysisContext context)
    {
        var filePath = ResolveSuppressionPath(context.Configuration);
        if (filePath is null || !File.Exists(filePath))
        {
            return Empty;
        }

        var entries = new List<Entry>();
        Entry? current = null;

        foreach (var raw in File.ReadLines(filePath))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('-'))
            {
                if (current is not null)
                {
                    entries.Add(current);
                }

                current = new Entry();
                line = line.TrimStart('-').Trim();
            }

            if (current is null)
            {
                continue;
            }

            var separator = line.IndexOf(':');
            if (separator < 0)
            {
                continue;
            }

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim().Trim('\'', '"');

            if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
            {
                current.PathGlob = value;
            }
            else if (key.Equals("rule", StringComparison.OrdinalIgnoreCase) || key.Equals("rule_id", StringComparison.OrdinalIgnoreCase))
            {
                current.RuleId = value;
            }
            else if (key.Equals("fingerprint", StringComparison.OrdinalIgnoreCase))
            {
                current.Fingerprint = value;
            }
        }

        if (current is not null)
        {
            entries.Add(current);
        }

        return new FileSuppressionSet(entries.Where(entry => !string.IsNullOrWhiteSpace(entry.PathGlob) && !string.IsNullOrWhiteSpace(entry.RuleId)).ToList());
    }

    public bool IsSuppressed(string filePath, string ruleId, string fingerprint)
    {
        foreach (var entry in _entries)
        {
            if (!GlobMatch(filePath, entry.PathGlob!))
            {
                continue;
            }

            if (!string.Equals(ruleId, entry.RuleId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(entry.Fingerprint) ||
                string.Equals(fingerprint, entry.Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? ResolveSuppressionPath(IReadOnlyDictionary<string, string?>? configuration)
    {
        if (configuration is null)
        {
            return null;
        }

        if (configuration.TryGetValue("suppressionsPath", out var explicitPath) && !string.IsNullOrWhiteSpace(explicitPath))
        {
            return Path.GetFullPath(explicitPath);
        }

        if (configuration.TryGetValue("repoRoot", out var repoRoot) && !string.IsNullOrWhiteSpace(repoRoot))
        {
            return Path.Combine(repoRoot, "reliabilityiq.suppressions.yaml");
        }

        return null;
    }

    private static bool GlobMatch(string value, string pattern)
    {
        var normalizedValue = value.Replace('\\', '/');
        var normalizedPattern = pattern.Replace('\\', '/');
        var regexPattern = "^" + Regex.Escape(normalizedPattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        return Regex.IsMatch(normalizedValue, regexPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private sealed class Entry
    {
        public string? PathGlob { get; set; }

        public string? RuleId { get; set; }

        public string? Fingerprint { get; set; }
    }
}
