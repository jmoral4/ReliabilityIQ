using System.Text.RegularExpressions;

namespace ReliabilityIQ.Core.Configuration;

public static class GlobUtility
{
    public static bool IsMatch(string value, string pattern)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        var regex = ToRegex(pattern);
        var normalized = Normalize(value);
        return regex.IsMatch(normalized);
    }

    public static bool TryCompile(string pattern, out Regex? regex, out string? error)
    {
        regex = null;
        error = null;

        if (string.IsNullOrWhiteSpace(pattern))
        {
            error = "Glob pattern is empty.";
            return false;
        }

        if (pattern.Contains('[', StringComparison.Ordinal) || pattern.Contains(']', StringComparison.Ordinal))
        {
            error = "Character classes ([...]) are not supported in glob patterns.";
            return false;
        }

        try
        {
            regex = ToRegex(pattern);
            return true;
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static Regex ToRegex(string pattern)
    {
        var normalized = Normalize(pattern);
        var regexPattern = "^" + Regex.Escape(normalized)
            .Replace("\\*\\*", "__DOUBLE_STAR__", StringComparison.Ordinal)
            .Replace("\\*", "[^/]*", StringComparison.Ordinal)
            .Replace("\\?", "[^/]", StringComparison.Ordinal)
            .Replace("__DOUBLE_STAR__", ".*", StringComparison.Ordinal) + "$";

        return new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    }

    private static string Normalize(string value) => value.Replace('\\', '/');
}
