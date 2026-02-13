using YamlDotNet.Core;
using YamlDotNet.Serialization;

namespace ReliabilityIQ.Core.Configuration;

public static class RuleConfigurationValidator
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder().Build();

    public static RuleValidationResult Validate(string? path)
    {
        var issues = new List<ValidationIssue>();
        var basePath = string.IsNullOrWhiteSpace(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);
        var configRoot = ResolveConfigRoot(basePath);

        if (!Directory.Exists(configRoot))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Warning, configRoot, "Configuration directory was not found; only built-in defaults are active."));
            return new RuleValidationResult(issues);
        }

        var yamlFiles = EnumerateYamlFiles(configRoot);
        foreach (var file in yamlFiles)
        {
            var text = File.ReadAllText(file);
            try
            {
                _ = YamlDeserializer.Deserialize<object?>(text);
            }
            catch (YamlException ex)
            {
                issues.Add(new ValidationIssue(
                    ValidationIssueSeverity.Error,
                    file,
                    $"Invalid YAML: {ex.Message}"));
                continue;
            }

            ValidateSchemaShape(file, text, issues);
        }

        RuleConfigurationBundle bundle;
        try
        {
            bundle = RuleConfigurationLoader.LoadFromPath(configRoot);
        }
        catch (YamlException ex)
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, configRoot, $"Invalid YAML: {ex.Message}"));
            return new RuleValidationResult(issues);
        }
        catch (Exception ex)
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, configRoot, ex.Message));
            return new RuleValidationResult(issues);
        }

        foreach (var warning in bundle.MergeWarnings)
        {
            issues.Add(warning);
        }

        var knownRuleIds = bundle.EffectiveRules.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in bundle.Allowlists.Entries)
        {
            if (!knownRuleIds.Contains(entry.RuleId))
            {
                issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, entry.SourceFile, $"Allowlist references unknown rule ID '{entry.RuleId}'."));
            }

            if (!GlobUtility.TryCompile(entry.PathGlob, out _, out var globError))
            {
                issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, entry.SourceFile, $"Invalid allowlist glob '{entry.PathGlob}': {globError}"));
            }

            if (!string.IsNullOrWhiteSpace(entry.Pattern))
            {
                try
                {
                    _ = new System.Text.RegularExpressions.Regex(entry.Pattern, System.Text.RegularExpressions.RegexOptions.CultureInvariant);
                }
                catch (ArgumentException ex)
                {
                    issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, entry.SourceFile, $"Invalid allowlist pattern '{entry.Pattern}': {ex.Message}"));
                }
            }
        }

        foreach (var entry in bundle.Suppressions.Entries)
        {
            if (!knownRuleIds.Contains(entry.RuleId))
            {
                issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, entry.SourceFile, $"Suppression references unknown rule ID '{entry.RuleId}'."));
            }

            if (!GlobUtility.TryCompile(entry.PathGlob, out _, out var globError))
            {
                issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, entry.SourceFile, $"Invalid suppression glob '{entry.PathGlob}': {globError}"));
            }
        }

        var customIds = bundle.Rules.CustomRules
            .GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1);

        foreach (var duplicate in customIds)
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, configRoot, $"Duplicate custom rule ID '{duplicate.Key}'."));
        }

        return new RuleValidationResult(issues);
    }

    private static void ValidateSchemaShape(string file, string yamlText, ICollection<ValidationIssue> issues)
    {
        var fileName = Path.GetFileName(file);
        if (!fileName.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Lightweight JSON-schema-style checks while keeping zero external schema runtime dependencies.
        if (fileName.Equals("config.yaml", StringComparison.OrdinalIgnoreCase))
        {
            if (yamlText.Contains("rules:", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new ValidationIssue(ValidationIssueSeverity.Warning, file, "config.yaml should contain global scan settings; rule overrides belong in rules/*.yaml."));
            }

            return;
        }

        if (file.Contains($"{Path.DirectorySeparatorChar}rules{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) &&
            !file.Contains($"{Path.DirectorySeparatorChar}rules{Path.DirectorySeparatorChar}custom{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) &&
            !yamlText.Contains("rules:", StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Warning, file, "Rule file does not contain a 'rules:' mapping."));
        }

        if (file.Contains($"{Path.DirectorySeparatorChar}allowlists{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) &&
            !yamlText.Contains("allowlist:", StringComparison.OrdinalIgnoreCase) &&
            !yamlText.Contains("entries:", StringComparison.OrdinalIgnoreCase) &&
            !yamlText.TrimStart().StartsWith("-", StringComparison.Ordinal))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Warning, file, "Allowlist file should contain 'allowlist:' or 'entries:' collection."));
        }
    }

    private static IReadOnlyList<string> EnumerateYamlFiles(string configRoot)
    {
        return Directory.EnumerateFiles(configRoot, "*.yaml", SearchOption.AllDirectories)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ResolveConfigRoot(string path)
    {
        if (Directory.Exists(path) && string.Equals(Path.GetFileName(path), ".reliabilityiq", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        var nested = Path.Combine(path, ".reliabilityiq");
        if (Directory.Exists(nested) || File.Exists(Path.Combine(nested, "config.yaml")))
        {
            return nested;
        }

        return path;
    }
}
