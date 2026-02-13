using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ReliabilityIQ.Core.Persistence;
using YamlDotNet.Serialization;

namespace ReliabilityIQ.Core.Configuration;

public static class RuleConfigurationLoader
{
    private const string ConfigDirectoryName = ".reliabilityiq";
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder().Build();

    public static RuleConfigurationBundle LoadForRepo(string repoRoot, CliRuleOverrides? cliOverrides = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repoRoot);

        var resolvedRepo = Path.GetFullPath(repoRoot);
        var configRoot = Path.Combine(resolvedRepo, ConfigDirectoryName);
        if (!Directory.Exists(configRoot))
        {
            return ApplyCliOverrides(RuleConfigurationBundle.Empty(resolvedRepo), cliOverrides);
        }

        return LoadFromConfigRoot(configRoot, resolvedRepo, cliOverrides);
    }

    public static RuleConfigurationBundle LoadFromPath(string? path, CliRuleOverrides? cliOverrides = null)
    {
        var basePath = string.IsNullOrWhiteSpace(path)
            ? Directory.GetCurrentDirectory()
            : Path.GetFullPath(path);

        var configRoot = ResolveConfigRoot(basePath);
        var repoRoot = ResolveRepoRootFromConfig(configRoot);
        if (!Directory.Exists(configRoot))
        {
            return ApplyCliOverrides(RuleConfigurationBundle.Empty(repoRoot), cliOverrides);
        }

        return LoadFromConfigRoot(configRoot, repoRoot, cliOverrides);
    }

    public static string LoadEmbeddedSchema()
    {
        var assembly = typeof(RuleConfigurationLoader).Assembly;
        var resourceName = assembly
            .GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("Configuration.Schemas.rules-config.schema.json", StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
        {
            return "{}";
        }

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return "{}";
        }

        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static RuleConfigurationBundle LoadFromConfigRoot(string configRoot, string repoRoot, CliRuleOverrides? cliOverrides)
    {
        var builtInRules = RuleCatalog.GetBuiltInDefinitions();
        var effectiveRules = builtInRules.ToDictionary(
            r => r.RuleId,
            r => new EffectiveRuleEntry(r, Enabled: true, Severity: r.DefaultSeverity, Source: "built-in"),
            StringComparer.OrdinalIgnoreCase);

        var rawRuleOverrides = new Dictionary<string, RuleOverrideConfig>(StringComparer.OrdinalIgnoreCase);
        var allCustomRules = new List<CustomRegexRuleConfig>();
        var allowlistEntries = new List<AllowlistEntryConfig>();
        var warnings = new List<ValidationIssue>();
        var scanSettings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var loadedTextByFile = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var configFile = Path.Combine(configRoot, "config.yaml");
        var scanConfig = ParseScanConfig(configFile, repoRoot, loadedTextByFile);

        var rulesRoot = Path.Combine(configRoot, "rules");
        if (Directory.Exists(rulesRoot))
        {
            foreach (var path in Directory.EnumerateFiles(rulesRoot, "*.yaml", SearchOption.TopDirectoryOnly).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                ParseRuleFile(path, precedence: 2, rawRuleOverrides, scanSettings, warnings, loadedTextByFile);
            }

            var customRoot = Path.Combine(rulesRoot, "custom");
            if (Directory.Exists(customRoot))
            {
                foreach (var path in Directory.EnumerateFiles(customRoot, "*.yaml", SearchOption.TopDirectoryOnly).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
                {
                    ParseCustomRuleFile(path, precedence: 3, rawRuleOverrides, allCustomRules, warnings, loadedTextByFile);
                }
            }
        }

        var allowlistsRoot = Path.Combine(configRoot, "allowlists");
        if (Directory.Exists(allowlistsRoot))
        {
            foreach (var path in Directory.EnumerateFiles(allowlistsRoot, "*.yaml", SearchOption.TopDirectoryOnly).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                ParseAllowlistFile(path, allowlistEntries, loadedTextByFile);
            }
        }

        var suppressionEntries = ParseSuppressions(repoRoot, loadedTextByFile);

        foreach (var custom in allCustomRules)
        {
            var definition = new RuleDefinition(
                RuleId: custom.Id,
                Title: custom.Title ?? custom.Id,
                DefaultSeverity: custom.Severity,
                Description: custom.Description ?? custom.Message);

            effectiveRules[custom.Id] = new EffectiveRuleEntry(definition, custom.Enabled, custom.Severity, custom.SourceFile);
        }

        foreach (var kvp in rawRuleOverrides.OrderBy(k => k.Value.Precedence).ThenBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!effectiveRules.TryGetValue(kvp.Key, out var current))
            {
                current = new EffectiveRuleEntry(
                    Definition: new RuleDefinition(kvp.Key, kvp.Key, FindingSeverity.Warning, "Rule override declared in configuration."),
                    Enabled: true,
                    Severity: FindingSeverity.Warning,
                    Source: "built-in");
            }

            var overrideConfig = kvp.Value;
            effectiveRules[kvp.Key] = current with
            {
                Enabled = overrideConfig.Enabled ?? current.Enabled,
                Severity = overrideConfig.Severity ?? current.Severity,
                Source = overrideConfig.SourceFile
            };
        }

        var bundle = new RuleConfigurationBundle(
            RepoRoot: repoRoot,
            Scan: scanConfig,
            Rules: new RuleConfig(rawRuleOverrides, allCustomRules),
            Allowlists: new AllowlistConfig(allowlistEntries),
            Suppressions: new SuppressionConfig(suppressionEntries),
            EffectiveRules: effectiveRules,
            ScanSettings: scanSettings,
            MergeWarnings: warnings,
            SchemaJson: LoadEmbeddedSchema(),
            ConfigHash: ComputeHash(loadedTextByFile));

        return ApplyCliOverrides(bundle, cliOverrides);
    }

    private static RuleConfigurationBundle ApplyCliOverrides(RuleConfigurationBundle input, CliRuleOverrides? cliOverrides)
    {
        if (cliOverrides is null)
        {
            return input;
        }

        var effective = input.EffectiveRules.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
        var settings = input.ScanSettings.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);

        if (cliOverrides.PortabilityFailOn.HasValue)
        {
            settings["portability.failOn"] = cliOverrides.PortabilityFailOn.Value.ToString();
        }

        if (cliOverrides.MagicMinOccurrences.HasValue)
        {
            settings["magic.minOccurrences"] = cliOverrides.MagicMinOccurrences.Value.ToString();
        }

        if (cliOverrides.MagicTop.HasValue)
        {
            settings["magic.top"] = cliOverrides.MagicTop.Value.ToString();
        }

        if (cliOverrides.ChurnSinceDays.HasValue)
        {
            settings["churn.sinceDays"] = cliOverrides.ChurnSinceDays.Value.ToString();
        }

        if (cliOverrides.DeployEv2PathMarkers is not null)
        {
            settings["deploy.ev2.pathMarkers"] = string.Join(';', cliOverrides.DeployEv2PathMarkers);
        }

        if (cliOverrides.DeployAdoPathMarkers is not null)
        {
            settings["deploy.ado.pathMarkers"] = string.Join(';', cliOverrides.DeployAdoPathMarkers);
        }

        return input with
        {
            EffectiveRules = effective,
            ScanSettings = settings
        };
    }

    private static ScanConfig ParseScanConfig(string path, string repoRoot, IDictionary<string, string> loadedTextByFile)
    {
        if (!File.Exists(path))
        {
            return new ScanConfig(repoRoot, [], null, [], UseGitIgnore: null, ExcludeDotDirectories: null, MaxFileSizeBytes: null);
        }

        var text = File.ReadAllText(path);
        loadedTextByFile[path] = text;
        var root = ParseYamlRoot(text);

        var excludes = ReadStringList(root, "excludes");
        var scanTargets = ReadStringList(root, "scanTargets");
        var snippetMode = ReadString(root, "snippetMode");
        var useGitIgnore = ReadBoolean(root, "useGitIgnore");
        var excludeDots = ReadBoolean(root, "excludeDotDirectories");
        var maxFileSize = ReadLong(root, "maxFileSizeBytes");

        return new ScanConfig(repoRoot, excludes, snippetMode, scanTargets, useGitIgnore, excludeDots, maxFileSize);
    }

    private static void ParseRuleFile(
        string path,
        int precedence,
        IDictionary<string, RuleOverrideConfig> target,
        IDictionary<string, string> scanSettings,
        ICollection<ValidationIssue> warnings,
        IDictionary<string, string> loadedTextByFile)
    {
        var text = File.ReadAllText(path);
        loadedTextByFile[path] = text;

        var root = ParseYamlRoot(text);
        var rulesNode = ReadMap(root, "rules");
        if (rulesNode.Count > 0)
        {
            foreach (var (ruleIdObject, node) in rulesNode)
            {
                var ruleId = ruleIdObject?.ToString()?.Trim();
                if (string.IsNullOrWhiteSpace(ruleId))
                {
                    continue;
                }

                if (!TryReadRuleOverride(node, path, precedence, out var parsed))
                {
                    continue;
                }

                if (target.TryGetValue(ruleId, out var prior))
                {
                    warnings.Add(new ValidationIssue(
                        ValidationIssueSeverity.Warning,
                        path,
                        $"Rule '{ruleId}' is overridden by multiple files ('{prior.SourceFile}' and '{path}')."));
                }

                target[ruleId] = parsed;
            }
        }

        CopyKnownScanSettings(root, scanSettings);
    }

    private static void ParseCustomRuleFile(
        string path,
        int precedence,
        IDictionary<string, RuleOverrideConfig> overrideTarget,
        ICollection<CustomRegexRuleConfig> customTarget,
        ICollection<ValidationIssue> warnings,
        IDictionary<string, string> loadedTextByFile)
    {
        var text = File.ReadAllText(path);
        loadedTextByFile[path] = text;
        var root = ParseYamlRoot(text);

        if (!root.TryGetValue("rules", out var rulesObject) || rulesObject is not IEnumerable<object?> rulesSequence)
        {
            return;
        }

        foreach (var item in rulesSequence)
        {
            if (item is not IDictionary<object, object?> itemMap)
            {
                continue;
            }

            var id = ReadString(itemMap, "id")?.Trim();
            var pattern = ReadString(itemMap, "pattern")?.Trim();
            var message = ReadString(itemMap, "message")?.Trim();
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(message))
            {
                warnings.Add(new ValidationIssue(ValidationIssueSeverity.Error, path, "Custom rules must define non-empty id, pattern, and message."));
                continue;
            }

            var severity = ParseSeverity(ReadString(itemMap, "severity")) ?? FindingSeverity.Warning;
            var enabled = ReadBoolean(itemMap, "enabled") ?? true;
            var title = ReadString(itemMap, "title");
            var description = ReadString(itemMap, "description");
            var fileCategories = ReadFileCategories(itemMap, "fileCategories");

            try
            {
                _ = new System.Text.RegularExpressions.Regex(pattern, System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            catch (ArgumentException ex)
            {
                warnings.Add(new ValidationIssue(ValidationIssueSeverity.Error, path, $"Custom rule '{id}' has invalid regex pattern: {ex.Message}"));
                continue;
            }

            if (customTarget.Any(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase)))
            {
                warnings.Add(new ValidationIssue(ValidationIssueSeverity.Error, path, $"Duplicate custom rule id '{id}'."));
                continue;
            }

            customTarget.Add(new CustomRegexRuleConfig(
                Id: id,
                Pattern: pattern,
                FileCategories: fileCategories,
                Severity: severity,
                Message: message,
                Enabled: enabled,
                SourceFile: path,
                Title: title,
                Description: description));

            overrideTarget[id] = new RuleOverrideConfig(enabled, severity, path, precedence);
        }
    }

    private static void ParseAllowlistFile(string path, ICollection<AllowlistEntryConfig> target, IDictionary<string, string> loadedTextByFile)
    {
        var text = File.ReadAllText(path);
        loadedTextByFile[path] = text;
        var root = ParseYamlRoot(text);

        IEnumerable<object?> sequence;
        if (root.TryGetValue("allowlist", out var allowlistObject) && allowlistObject is IEnumerable<object?> listNode)
        {
            sequence = listNode;
        }
        else if (root.TryGetValue("entries", out var entriesObject) && entriesObject is IEnumerable<object?> entriesNode)
        {
            sequence = entriesNode;
        }
        else if (root.Count == 0 && ParseTopLevelSequence(text, out var topLevel))
        {
            sequence = topLevel;
        }
        else
        {
            return;
        }

        foreach (var item in sequence)
        {
            if (item is not IDictionary<object, object?> map)
            {
                continue;
            }

            var pathGlob = ReadString(map, "path")?.Trim();
            var ruleId = ReadString(map, "ruleId")?.Trim() ?? ReadString(map, "rule")?.Trim();
            var pattern = ReadString(map, "pattern")?.Trim();

            if (string.IsNullOrWhiteSpace(pathGlob) || string.IsNullOrWhiteSpace(ruleId))
            {
                continue;
            }

            target.Add(new AllowlistEntryConfig(pathGlob, ruleId, pattern, path));
        }
    }

    private static IReadOnlyList<SuppressionEntryConfig> ParseSuppressions(string repoRoot, IDictionary<string, string> loadedTextByFile)
    {
        var path = Path.Combine(repoRoot, "reliabilityiq.suppressions.yaml");
        if (!File.Exists(path))
        {
            return [];
        }

        var text = File.ReadAllText(path);
        loadedTextByFile[path] = text;

        var result = new List<SuppressionEntryConfig>();
        var lines = text.Split('\n');
        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith("-", StringComparison.Ordinal))
            {
                AddCurrent();
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                line = line.TrimStart('-').Trim();
            }

            var sep = line.IndexOf(':');
            if (sep <= 0)
            {
                continue;
            }

            var key = line[..sep].Trim();
            var value = line[(sep + 1)..].Trim().Trim('\'', '"');
            current[key] = value;
        }

        AddCurrent();
        return result;

        void AddCurrent()
        {
            if (!current.TryGetValue("path", out var pathGlob) || string.IsNullOrWhiteSpace(pathGlob))
            {
                return;
            }

            var ruleId = current.TryGetValue("rule", out var rule) ? rule : (current.TryGetValue("rule_id", out var ruleIdValue) ? ruleIdValue : null);
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                return;
            }

            current.TryGetValue("fingerprint", out var fingerprint);
            result.Add(new SuppressionEntryConfig(pathGlob, ruleId, string.IsNullOrWhiteSpace(fingerprint) ? null : fingerprint, path));
        }
    }

    private static void CopyKnownScanSettings(IReadOnlyDictionary<object, object?> root, IDictionary<string, string> scanSettings)
    {
        SetIfPresent(root, "failOn", "portability.failOn", scanSettings);
        SetIfPresent(root, "minOccurrences", "magic.minOccurrences", scanSettings);
        SetIfPresent(root, "top", "magic.top", scanSettings);
        SetIfPresent(root, "sinceDays", "churn.sinceDays", scanSettings);
        SetIfPresent(root, "since", "churn.since", scanSettings);
        SetIfPresent(root, "ev2PathMarkers", "deploy.ev2.pathMarkers", scanSettings);
        SetIfPresent(root, "adoPathMarkers", "deploy.ado.pathMarkers", scanSettings);
        SetIfPresent(root, "featureFlagApiPatterns", "hygiene.featureFlagApiPatterns", scanSettings);
        SetIfPresent(root, "featureFlagDefinitionPatterns", "hygiene.featureFlagDefinitionPatterns", scanSettings);
        SetIfPresent(root, "featureFlagStaleDays", "hygiene.featureFlagStaleDays", scanSettings);
        SetIfPresent(root, "featureFlagRecentChangeDays", "hygiene.featureFlagRecentChangeDays", scanSettings);
        SetIfPresent(root, "todoKeywords", "hygiene.todoKeywords", scanSettings);
        SetIfPresent(root, "todoOldDays", "hygiene.todoOldDays", scanSettings);
    }

    private static void SetIfPresent(IReadOnlyDictionary<object, object?> root, string yamlKey, string settingKey, IDictionary<string, string> target)
    {
        if (!root.TryGetValue(yamlKey, out var value) || value is null)
        {
            return;
        }

        target[settingKey] = value.ToString() ?? string.Empty;
    }

    private static bool TryReadRuleOverride(object? node, string sourceFile, int precedence, out RuleOverrideConfig config)
    {
        config = new RuleOverrideConfig(null, null, sourceFile, precedence);
        if (node is not IDictionary<object, object?> map)
        {
            return false;
        }

        var enabled = ReadBoolean(map, "enabled");
        var severity = ParseSeverity(ReadString(map, "severity"));
        config = new RuleOverrideConfig(enabled, severity, sourceFile, precedence);
        return true;
    }

    private static IReadOnlyDictionary<object, object?> ParseYamlRoot(string text)
    {
        var parsed = YamlDeserializer.Deserialize<object?>(text);
        return parsed as IReadOnlyDictionary<object, object?> ?? new Dictionary<object, object?>();
    }

    private static bool ParseTopLevelSequence(string text, out IReadOnlyList<object?> sequence)
    {
        sequence = [];
        var parsed = YamlDeserializer.Deserialize<object?>(text);
        if (parsed is IEnumerable<object?> items)
        {
            sequence = items.ToList();
            return true;
        }

        return false;
    }

    private static IReadOnlyDictionary<object, object?> ReadMap(IReadOnlyDictionary<object, object?> root, string key)
    {
        if (!root.TryGetValue(key, out var value) || value is not IReadOnlyDictionary<object, object?> map)
        {
            return new Dictionary<object, object?>();
        }

        return map;
    }

    private static IReadOnlyList<string> ReadStringList(IReadOnlyDictionary<object, object?> root, string key)
    {
        if (!root.TryGetValue(key, out var value) || value is not IEnumerable<object?> sequence)
        {
            return [];
        }

        return sequence
            .Select(v => v?.ToString()?.Trim())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Cast<string>()
            .ToList();
    }

    private static string? ReadString(IReadOnlyDictionary<object, object?> root, string key)
    {
        if (!root.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }

        return value.ToString();
    }

    private static string? ReadString(IDictionary<object, object?> root, string key)
    {
        if (!root.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }

        return value.ToString();
    }

    private static bool? ReadBoolean(IReadOnlyDictionary<object, object?> root, string key)
    {
        var raw = ReadString(root, key);
        return bool.TryParse(raw, out var value) ? value : null;
    }

    private static bool? ReadBoolean(IDictionary<object, object?> root, string key)
    {
        var raw = ReadString(root, key);
        return bool.TryParse(raw, out var value) ? value : null;
    }

    private static long? ReadLong(IReadOnlyDictionary<object, object?> root, string key)
    {
        var raw = ReadString(root, key);
        return long.TryParse(raw, out var value) ? value : null;
    }

    private static FindingSeverity? ParseSeverity(string? severity)
    {
        if (string.IsNullOrWhiteSpace(severity))
        {
            return null;
        }

        return severity.Trim().ToLowerInvariant() switch
        {
            "error" => FindingSeverity.Error,
            "warning" => FindingSeverity.Warning,
            "info" => FindingSeverity.Info,
            _ => null
        };
    }

    private static IReadOnlySet<FileCategory> ReadFileCategories(IDictionary<object, object?> root, string key)
    {
        if (!root.TryGetValue(key, out var value) || value is not IEnumerable<object?> items)
        {
            return new HashSet<FileCategory> { FileCategory.Source, FileCategory.Config };
        }

        var parsed = new HashSet<FileCategory>();
        foreach (var item in items)
        {
            if (Enum.TryParse<FileCategory>(item?.ToString(), ignoreCase: true, out var category))
            {
                parsed.Add(category);
            }
        }

        if (parsed.Count == 0)
        {
            parsed.Add(FileCategory.Source);
            parsed.Add(FileCategory.Config);
        }

        return parsed;
    }

    private static string ResolveConfigRoot(string path)
    {
        if (Directory.Exists(path) && string.Equals(Path.GetFileName(path), ConfigDirectoryName, StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        var direct = Path.Combine(path, ConfigDirectoryName);
        if (Directory.Exists(direct) || File.Exists(Path.Combine(direct, "config.yaml")))
        {
            return direct;
        }

        return path;
    }

    private static string ResolveRepoRootFromConfig(string configRoot)
    {
        var directory = new DirectoryInfo(configRoot);
        if (string.Equals(directory.Name, ConfigDirectoryName, StringComparison.OrdinalIgnoreCase) && directory.Parent is not null)
        {
            return directory.Parent.FullName;
        }

        return directory.FullName;
    }

    private static string ComputeHash(IReadOnlyDictionary<string, string> contents)
    {
        if (contents.Count == 0)
        {
            return "defaults";
        }

        var sb = new StringBuilder();
        foreach (var file in contents.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
        {
            sb.Append(file).Append('\n').Append(contents[file]).Append('\n');
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexString(bytes);
    }
}
