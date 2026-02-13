using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.ConfigDrift;
using YamlDotNet.RepresentationModel;

namespace ReliabilityIQ.Analyzers.ConfigDrift;

public sealed record ConfigDriftFileInput(string FilePath, string Content);

public sealed class ConfigDriftAnalyzer
{
    private static readonly string[] DefaultEnvironmentTokens =
    [
        "dev", "development", "test", "qa", "stage", "staging", "prod", "production", "uat"
    ];

    private static readonly Regex DefaultPattern = new(
        @"^(?<base>.+?)\.(?<env>dev|development|test|qa|stage|staging|prod|production|uat)\.(?<ext>json|ya?ml|toml|ini|config)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex ParameterizedValueRegex = new(
        @"^\s*(\$\{[^}]+\}|\$\([^)]+\)|\{\{[^}]+\}\}|%[^%]+%|@Microsoft\.KeyVault\([^)]+\))\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public IReadOnlyList<Finding> AnalyzeRepository(
        IReadOnlyList<ConfigDriftFileInput> files,
        IReadOnlyDictionary<string, string>? settings = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);

        var findings = new List<Finding>();
        if (files.Count == 0)
        {
            return findings;
        }

        var regexes = BuildPatterns(settings);
        var groups = new Dictionary<string, List<ParsedConfig>>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!TryClassifyEnvironmentFile(file.FilePath, regexes, out var baseName, out var environment, out var extension))
            {
                continue;
            }

            if (!TryFlattenConfig(file.Content, extension, out var flattened))
            {
                continue;
            }

            var directory = Path.GetDirectoryName(file.FilePath)?.Replace('\\', '/') ?? string.Empty;
            var groupKey = $"{directory}|{baseName}.{extension}";

            if (!groups.TryGetValue(groupKey, out var parsed))
            {
                parsed = [];
                groups[groupKey] = parsed;
            }

            parsed.Add(new ParsedConfig(file.FilePath, environment, baseName, extension, flattened));
        }

        foreach (var (_, configs) in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (configs.Count < 2)
            {
                continue;
            }

            AnalyzeGroup(configs, findings, cancellationToken);
        }

        return findings;
    }

    private static void AnalyzeGroup(IReadOnlyList<ParsedConfig> configs, ICollection<Finding> findings, CancellationToken cancellationToken)
    {
        var environments = configs
            .Select(c => c.Environment)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var keys = configs
            .SelectMany(c => c.Values.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var key in keys)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var present = new List<(ParsedConfig Config, string Value)>();
            foreach (var config in configs)
            {
                if (config.Values.TryGetValue(key, out var value))
                {
                    present.Add((config, value));
                }
            }

            var presentEnvs = present
                .Select(p => p.Config.Environment)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (presentEnvs.Count == 1)
            {
                var orphan = present[0];
                findings.Add(CreateFinding(
                    ruleId: "config.drift.orphan_key",
                    filePath: orphan.Config.FilePath,
                    message: $"Config key '{key}' appears only in environment '{orphan.Config.Environment}'.",
                    key: key,
                    baseName: orphan.Config.BaseName,
                    extension: orphan.Config.Extension,
                    environments,
                    presentEnvironments: presentEnvs,
                    missingEnvironments: environments.Except(presentEnvs, StringComparer.OrdinalIgnoreCase).ToList(),
                    valueDiffers: false,
                    confidence: FindingConfidence.High));

                continue;
            }

            if (presentEnvs.Count < environments.Count)
            {
                var missingEnvs = environments.Except(presentEnvs, StringComparer.OrdinalIgnoreCase).ToList();
                foreach (var missing in missingEnvs)
                {
                    var anchor = present[0].Config;
                    findings.Add(CreateFinding(
                        ruleId: "config.drift.missing_key",
                        filePath: anchor.FilePath,
                        message: $"Config key '{key}' exists in [{string.Join(", ", presentEnvs)}] but is missing in '{missing}'.",
                        key: key,
                        baseName: anchor.BaseName,
                        extension: anchor.Extension,
                        environments,
                        presentEnvironments: presentEnvs,
                        missingEnvironments: [missing],
                        valueDiffers: false,
                        confidence: FindingConfidence.High));
                }
            }

            var normalizedValues = present
                .Select(p => NormalizeValue(p.Value))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (normalizedValues.Count < 2)
            {
                continue;
            }

            var hasHardcodedDifference = present.Any(p => !LooksParameterized(p.Value));
            if (!hasHardcodedDifference)
            {
                continue;
            }

            var byEnv = present
                .Select(p => new ValuePreview(p.Config.Environment, BuildSafePreview(p.Value)))
                .ToList();

            var target = present[0].Config;
            findings.Add(CreateFinding(
                ruleId: "config.drift.hardcoded_env_value",
                filePath: target.FilePath,
                message: $"Config key '{key}' has differing environment values and appears hardcoded.",
                key: key,
                baseName: target.BaseName,
                extension: target.Extension,
                environments,
                presentEnvironments: presentEnvs,
                missingEnvironments: [],
                valueDiffers: true,
                confidence: FindingConfidence.Medium,
                valuePreviews: byEnv));
        }
    }

    private static Finding CreateFinding(
        string ruleId,
        string filePath,
        string message,
        string key,
        string baseName,
        string extension,
        IReadOnlyList<string> environments,
        IReadOnlyList<string> presentEnvironments,
        IReadOnlyList<string> missingEnvironments,
        bool valueDiffers,
        FindingConfidence confidence,
        IReadOnlyList<ValuePreview>? valuePreviews = null)
    {
        var metadata = JsonSerializer.Serialize(new
        {
            engine = "config-drift",
            key,
            configSet = $"{baseName}.{extension}",
            environments,
            presentEnvironments,
            missingEnvironments,
            valueDiffers,
            valuePreviews
        });

        return new Finding
        {
            RuleId = ruleId,
            FilePath = filePath,
            Line = 1,
            Column = 1,
            Message = message,
            Snippet = null,
            Severity = ConfigDriftRuleDefinitions.ById[ruleId].DefaultSeverity,
            Confidence = confidence,
            Fingerprint = CreateFingerprint(ruleId, filePath, key, string.Join("|", presentEnvironments), string.Join("|", missingEnvironments)),
            Metadata = metadata
        };
    }

    private static IReadOnlyList<Regex> BuildPatterns(IReadOnlyDictionary<string, string>? settings)
    {
        if (settings is null || !settings.TryGetValue("configDrift.filePatterns", out var raw) || string.IsNullOrWhiteSpace(raw))
        {
            return [DefaultPattern];
        }

        var patterns = new List<Regex>();
        foreach (var entry in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                patterns.Add(new Regex(entry, RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase));
            }
            catch
            {
                // Ignore malformed pattern override and continue with valid ones.
            }
        }

        if (patterns.Count == 0)
        {
            patterns.Add(DefaultPattern);
        }

        return patterns;
    }

    private static bool TryClassifyEnvironmentFile(
        string filePath,
        IReadOnlyList<Regex> patterns,
        out string baseName,
        out string environment,
        out string extension)
    {
        baseName = string.Empty;
        environment = string.Empty;
        extension = string.Empty;

        var fileName = Path.GetFileName(filePath);
        foreach (var pattern in patterns)
        {
            var match = pattern.Match(fileName);
            if (!match.Success)
            {
                continue;
            }

            baseName = match.Groups["base"].Value;
            environment = match.Groups["env"].Value.ToLowerInvariant();
            extension = match.Groups["ext"].Value.ToLowerInvariant();
            return true;
        }

        var tokens = fileName.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length >= 3)
        {
            var possibleEnv = tokens[^2].ToLowerInvariant();
            if (DefaultEnvironmentTokens.Contains(possibleEnv, StringComparer.OrdinalIgnoreCase))
            {
                baseName = string.Join('.', tokens[..^2]);
                environment = possibleEnv;
                extension = tokens[^1].ToLowerInvariant();
                return true;
            }
        }

        return false;
    }

    private static bool TryFlattenConfig(string content, string extension, out Dictionary<string, string> flattened)
    {
        flattened = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            switch (extension.ToLowerInvariant())
            {
                case "json":
                    using (var document = JsonDocument.Parse(content))
                    {
                        FlattenJson(document.RootElement, prefix: null, flattened);
                    }

                    return true;

                case "yaml":
                case "yml":
                    using (var reader = new StringReader(content))
                    {
                        var yaml = new YamlStream();
                        yaml.Load(reader);
                        foreach (var doc in yaml.Documents)
                        {
                            FlattenYaml(doc.RootNode, prefix: null, flattened);
                        }
                    }

                    return true;

                default:
                    return false;
            }
        }
        catch
        {
            return false;
        }
    }

    private static void FlattenJson(JsonElement element, string? prefix, IDictionary<string, string> output)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    var key = string.IsNullOrEmpty(prefix) ? property.Name : $"{prefix}.{property.Name}";
                    FlattenJson(property.Value, key, output);
                }

                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    var key = $"{prefix}[{index}]";
                    FlattenJson(item, key, output);
                    index++;
                }

                break;

            default:
                if (!string.IsNullOrWhiteSpace(prefix))
                {
                    output[prefix] = element.ToString();
                }

                break;
        }
    }

    private static void FlattenYaml(YamlNode node, string? prefix, IDictionary<string, string> output)
    {
        switch (node)
        {
            case YamlMappingNode mapping:
                foreach (var entry in mapping.Children)
                {
                    var keyPart = (entry.Key as YamlScalarNode)?.Value ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(keyPart))
                    {
                        continue;
                    }

                    var key = string.IsNullOrEmpty(prefix) ? keyPart : $"{prefix}.{keyPart}";
                    FlattenYaml(entry.Value, key, output);
                }

                break;

            case YamlSequenceNode sequence:
                for (var i = 0; i < sequence.Children.Count; i++)
                {
                    var key = $"{prefix}[{i}]";
                    FlattenYaml(sequence.Children[i], key, output);
                }

                break;

            case YamlScalarNode scalar:
                if (!string.IsNullOrWhiteSpace(prefix))
                {
                    output[prefix] = scalar.Value ?? string.Empty;
                }

                break;
        }
    }

    private static bool LooksParameterized(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (ParameterizedValueRegex.IsMatch(value))
        {
            return true;
        }

        return value.Contains("keyvault", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("vault.azure.net", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeValue(string value)
    {
        return value.Trim();
    }

    private static string BuildSafePreview(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length <= 32)
        {
            return trimmed;
        }

        return trimmed[..32] + "...";
    }

    private static string CreateFingerprint(params string[] parts)
    {
        var joined = string.Join('|', parts);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(joined));
        return Convert.ToHexString(hash);
    }

    private sealed record ParsedConfig(
        string FilePath,
        string Environment,
        string BaseName,
        string Extension,
        IReadOnlyDictionary<string, string> Values);

    private sealed record ValuePreview(string Environment, string Value);
}
