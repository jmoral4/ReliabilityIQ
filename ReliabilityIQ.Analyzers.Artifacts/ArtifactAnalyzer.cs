using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Artifacts;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace ReliabilityIQ.Analyzers.Artifacts;

public sealed class ArtifactAnalyzer : IAnalyzer
{
    private static readonly Regex GuidRegex = new(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CloudEndpointRegex = new(
        "(windows\\.net|azure\\.com|core\\.windows\\.net|database\\.windows\\.net|microsoftonline\\.com)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex RegionRegex = new(
        "^(eastus2?|westus[23]?|centralus|northcentralus|southcentralus|westeurope|northeurope|uksouth|ukwest|southeastasia|eastasia)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex SecretKeyRegex = new(
        "(secret|password|token|clientsecret|apikey|accesskey|key)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex WindowsPathRegex = new(
        "([A-Za-z]:\\\\|\\\\\\\\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public string Name => "Deploy.Artifacts";

    public string Version => "1.0.0";

    public IReadOnlyCollection<FileCategory> SupportedFileCategories { get; } =
    [
        FileCategory.DeploymentArtifact,
        FileCategory.Config,
        FileCategory.Source,
        FileCategory.Unknown
    ];

    public Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default)
    {
        var artifactKind = ArtifactClassifier.DetectKind(context.FilePath, context.Content, context.Configuration);
        if (artifactKind == ArtifactKind.Unknown)
        {
            return Task.FromResult<IEnumerable<Finding>>([]);
        }

        var extension = Path.GetExtension(context.FilePath);
        var findings = new List<Finding>();

        if (IsYaml(extension))
        {
            AnalyzeYaml(context, artifactKind, findings, cancellationToken);
            return Task.FromResult<IEnumerable<Finding>>(findings);
        }

        if (IsJson(extension))
        {
            AnalyzeJson(context, artifactKind, findings, cancellationToken);
            return Task.FromResult<IEnumerable<Finding>>(findings);
        }

        AnalyzeTextFallback(context, artifactKind, findings, cancellationToken, null);
        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static void AnalyzeYaml(AnalysisContext context, ArtifactKind artifactKind, List<Finding> findings, CancellationToken cancellationToken)
    {
        try
        {
            using var reader = new StringReader(context.Content);
            var yaml = new YamlStream();
            yaml.Load(reader);

            var scalars = new List<ScalarOccurrence>();
            foreach (var doc in yaml.Documents)
            {
                CollectYamlScalars(doc.RootNode, "$", scalars);
            }

            EmitRuleFindings(context, artifactKind, scalars, findings, cancellationToken);
        }
        catch (YamlException ex)
        {
            findings.Add(CreateParseErrorFinding(context, artifactKind, (int)ex.Start.Line, (int)ex.Start.Column, ex.Message));
            AnalyzeTextFallback(context, artifactKind, findings, cancellationToken, ex.Message);
        }
    }

    private static void AnalyzeJson(AnalysisContext context, ArtifactKind artifactKind, List<Finding> findings, CancellationToken cancellationToken)
    {
        try
        {
            using var document = JsonDocument.Parse(context.Content);
            var scalars = new List<ScalarOccurrence>();
            CollectJsonScalars(document.RootElement, "$", null, scalars);
            EmitRuleFindings(context, artifactKind, scalars, findings, cancellationToken);
        }
        catch (JsonException ex)
        {
            var line = (int)(ex.LineNumber ?? 0) + 1;
            var column = (int)(ex.BytePositionInLine ?? 0) + 1;
            findings.Add(CreateParseErrorFinding(context, artifactKind, line, column, ex.Message));
            AnalyzeTextFallback(context, artifactKind, findings, cancellationToken, ex.Message);
        }
    }

    private static void AnalyzeTextFallback(
        AnalysisContext context,
        ArtifactKind artifactKind,
        List<Finding> findings,
        CancellationToken cancellationToken,
        string? parserError)
    {
        var lines = context.Content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rawLine = lines[i].TrimEnd('\r');
            var normalized = rawLine.Trim();

            if (normalized.Length == 0 || normalized.StartsWith('#'))
            {
                continue;
            }

            if (artifactKind == ArtifactKind.Ev2)
            {
                if (normalized.Contains("subscription", StringComparison.OrdinalIgnoreCase) && GuidRegex.IsMatch(ExtractValue(normalized)))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.hardcoded.subscription", rawLine, i + 1, 1, "$[line]", ExtractValue(normalized), "fallback", parserError));
                }

                if (normalized.Contains("tenant", StringComparison.OrdinalIgnoreCase) && GuidRegex.IsMatch(ExtractValue(normalized)))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.hardcoded.tenant", rawLine, i + 1, 1, "$[line]", ExtractValue(normalized), "fallback", parserError));
                }

                if (normalized.Contains("WaitDuration", StringComparison.OrdinalIgnoreCase) && normalized.Contains("PT0S", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.zero_bake_time", rawLine, i + 1, 1, "$[line]", "PT0S", "fallback", parserError));
                }
            }
            else if (artifactKind == ArtifactKind.Ado)
            {
                if (normalized.Contains("pool", StringComparison.OrdinalIgnoreCase) && !IsParameterToken(ExtractValue(normalized)))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.hardcoded.agentpool", rawLine, i + 1, 1, "$[line]", ExtractValue(normalized), "fallback", parserError));
                }

                if (normalized.Contains(":latest", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.container_latest", rawLine, i + 1, 1, "$[line]", ExtractValue(normalized), "fallback", parserError));
                }
            }
        }
    }

    private static void EmitRuleFindings(
        AnalysisContext context,
        ArtifactKind artifactKind,
        IReadOnlyList<ScalarOccurrence> scalars,
        List<Finding> findings,
        CancellationToken cancellationToken)
    {
        foreach (var scalar in scalars)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var key = scalar.Key?.ToLowerInvariant() ?? string.Empty;
            var value = scalar.Value;
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (artifactKind == ArtifactKind.Ev2)
            {
                if ((key.Contains("subscription") || scalar.Path.Contains("subscription", StringComparison.OrdinalIgnoreCase)) &&
                    GuidRegex.IsMatch(value) &&
                    !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.hardcoded.subscription", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key.Contains("tenant") || scalar.Path.Contains("tenant", StringComparison.OrdinalIgnoreCase)) &&
                    GuidRegex.IsMatch(value) &&
                    !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.hardcoded.tenant", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if (CloudEndpointRegex.IsMatch(value) && !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.hardcoded.endpoint", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key.Contains("region") || scalar.Path.Contains("region", StringComparison.OrdinalIgnoreCase)) &&
                    RegionRegex.IsMatch(value) &&
                    !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.hardcoded.region", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key.Contains("waitduration") || key.Contains("wait_duration")) && value.Equals("PT0S", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.zero_bake_time", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if (SecretKeyRegex.IsMatch(key) && !LooksLikeKeyVaultReference(value) && !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.inline_secret", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key.Contains("environment") || key == "env") &&
                    IsEnvironmentConstant(value) &&
                    !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ev2.env_constant", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }
            }

            if (artifactKind == ArtifactKind.Ado)
            {
                if ((key == "pool" || key == "name" || scalar.Path.Contains(".pool", StringComparison.OrdinalIgnoreCase)) &&
                    scalar.Path.Contains("pool", StringComparison.OrdinalIgnoreCase) &&
                    !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.hardcoded.agentpool", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key.Contains("path") || key == "script") && WindowsPathRegex.IsMatch(value) && !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.hardcoded.path", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key.Contains("serviceconnection") || key.Contains("endpoint") || key.Contains("connectedservicename")) &&
                    !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.hardcoded.endpoint", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if (SecretKeyRegex.IsMatch(key) && !LooksLikeSecureVariable(value) && !IsParameterToken(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.inline_secret", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key == "script" || key.Contains("powershell") || key.Contains("bash")) && WindowsPathRegex.IsMatch(value))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.platform_assumption", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if ((key == "image" || key.Contains("container")) && value.Contains(":latest", StringComparison.OrdinalIgnoreCase) && !value.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.container_latest", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }

                if (key == "script" && value.Contains(":latest", StringComparison.OrdinalIgnoreCase) && !value.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, "deploy.ado.container_latest", scalar.Snippet, scalar.Line, scalar.Column, scalar.Path, value, "structured", null));
                }
            }
        }

        if (artifactKind == ArtifactKind.Ev2)
        {
            if (!scalars.Any(s => (s.Key?.Contains("waitduration", StringComparison.OrdinalIgnoreCase) ?? false) || s.Path.Contains("waitDuration", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(CreateFinding(context, "deploy.ev2.zero_bake_time", null, 1, 1, "$", "missing WaitDuration", "structured", null,
                    messageOverride: "EV2 artifact does not define wait duration; add non-zero bake time between deployment steps."));
            }

            if (!scalars.Any(s => s.Path.Contains("health", StringComparison.OrdinalIgnoreCase) || (s.Key?.Contains("health", StringComparison.OrdinalIgnoreCase) ?? false)))
            {
                findings.Add(CreateFinding(context, "deploy.ev2.no_health_check", null, 1, 1, "$", "missing health checks", "structured", null,
                    messageOverride: "EV2 artifact has no post-deploy health check configuration."));
            }

            var regionValues = scalars
                .Where(s => (s.Key?.Contains("region", StringComparison.OrdinalIgnoreCase) ?? false) || s.Path.Contains("region", StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (regionValues.Count == 1)
            {
                findings.Add(CreateFinding(context, "deploy.ev2.single_region", null, 1, 1, "$", regionValues[0], "structured", null,
                    messageOverride: "EV2 artifact appears pinned to a single region without explicit failover path."));
            }
        }

        if (artifactKind == ArtifactKind.Ado)
        {
            var hasProdStage = scalars.Any(s =>
                (s.Key?.Equals("stage", StringComparison.OrdinalIgnoreCase) ?? false) &&
                (s.Value.Contains("prod", StringComparison.OrdinalIgnoreCase) || s.Value.Contains("production", StringComparison.OrdinalIgnoreCase)));

            var hasApproval = scalars.Any(s =>
                s.Path.Contains("approval", StringComparison.OrdinalIgnoreCase) ||
                s.Path.Contains("check", StringComparison.OrdinalIgnoreCase) ||
                (s.Key?.Contains("approval", StringComparison.OrdinalIgnoreCase) ?? false));

            if (hasProdStage && !hasApproval)
            {
                findings.Add(CreateFinding(context, "deploy.ado.missing_approval", null, 1, 1, "$", "production stage without approval", "structured", null));
            }
        }

        Deduplicate(findings);
    }

    private static void CollectYamlScalars(YamlNode node, string path, List<ScalarOccurrence> output)
    {
        if (node is YamlScalarNode scalar)
        {
            output.Add(new ScalarOccurrence(path, null, scalar.Value ?? string.Empty, (int)scalar.Start.Line, (int)scalar.Start.Column, scalar.Value));
            return;
        }

        if (node is YamlSequenceNode sequence)
        {
            for (var i = 0; i < sequence.Children.Count; i++)
            {
                CollectYamlScalars(sequence.Children[i], $"{path}[{i}]", output);
            }

            return;
        }

        if (node is YamlMappingNode mapping)
        {
            foreach (var item in mapping.Children)
            {
                var keyText = (item.Key as YamlScalarNode)?.Value ?? item.Key.ToString();
                var childPath = path == "$" ? $"$.{keyText}" : $"{path}.{keyText}";

                if (item.Value is YamlScalarNode valueScalar)
                {
                    output.Add(new ScalarOccurrence(
                        childPath,
                        keyText,
                        valueScalar.Value ?? string.Empty,
                        (int)valueScalar.Start.Line,
                        (int)valueScalar.Start.Column,
                        valueScalar.Value));
                }
                else
                {
                    CollectYamlScalars(item.Value, childPath, output);
                }
            }
        }
    }

    private static void CollectJsonScalars(JsonElement element, string path, string? key, List<ScalarOccurrence> output)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    CollectJsonScalars(property.Value, $"{path}.{property.Name}", property.Name, output);
                }
                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    CollectJsonScalars(item, $"{path}[{index}]", key, output);
                    index++;
                }
                break;

            case JsonValueKind.String:
                output.Add(new ScalarOccurrence(path, key, element.GetString() ?? string.Empty, 1, 1, element.GetString()));
                break;

            case JsonValueKind.Number:
                output.Add(new ScalarOccurrence(path, key, element.ToString(), 1, 1, element.ToString()));
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
                output.Add(new ScalarOccurrence(path, key, element.GetBoolean().ToString(), 1, 1, element.GetBoolean().ToString()));
                break;
        }
    }

    private static Finding CreateParseErrorFinding(AnalysisContext context, ArtifactKind kind, int line, int column, string error)
    {
        var safeLine = line > 0 ? line : 1;
        var safeColumn = column > 0 ? column : 1;
        var snippet = GetLineSnippet(context.Content, safeLine);

        return CreateFinding(
            context,
            ArtifactRuleDefinitions.ParseErrorRuleId,
            snippet,
            safeLine,
            safeColumn,
            "$",
            error,
            "structured",
            error,
            $"Failed to parse {kind} artifact as structured {(IsJson(Path.GetExtension(context.FilePath)) ? "JSON" : "YAML")}: {error}");
    }

    private static Finding CreateFinding(
        AnalysisContext context,
        string ruleId,
        string? snippet,
        int line,
        int column,
        string path,
        string matchedValue,
        string mode,
        string? parserError,
        string? messageOverride = null)
    {
        var rule = ArtifactRuleDefinitions.ById[ruleId];
        var message = messageOverride ?? $"{rule.Title}: '{matchedValue}' at {path}.";

        var metadata = JsonSerializer.Serialize(new
        {
            engine = "artifact-structured",
            parserMode = mode,
            artifactPath = path,
            matchedValue,
            parserError
        });

        return new Finding
        {
            RuleId = ruleId,
            FilePath = context.FilePath,
            Line = Math.Max(1, line),
            Column = Math.Max(1, column),
            Message = message,
            Snippet = snippet,
            Severity = rule.DefaultSeverity,
            Confidence = mode == "structured" ? FindingConfidence.High : FindingConfidence.Medium,
            Fingerprint = CreateFingerprint(ruleId, context.FilePath, path, matchedValue),
            Metadata = metadata
        };
    }

    private static string ExtractValue(string line)
    {
        var idx = line.IndexOf(':');
        if (idx >= 0 && idx < line.Length - 1)
        {
            return line[(idx + 1)..].Trim().Trim('"', '\'', '[', ']', ',');
        }

        var eq = line.IndexOf('=');
        if (eq >= 0 && eq < line.Length - 1)
        {
            return line[(eq + 1)..].Trim().Trim('"', '\'', ',');
        }

        return line.Trim();
    }

    private static bool IsParameterToken(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Contains("$(", StringComparison.Ordinal) ||
               value.Contains("${", StringComparison.Ordinal) ||
               value.Contains("{{", StringComparison.Ordinal) ||
               value.Contains("[parameters(", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("#{", StringComparison.Ordinal);
    }

    private static bool LooksLikeKeyVaultReference(string value)
    {
        return value.Contains("keyvault", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("kv://", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("secretref", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeSecureVariable(string value)
    {
        return value.Contains("$(", StringComparison.Ordinal) ||
               value.Contains("${{", StringComparison.Ordinal) ||
               value.Contains("variables[", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("keyvault", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsEnvironmentConstant(string value)
    {
        return value.Equals("dev", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("development", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("test", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("staging", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("prod", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("production", StringComparison.OrdinalIgnoreCase);
    }

    private static string CreateFingerprint(string ruleId, string filePath, string path, string value)
    {
        var payload = $"{ruleId}|{filePath}|{path}|{value}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash);
    }

    private static bool IsYaml(string extension)
        => extension.Equals(".yaml", StringComparison.OrdinalIgnoreCase) || extension.Equals(".yml", StringComparison.OrdinalIgnoreCase);

    private static bool IsJson(string extension)
        => extension.Equals(".json", StringComparison.OrdinalIgnoreCase);

    private static string? GetLineSnippet(string content, int line)
    {
        if (line <= 0)
        {
            return null;
        }

        var lines = content.Split('\n');
        if (line > lines.Length)
        {
            return null;
        }

        return lines[line - 1].TrimEnd('\r');
    }

    private static void Deduplicate(List<Finding> findings)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = findings.Count - 1; i >= 0; i--)
        {
            var key = findings[i].RuleId + "|" + findings[i].Fingerprint;
            if (!seen.Add(key))
            {
                findings.RemoveAt(i);
            }
        }
    }

    private sealed record ScalarOccurrence(
        string Path,
        string? Key,
        string Value,
        int Line,
        int Column,
        string? Snippet);
}
