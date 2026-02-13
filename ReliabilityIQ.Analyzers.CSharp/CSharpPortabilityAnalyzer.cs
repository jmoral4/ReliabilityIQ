using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Analyzers.CSharp;

public sealed class CSharpPortabilityAnalyzer : IAnalyzer
{
    private static readonly Regex InlineSuppressionRegex = new(
        @"reliabilityiq:\s*ignore\s+(?<rule>[a-z0-9\.-]+)(?:\s+reason=(?<reason>.*))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public string Name => "Portability.CSharp.Roslyn";

    public string Version => "3.0.0";

    public IReadOnlyCollection<FileCategory> SupportedFileCategories { get; } =
    [
        FileCategory.Source
    ];

    public async Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default)
    {
        if (context.FileCategory != FileCategory.Source ||
            !string.Equals(context.Language, "csharp", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        using var workspace = new AdhocWorkspace();
        var projectInfo = ProjectInfo.Create(
            id: ProjectId.CreateNewId(),
            version: VersionStamp.Create(),
            name: "ReliabilityIQ.AdHoc",
            assemblyName: "ReliabilityIQ.AdHoc",
            language: LanguageNames.CSharp,
            parseOptions: new CSharpParseOptions(LanguageVersion.Preview));

        var project = workspace.AddProject(projectInfo);
        var document = workspace.AddDocument(project.Id, Path.GetFileName(context.FilePath), SourceText.From(context.Content));
        var syntaxTree = await document.GetSyntaxTreeAsync(cancellationToken).ConfigureAwait(false);
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
        if (syntaxTree is null || root is null)
        {
            return [];
        }

        var lines = context.Content.Split('\n');
        var inlineSuppressions = ParseInlineSuppressions(lines);
        var fileSuppressions = FileSuppressionSet.Load(context);
        var isTestCode = IsTestCode(context.FilePath);

        var findings = new List<Finding>();
        foreach (var literal in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (!literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();

            var value = literal.Token.ValueText;
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var usage = UsageContext.FromLiteral(literal);
            if (usage.IsConfigReadStringArgument)
            {
                continue;
            }

            var matchedRuleIds = PortabilityPatternMatcher.MatchRuleIds(value);
            if (matchedRuleIds.Count == 0)
            {
                continue;
            }

            var span = syntaxTree.GetLineSpan(literal.Span);
            var line = span.StartLinePosition.Line + 1;
            var column = span.StartLinePosition.Character + 1;

            foreach (var ruleId in matchedRuleIds)
            {
                if (!PortabilityRuleDefinitions.ById.TryGetValue(ruleId, out var rule))
                {
                    continue;
                }

                var fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, line, column, value);

                if (IsInlineSuppressed(inlineSuppressions, line, ruleId) ||
                    fileSuppressions.IsSuppressed(context.FilePath, ruleId, fingerprint))
                {
                    continue;
                }

                var severity = rule.DefaultSeverity;
                if (isTestCode || HasConfigReadNearby(lines, line))
                {
                    severity = FindingSeverity.Info;
                }

                var confidence = usage.IsInterestingCallsite || usage.IsAttributeArgument ||
                                 ruleId is "portability.hardcoded.connectionstring" or "portability.hardcoded.localhost"
                    ? FindingConfidence.High
                    : FindingConfidence.Medium;

                var metadata = CreateMetadata(usage, ruleId, confidence, line);

                findings.Add(new Finding
                {
                    RuleId = ruleId,
                    FilePath = context.FilePath,
                    Line = line,
                    Column = column,
                    Message = BuildMessage(ruleId, value, usage),
                    Snippet = PortabilityPatternMatcher.GetSnippet(context.Content, line),
                    Severity = severity,
                    Confidence = confidence,
                    Fingerprint = fingerprint,
                    Metadata = metadata
                });
            }
        }

        return findings;
    }

    private static string BuildMessage(string ruleId, string value, UsageContext usage)
    {
        return ruleId switch
        {
            "portability.hardcoded.connectionstring" => "Hardcoded connection string detected in C# code path.",
            "portability.hardcoded.localhost" => "Localhost literal detected; cloud/container workloads usually require configurable bindings.",
            _ => $"Hardcoded portability-sensitive value '{value}' detected in C# {usage.DisplayContext}."
        };
    }

    private static string CreateMetadata(UsageContext usage, string ruleId, FindingConfidence confidence, int line)
    {
        return $$"""{"engine":"roslyn","astConfirmed":{{(usage.IsInterestingCallsite || usage.IsAttributeArgument).ToString().ToLowerInvariant()}},"callsite":"{{Escape(usage.Symbol)}}","context":"{{Escape(usage.DisplayContext)}}","ruleId":"{{ruleId}}","confidence":"{{confidence}}","line":{{line}}}""";
    }

    private static Dictionary<int, List<string>> ParseInlineSuppressions(IReadOnlyList<string> lines)
    {
        var map = new Dictionary<int, List<string>>();

        for (var i = 0; i < lines.Count; i++)
        {
            var match = InlineSuppressionRegex.Match(lines[i]);
            if (!match.Success)
            {
                continue;
            }

            var ruleId = match.Groups["rule"].Value.Trim();
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                continue;
            }

            var lineNumber = i + 1;
            if (!map.TryGetValue(lineNumber, out var existing))
            {
                existing = [];
                map[lineNumber] = existing;
            }

            existing.Add(ruleId);
        }

        return map;
    }

    private static bool IsInlineSuppressed(IReadOnlyDictionary<int, List<string>> suppressions, int line, string ruleId)
    {
        return Matches(line) || Matches(line - 1);

        bool Matches(int key)
        {
            return suppressions.TryGetValue(key, out var rules) &&
                   rules.Any(rule => string.Equals(rule, ruleId, StringComparison.OrdinalIgnoreCase));
        }
    }

    private static bool HasConfigReadNearby(IReadOnlyList<string> lines, int line)
    {
        var start = Math.Max(1, line - 5);
        var end = Math.Min(lines.Count, line + 5);

        for (var current = start; current <= end; current++)
        {
            var text = lines[current - 1];
            if (text.Contains("GetEnvironmentVariable(", StringComparison.Ordinal) ||
                text.Contains("IConfiguration", StringComparison.Ordinal) ||
                text.Contains("Configuration[", StringComparison.Ordinal) ||
                text.Contains("GetConnectionString(", StringComparison.Ordinal) ||
                text.Contains("GetValue<", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsTestCode(string filePath)
    {
        var normalized = filePath.Replace('\\', '/');
        return normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(".tests.", StringComparison.OrdinalIgnoreCase);
    }

    private static string Escape(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }

    private sealed record UsageContext(string Symbol, bool IsInterestingCallsite, bool IsAttributeArgument, bool IsConfigReadStringArgument)
    {
        public string DisplayContext => IsAttributeArgument ? "attribute" : Symbol;

        public static UsageContext FromLiteral(LiteralExpressionSyntax literal)
        {
            var parent = literal.Parent;

            if (parent is ArgumentSyntax argument)
            {
                if (argument.Parent?.Parent is InvocationExpressionSyntax invocation)
                {
                    var symbol = invocation.Expression.ToString();
                    var isConfigRead = symbol.Contains("GetEnvironmentVariable", StringComparison.Ordinal) ||
                                       symbol.Contains("GetConnectionString", StringComparison.Ordinal) ||
                                       symbol.Contains("Configuration", StringComparison.Ordinal);

                    return new UsageContext(
                        Symbol: symbol,
                        IsInterestingCallsite: IsInterestingSymbol(symbol),
                        IsAttributeArgument: false,
                        IsConfigReadStringArgument: isConfigRead);
                }

                if (argument.Parent?.Parent is ObjectCreationExpressionSyntax objectCreation)
                {
                    var symbol = objectCreation.Type.ToString();
                    return new UsageContext(
                        Symbol: symbol,
                        IsInterestingCallsite: IsInterestingSymbol(symbol),
                        IsAttributeArgument: false,
                        IsConfigReadStringArgument: false);
                }
            }

            if (parent is AttributeArgumentSyntax attributeArgument && attributeArgument.Parent?.Parent is AttributeSyntax attribute)
            {
                return new UsageContext(
                    Symbol: attribute.Name.ToString(),
                    IsInterestingCallsite: true,
                    IsAttributeArgument: true,
                    IsConfigReadStringArgument: false);
            }

            return new UsageContext(
                Symbol: parent?.Kind().ToString() ?? "literal",
                IsInterestingCallsite: false,
                IsAttributeArgument: false,
                IsConfigReadStringArgument: false);
        }

        private static bool IsInterestingSymbol(string symbol)
        {
            return symbol.Contains("Uri", StringComparison.Ordinal) ||
                   symbol.Contains("HttpClient", StringComparison.Ordinal) ||
                   symbol.Contains("WebRequest", StringComparison.Ordinal) ||
                   symbol.Contains("Dns", StringComparison.Ordinal) ||
                   symbol.Contains("Socket", StringComparison.Ordinal) ||
                   symbol.Contains("ProcessStartInfo", StringComparison.Ordinal) ||
                   symbol.Contains("File", StringComparison.Ordinal) ||
                   symbol.Contains("Path", StringComparison.Ordinal) ||
                   symbol.Contains("BlobServiceClient", StringComparison.Ordinal) ||
                   symbol.Contains("SqlConnection", StringComparison.Ordinal);
        }
    }

    private sealed class FileSuppressionSet
    {
        private readonly List<Entry> _entries;

        private FileSuppressionSet(List<Entry> entries)
        {
            _entries = entries;
        }

        public static FileSuppressionSet Load(AnalysisContext context)
        {
            var filePath = ResolveSuppressionPath(context.Configuration);
            if (filePath is null || !File.Exists(filePath))
            {
                return new FileSuppressionSet([]);
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
}
