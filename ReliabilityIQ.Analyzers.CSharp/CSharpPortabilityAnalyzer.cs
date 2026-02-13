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

        AddCloudSdkWithoutAbstractionFindings(root, syntaxTree, context, fileSuppressions, isTestCode, findings);
        AddHardcodedPortFindings(root, syntaxTree, context, fileSuppressions, isTestCode, findings);

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

    private static void AddCloudSdkWithoutAbstractionFindings(
        SyntaxNode root,
        SyntaxTree syntaxTree,
        AnalysisContext context,
        FileSuppressionSet fileSuppressions,
        bool isTestCode,
        List<Finding> findings)
    {
        const string ruleId = "portability.cloud.sdk.no_abstraction";
        if (!PortabilityRuleDefinitions.ById.TryGetValue(ruleId, out var rule))
        {
            return;
        }

        foreach (var objectCreation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeName = objectCreation.Type.ToString();
            if (!IsCloudSdkType(typeName))
            {
                continue;
            }

            if (IsAssignedToInterfaceType(objectCreation))
            {
                continue;
            }

            var span = syntaxTree.GetLineSpan(objectCreation.Type.Span);
            var line = span.StartLinePosition.Line + 1;
            var column = span.StartLinePosition.Character + 1;
            var fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, line, column, typeName);

            if (fileSuppressions.IsSuppressed(context.FilePath, ruleId, fingerprint))
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = ruleId,
                FilePath = context.FilePath,
                Line = line,
                Column = column,
                Message = $"Direct cloud SDK type '{typeName}' is instantiated without an abstraction boundary.",
                Snippet = PortabilityPatternMatcher.GetSnippet(context.Content, line),
                Severity = isTestCode ? FindingSeverity.Info : rule.DefaultSeverity,
                Confidence = FindingConfidence.High,
                Fingerprint = fingerprint,
                Metadata = $$"""{"engine":"roslyn","astConfirmed":true,"callsite":"new {{Escape(typeName)}}","ruleId":"{{ruleId}}","confidence":"High"}"""
            });
        }
    }

    private static void AddHardcodedPortFindings(
        SyntaxNode root,
        SyntaxTree syntaxTree,
        AnalysisContext context,
        FileSuppressionSet fileSuppressions,
        bool isTestCode,
        List<Finding> findings)
    {
        const string ruleId = "portability.hardcoded.port";
        if (!PortabilityRuleDefinitions.ById.TryGetValue(ruleId, out var rule))
        {
            return;
        }

        foreach (var numericLiteral in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (!numericLiteral.IsKind(SyntaxKind.NumericLiteralExpression))
            {
                continue;
            }

            if (numericLiteral.Token.Value is not int intValue || !PortabilityPatternMatcher.IsNonStandardPort(intValue))
            {
                continue;
            }

            var symbol = FindPortCallsite(numericLiteral);
            if (symbol is null)
            {
                continue;
            }

            var span = syntaxTree.GetLineSpan(numericLiteral.Span);
            var line = span.StartLinePosition.Line + 1;
            var column = span.StartLinePosition.Character + 1;
            var fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, line, column, numericLiteral.Token.ValueText);

            if (fileSuppressions.IsSuppressed(context.FilePath, ruleId, fingerprint))
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = ruleId,
                FilePath = context.FilePath,
                Line = line,
                Column = column,
                Message = $"Hardcoded non-standard port '{intValue}' detected in '{symbol}'.",
                Snippet = PortabilityPatternMatcher.GetSnippet(context.Content, line),
                Severity = isTestCode ? FindingSeverity.Info : rule.DefaultSeverity,
                Confidence = FindingConfidence.High,
                Fingerprint = fingerprint,
                Metadata = $$"""{"engine":"roslyn","astConfirmed":true,"callsite":"{{Escape(symbol)}}","ruleId":"{{ruleId}}","confidence":"High"}"""
            });
        }
    }

    private static bool IsCloudSdkType(string typeName)
    {
        return typeName.Contains("BlobServiceClient", StringComparison.Ordinal) ||
               typeName.Contains("QueueServiceClient", StringComparison.Ordinal) ||
               typeName.Contains("TableServiceClient", StringComparison.Ordinal) ||
               typeName.Contains("SecretClient", StringComparison.Ordinal) ||
               typeName.Contains("AmazonS3Client", StringComparison.Ordinal) ||
               typeName.Contains("Google.Cloud", StringComparison.Ordinal);
    }

    private static bool IsAssignedToInterfaceType(ObjectCreationExpressionSyntax objectCreation)
    {
        if (objectCreation.Parent is EqualsValueClauseSyntax equals &&
            equals.Parent is VariableDeclaratorSyntax declarator &&
            declarator.Parent?.Parent is VariableDeclarationSyntax declaration &&
            declaration.Type is IdentifierNameSyntax identifier)
        {
            return identifier.Identifier.Text.StartsWith('I');
        }

        return false;
    }

    private static string? FindPortCallsite(LiteralExpressionSyntax literal)
    {
        var current = literal.Parent;
        while (current is not null)
        {
            if (current is InvocationExpressionSyntax invocation)
            {
                var symbol = invocation.Expression.ToString();
                if (symbol.Contains("Connect", StringComparison.OrdinalIgnoreCase) ||
                    symbol.Contains("Listen", StringComparison.OrdinalIgnoreCase) ||
                    symbol.Contains("Bind", StringComparison.OrdinalIgnoreCase))
                {
                    return symbol;
                }
            }

            if (current is ObjectCreationExpressionSyntax objectCreation)
            {
                var typeName = objectCreation.Type.ToString();
                if (typeName.Contains("IPEndPoint", StringComparison.OrdinalIgnoreCase) ||
                    typeName.Contains("Socket", StringComparison.OrdinalIgnoreCase))
                {
                    return typeName;
                }
            }

            current = current.Parent;
        }

        return null;
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
        return normalized.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
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
}
