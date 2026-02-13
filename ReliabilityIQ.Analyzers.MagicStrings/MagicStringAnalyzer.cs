using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.MagicStrings;
using ReliabilityIQ.Core.Portability;
using System.Management.Automation.Language;

namespace ReliabilityIQ.Analyzers.MagicStrings;

public sealed class MagicStringAnalyzer
{
    private static readonly Regex GenericStringLiteralRegex = new(
        "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex GuidRegex = new(
        @"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex IsoDateRegex = new(
        @"\b\d{4}-\d{2}-\d{2}(?:[tT ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SemverRegex = new(
        @"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly HashSet<string> DefaultStopWords =
    [
        "the", "a", "an", "and", "or", "is", "are", "to", "for", "of", "in", "on", "this", "that", "with", "from", "at", "by"
    ];

    private static readonly Dictionary<string, IReadOnlyList<string>> DefaultLoggingSinks =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["csharp"] = ["Console.Write", "ILogger", "Log", "Trace", "Debug", "Serilog"],
            ["cpp"] = ["std::cout", "std::cerr", "printf", "spdlog", "log("],
            ["python"] = ["logging.", "logger.", "print("],
            ["powershell"] = ["Write-Host", "Write-Output", "Write-Verbose", "Write-Debug", "Write-Information"],
            ["rust"] = ["println!", "eprintln!", "log::", "tracing::"]
        };

    private static readonly Dictionary<string, IReadOnlyList<string>> CallsiteTokens =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["cpp"] = ["connect(", "getaddrinfo(", "curl_easy_setopt(", "fopen(", "if", "switch", "throw"],
            ["python"] = ["requests.", "socket.", "open(", "if ", "match ", "raise"],
            ["rust"] = ["reqwest::", "std::net::", "std::fs::", "if ", "match ", "panic!"],
            ["javascript"] = ["if (", "switch(", "throw new", "console."],
            ["typescript"] = ["if (", "switch(", "throw new", "console."],
            ["jsx"] = ["if (", "switch(", "throw new", "console."]
        };

    public IReadOnlyList<MagicStringCandidate> AnalyzeRepository(
        IReadOnlyList<MagicStringFileInput> files,
        MagicStringsAnalysisOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(options);

        var occurrences = new List<MagicStringOccurrence>();
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            occurrences.AddRange(ExtractOccurrences(file, options));
        }

        var grouped = occurrences
            .Where(o => o.NormalizedText.Length > 0)
            .GroupBy(o => o.NormalizedText, StringComparer.Ordinal)
            .ToList();

        var candidates = new List<MagicStringCandidate>(grouped.Count);
        foreach (var group in grouped)
        {
            var candidate = BuildCandidate(group.Key, group.ToList(), options);
            if (candidate is not null)
            {
                candidates.Add(candidate);
            }
        }

        var limited = ApplyLimits(candidates, options);
        return limited
            .OrderByDescending(c => c.MagicScore)
            .ThenByDescending(c => c.OccurrenceCount)
            .ThenBy(c => c.NormalizedText, StringComparer.Ordinal)
            .ToList();
    }

    private IEnumerable<MagicStringOccurrence> ExtractOccurrences(MagicStringFileInput file, MagicStringsAnalysisOptions options)
    {
        if (file.Category is FileCategory.Generated or FileCategory.Vendor or FileCategory.IDE)
        {
            return [];
        }

        if (file.Category != FileCategory.Source)
        {
            return [];
        }

        if (string.Equals(file.Language, "csharp", StringComparison.OrdinalIgnoreCase))
        {
            return ExtractCSharpOccurrences(file, options);
        }

        if (string.Equals(file.Language, "powershell", StringComparison.OrdinalIgnoreCase))
        {
            return ExtractPowerShellOccurrences(file, options);
        }

        return ExtractLineBasedOccurrences(file, options);
    }

    private IEnumerable<MagicStringOccurrence> ExtractCSharpOccurrences(MagicStringFileInput file, MagicStringsAnalysisOptions options)
    {
        using var workspace = new AdhocWorkspace();
        var projectInfo = ProjectInfo.Create(
            id: ProjectId.CreateNewId(),
            version: VersionStamp.Create(),
            name: "ReliabilityIQ.MagicStrings.AdHoc",
            assemblyName: "ReliabilityIQ.MagicStrings.AdHoc",
            language: LanguageNames.CSharp,
            parseOptions: new CSharpParseOptions(LanguageVersion.Preview));

        var project = workspace.AddProject(projectInfo);
        var document = workspace.AddDocument(project.Id, Path.GetFileName(file.FilePath), SourceText.From(file.Content));
        var syntaxTree = document.GetSyntaxTreeAsync().GetAwaiter().GetResult();
        var root = document.GetSyntaxRootAsync().GetAwaiter().GetResult();
        if (syntaxTree is null || root is null)
        {
            return [];
        }

        var occurrences = new List<MagicStringOccurrence>();
        foreach (var literal in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (!literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                continue;
            }

            var rawText = literal.Token.ValueText;
            if (!TryBuildCommonOccurrence(file, rawText, out var normalized, out var reason, options))
            {
                continue;
            }

            var lineSpan = syntaxTree.GetLineSpan(literal.Span);
            var line = lineSpan.StartLinePosition.Line + 1;
            var column = lineSpan.StartLinePosition.Character + 1;
            var invocation = literal.Ancestors().OfType<InvocationExpressionSyntax>().FirstOrDefault();
            var callsite = invocation?.Expression.ToString();

            var parentKinds = literal.Ancestors().Take(3).Select(a => a.Kind().ToString());
            var parentNodeType = string.Join('>', parentKinds);
            var isComparison = literal.Ancestors().Any(IsComparisonSyntax);
            var isConditional = literal.Ancestors().Any(IsConditionalSyntax);
            var isExceptionMessage = literal.Ancestors().Any(IsExceptionSyntax);
            var isLogging = IsLoggingCallsite(file.Language, callsite, literal.GetText().ToString(), options);

            if (isLogging)
            {
                continue;
            }

            occurrences.Add(new MagicStringOccurrence(
                RawText: rawText,
                NormalizedText: normalized,
                FilePath: file.FilePath,
                Line: line,
                Column: column,
                Language: file.Language ?? "unknown",
                ParentNodeType: parentNodeType,
                CallsiteSymbol: callsite,
                IsComparisonUsage: isComparison,
                IsConditionalUsage: isConditional,
                IsExceptionMessage: isExceptionMessage,
                IsTestCode: IsTestCode(file.FilePath),
                IsAstConfirmed: true,
                FilterReason: reason));
        }

        return occurrences;
    }

    private IEnumerable<MagicStringOccurrence> ExtractPowerShellOccurrences(MagicStringFileInput file, MagicStringsAnalysisOptions options)
    {
        ScriptBlockAst ast;
        try
        {
            ast = Parser.ParseInput(file.Content, out _, out _);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"PowerShell parse failed for '{file.FilePath}' during magic string extraction: {ex.Message}");
            return [];
        }

        var occurrences = new List<MagicStringOccurrence>();
        var candidates = ast.FindAll(node => node is StringConstantExpressionAst or ExpandableStringExpressionAst, searchNestedScriptBlocks: true);

        foreach (var candidate in candidates)
        {
            var rawText = candidate switch
            {
                StringConstantExpressionAst constant => constant.Value,
                ExpandableStringExpressionAst expandable => expandable.Value,
                _ => string.Empty
            };

            if (!TryBuildCommonOccurrence(file, rawText, out var normalized, out var reason, options))
            {
                continue;
            }

            var command = FindParentCommand(candidate);
            var commandName = command?.GetCommandName();
            var isLogging = IsLoggingCallsite(file.Language, commandName, command?.Extent.Text ?? string.Empty, options);
            if (isLogging)
            {
                continue;
            }

            var isComparison = candidate.Parent is BinaryExpressionAst binary &&
                               binary.Operator is TokenKind.Ieq or TokenKind.Ine or TokenKind.Ceq or TokenKind.Cne or TokenKind.Ilike;
            var isConditional = GetAstAncestors(candidate).Any(a => a is IfStatementAst or WhileStatementAst or ForEachStatementAst);
            var isException = commandName?.Equals("throw", StringComparison.OrdinalIgnoreCase) == true ||
                              GetAstAncestors(candidate).Any(a => a is ThrowStatementAst);

            var parentType = candidate.Parent?.GetType().Name ?? "Ast";

            occurrences.Add(new MagicStringOccurrence(
                RawText: rawText,
                NormalizedText: normalized,
                FilePath: file.FilePath,
                Line: candidate.Extent.StartLineNumber,
                Column: candidate.Extent.StartColumnNumber,
                Language: file.Language ?? "unknown",
                ParentNodeType: parentType,
                CallsiteSymbol: commandName,
                IsComparisonUsage: isComparison,
                IsConditionalUsage: isConditional,
                IsExceptionMessage: isException,
                IsTestCode: IsTestCode(file.FilePath),
                IsAstConfirmed: true,
                FilterReason: reason));
        }

        return occurrences;
    }

    private IEnumerable<MagicStringOccurrence> ExtractLineBasedOccurrences(MagicStringFileInput file, MagicStringsAnalysisOptions options)
    {
        var lines = file.Content.Split('\n');
        var occurrences = new List<MagicStringOccurrence>();

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var callsite = DetectLineCallsite(file.Language, line);
            var isLoggingLine = IsLoggingCallsite(file.Language, callsite, line, options);

            foreach (Match match in GenericStringLiteralRegex.Matches(line))
            {
                if (!match.Success || match.Value.Length < 2)
                {
                    continue;
                }

                var rawText = match.Value[1..^1];
                if (!TryBuildCommonOccurrence(file, rawText, out var normalized, out var reason, options))
                {
                    continue;
                }

                if (isLoggingLine)
                {
                    continue;
                }

                var isComparison = line.Contains("==", StringComparison.Ordinal) ||
                                   line.Contains("!=", StringComparison.Ordinal) ||
                                   line.Contains("case ", StringComparison.OrdinalIgnoreCase) ||
                                   line.Contains("match ", StringComparison.OrdinalIgnoreCase) ||
                                   line.Contains("ContainsKey", StringComparison.OrdinalIgnoreCase) ||
                                   line.Contains("TryGetValue", StringComparison.OrdinalIgnoreCase);

                var isConditional = line.Contains("if ", StringComparison.OrdinalIgnoreCase) ||
                                    line.Contains("if(", StringComparison.OrdinalIgnoreCase) ||
                                    line.Contains("else if", StringComparison.OrdinalIgnoreCase) ||
                                    line.Contains("while ", StringComparison.OrdinalIgnoreCase);

                var isException = line.Contains("throw", StringComparison.OrdinalIgnoreCase) ||
                                  line.Contains("raise", StringComparison.OrdinalIgnoreCase) ||
                                  line.Contains("panic!", StringComparison.OrdinalIgnoreCase);

                occurrences.Add(new MagicStringOccurrence(
                    RawText: rawText,
                    NormalizedText: normalized,
                    FilePath: file.FilePath,
                    Line: i + 1,
                    Column: match.Index + 1,
                    Language: file.Language ?? "unknown",
                    ParentNodeType: "line-based",
                    CallsiteSymbol: callsite,
                    IsComparisonUsage: isComparison,
                    IsConditionalUsage: isConditional,
                    IsExceptionMessage: isException,
                    IsTestCode: IsTestCode(file.FilePath),
                    IsAstConfirmed: callsite is not null,
                    FilterReason: reason));
            }
        }

        return occurrences;
    }

    private static bool TryBuildCommonOccurrence(
        MagicStringFileInput file,
        string rawText,
        out string normalized,
        out string? filterReason,
        MagicStringsAnalysisOptions options)
    {
        normalized = NormalizeLiteral(rawText);
        filterReason = null;

        if (normalized.Length <= 2)
        {
            filterReason = "too-short";
            return false;
        }

        var denylisted = MatchesAnyWildcard(normalized, options.DenylistPatterns);
        if (!denylisted && MatchesAnyWildcard(normalized, options.AllowlistPatterns))
        {
            filterReason = "allowlisted";
            return false;
        }

        if (!denylisted && PortabilityPatternMatcher.MatchRuleIds(normalized).Count > 0)
        {
            filterReason = "covered-by-portability";
            return false;
        }

        if (!denylisted && (GuidRegex.IsMatch(normalized) || IsoDateRegex.IsMatch(normalized) || SemverRegex.IsMatch(normalized)))
        {
            filterReason = "safe-format";
            return false;
        }

        if (!denylisted && MagicStringHeuristics.IsNaturalLanguage(normalized, DefaultStopWords))
        {
            filterReason = "natural-language";
            return false;
        }

        if (!denylisted && MagicStringHeuristics.ShannonEntropy(normalized) >= options.EntropyThreshold && normalized.Length >= 16)
        {
            filterReason = "high-entropy-secret-candidate";
            return false;
        }

        return true;
    }

    private static MagicStringCandidate? BuildCandidate(string normalizedText, List<MagicStringOccurrence> occurrences, MagicStringsAnalysisOptions options)
    {
        if (occurrences.Count < options.MinOccurrences)
        {
            return null;
        }

        var occurrenceCount = occurrences.Count;
        var comparisonCount = occurrences.Count(o => o.IsComparisonUsage);
        var conditionalCount = occurrences.Count(o => o.IsConditionalUsage);
        var exceptionCount = occurrences.Count(o => o.IsExceptionMessage);
        var allInTests = occurrences.All(o => o.IsTestCode);

        var frequencyScore = Math.Log2(occurrenceCount + 1d);
        var usageBoost = 1d + (comparisonCount > 0 ? 0.9d : 0d) + (conditionalCount > 0 ? 0.4d : 0d);

        var penalty = 0d;
        if (allInTests)
        {
            penalty += 0.45d;
        }

        if (exceptionCount > 0)
        {
            var ratio = exceptionCount / (double)occurrenceCount;
            penalty += Math.Min(0.35d, 0.35d * ratio);
        }

        penalty = Math.Clamp(penalty, 0d, 0.9d);
        var magicScore = frequencyScore * usageBoost * (1d - penalty);

        var sortedOccurrences = occurrences
            .OrderByDescending(o => o.IsComparisonUsage)
            .ThenByDescending(o => o.IsConditionalUsage)
            .ThenBy(o => o.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(o => o.Line)
            .ThenBy(o => o.Column)
            .ToList();

        var top = sortedOccurrences[0];
        var contextSummary = BuildContextSummary(occurrences);
        var metadata = BuildMetadata(occurrences, contextSummary, frequencyScore, usageBoost, penalty, magicScore);

        var ruleId = comparisonCount > 0
            ? "magic-string.comparison-used"
            : occurrenceCount >= Math.Max(options.MinOccurrences * 2, 5)
                ? "magic-string.high-frequency"
                : "magic-string.candidate";

        return new MagicStringCandidate(
            RuleId: ruleId,
            NormalizedText: normalizedText,
            MagicScore: Math.Round(magicScore, 4),
            OccurrenceCount: occurrenceCount,
            TopFilePath: top.FilePath,
            TopLine: top.Line,
            TopColumn: top.Column,
            Severity: FindingSeverity.Info,
            Confidence: comparisonCount > 0 ? FindingConfidence.High : FindingConfidence.Medium,
            ContextSummary: contextSummary,
            Metadata: metadata,
            Occurrences: sortedOccurrences);
    }

    private static IReadOnlyList<MagicStringCandidate> ApplyLimits(IReadOnlyList<MagicStringCandidate> candidates, MagicStringsAnalysisOptions options)
    {
        var perDirectoryCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var selected = new List<MagicStringCandidate>();

        foreach (var candidate in candidates
                     .OrderByDescending(c => c.MagicScore)
                     .ThenByDescending(c => c.OccurrenceCount)
                     .ThenBy(c => c.NormalizedText, StringComparer.Ordinal))
        {
            if (selected.Count >= options.MaxFindingsTotal)
            {
                break;
            }

            var directory = Path.GetDirectoryName(candidate.TopFilePath)?.Replace('\\', '/') ?? ".";
            var current = perDirectoryCount.GetValueOrDefault(directory);
            if (current >= options.MaxFindingsPerDirectory)
            {
                continue;
            }

            selected.Add(candidate);
            perDirectoryCount[directory] = current + 1;
        }

        return selected;
    }

    private static bool IsComparisonSyntax(SyntaxNode node)
    {
        return node switch
        {
            BinaryExpressionSyntax binary => binary.IsKind(SyntaxKind.EqualsExpression) || binary.IsKind(SyntaxKind.NotEqualsExpression),
            CaseSwitchLabelSyntax => true,
            SwitchExpressionArmSyntax => true,
            ArgumentSyntax argument when argument.Parent?.Parent is InvocationExpressionSyntax invocation =>
                invocation.Expression.ToString().Contains("ContainsKey", StringComparison.OrdinalIgnoreCase) ||
                invocation.Expression.ToString().Contains("TryGetValue", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool IsConditionalSyntax(SyntaxNode node)
    {
        return node is IfStatementSyntax or ElseClauseSyntax or ConditionalExpressionSyntax or WhileStatementSyntax ||
               node is ForStatementSyntax;
    }

    private static bool IsExceptionSyntax(SyntaxNode node)
    {
        if (node is ThrowStatementSyntax or ThrowExpressionSyntax)
        {
            return true;
        }

        if (node is ObjectCreationExpressionSyntax objectCreation)
        {
            return objectCreation.Type.ToString().EndsWith("Exception", StringComparison.Ordinal);
        }

        return false;
    }

    private static bool IsLoggingCallsite(string? language, string? callsite, string containingLine, MagicStringsAnalysisOptions options)
    {
        var sinks = ResolveSinks(language, options);
        foreach (var sink in sinks)
        {
            if (!string.IsNullOrWhiteSpace(callsite) &&
                callsite.Contains(sink, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (containingLine.Contains(sink, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<string> ResolveSinks(string? language, MagicStringsAnalysisOptions options)
    {
        if (!string.IsNullOrWhiteSpace(language) &&
            options.LoggingSinks.TryGetValue(language, out var configured) &&
            configured.Count > 0)
        {
            return configured;
        }

        if (!string.IsNullOrWhiteSpace(language) &&
            DefaultLoggingSinks.TryGetValue(language, out var defaults) &&
            defaults.Count > 0)
        {
            return defaults;
        }

        return [];
    }

    private static string? DetectLineCallsite(string? language, string line)
    {
        if (string.IsNullOrWhiteSpace(language) ||
            !CallsiteTokens.TryGetValue(language, out var tokens))
        {
            return null;
        }

        return tokens.FirstOrDefault(token => line.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeLiteral(string raw)
    {
        var normalized = raw.Replace("\r", "", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();
        normalized = Regex.Replace(normalized, "\\s+", " ");
        return normalized;
    }

    private static bool IsTestCode(string filePath)
    {
        var normalized = filePath.Replace('\\', '/');
        return normalized.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(".tests.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesAnyWildcard(string value, IReadOnlyList<string> patterns)
    {
        foreach (var pattern in patterns)
        {
            var escaped = Regex.Escape(pattern)
                .Replace("\\*", ".*", StringComparison.Ordinal)
                .Replace("\\?", ".", StringComparison.Ordinal);
            if (Regex.IsMatch(value, "^" + escaped + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                return true;
            }
        }

        return false;
    }

    private static CommandAst? FindParentCommand(Ast ast)
    {
        var current = ast.Parent;
        while (current is not null)
        {
            if (current is CommandAst command)
            {
                return command;
            }

            current = current.Parent;
        }

        return null;
    }

    private static IEnumerable<Ast> GetAstAncestors(Ast ast)
    {
        var current = ast.Parent;
        while (current is not null)
        {
            yield return current;
            current = current.Parent;
        }
    }

    private static string BuildContextSummary(IReadOnlyList<MagicStringOccurrence> occurrences)
    {
        var languages = occurrences.Select(o => o.Language).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v).ToList();
        var contexts = occurrences.Select(o => o.ParentNodeType).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.Ordinal).Take(5).ToList();
        return $"languages={string.Join(',', languages)};contexts={string.Join(',', contexts)}";
    }

    private static string BuildMetadata(
        IReadOnlyList<MagicStringOccurrence> occurrences,
        string contextSummary,
        double frequencyScore,
        double usageBoost,
        double penalty,
        double magicScore)
    {
        var payload = new
        {
            strategy = "exclude-detect-score-threshold",
            contextSummary,
            scoring = new
            {
                frequencyScore = Math.Round(frequencyScore, 4),
                usageBoost = Math.Round(usageBoost, 4),
                penalties = Math.Round(penalty, 4),
                magicScore = Math.Round(magicScore, 4)
            },
            topLocations = occurrences
                .OrderByDescending(o => o.IsComparisonUsage)
                .ThenBy(o => o.FilePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(o => o.Line)
                .Take(5)
                .Select(o => new { file = o.FilePath, line = o.Line, column = o.Column })
                .ToList(),
            allOccurrences = occurrences.Select(o => new
            {
                file = o.FilePath,
                line = o.Line,
                column = o.Column,
                language = o.Language,
                astParent = o.ParentNodeType,
                callsite = o.CallsiteSymbol,
                comparison = o.IsComparisonUsage,
                conditional = o.IsConditionalUsage,
                exception = o.IsExceptionMessage,
                astConfirmed = o.IsAstConfirmed,
                testCode = o.IsTestCode,
                raw = o.RawText
            }).ToList()
        };

        return JsonSerializer.Serialize(payload);
    }

    public static string CreateFingerprint(string ruleId, string normalizedText, int occurrenceCount)
    {
        var raw = $"{ruleId}|{normalizedText}|{occurrenceCount}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash);
    }
}

public static class MagicStringHeuristics
{
    public static bool IsNaturalLanguage(string value, IReadOnlySet<string>? stopWords = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var words = Regex.Matches(value, "[A-Za-z]{2,}")
            .Select(match => match.Value.ToLowerInvariant())
            .ToList();

        if (words.Count < 3)
        {
            return false;
        }

        var punctuationCount = value.Count(ch => ch is '.' or ',' or ';' or ':' or '!' or '?');
        var stopWordSet = stopWords ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "the", "a", "an", "and", "or", "is", "are", "to", "for", "of", "in", "on", "this", "that", "with", "from", "at", "by"
        };

        var stopwordRatio = words.Count(word => stopWordSet.Contains(word)) / (double)words.Count;
        return punctuationCount >= 1 && stopwordRatio >= 0.35;
    }

    public static double ShannonEntropy(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return 0d;
        }

        var frequencies = new Dictionary<char, int>();
        foreach (var ch in value)
        {
            frequencies[ch] = frequencies.GetValueOrDefault(ch) + 1;
        }

        var entropy = 0d;
        var length = value.Length;
        foreach (var count in frequencies.Values)
        {
            var probability = count / (double)length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}

public sealed record MagicStringFileInput(
    string FilePath,
    string Content,
    FileCategory Category,
    string? Language);

public sealed record MagicStringsAnalysisOptions(
    int MinOccurrences,
    int MaxFindingsPerDirectory,
    int MaxFindingsTotal,
    double EntropyThreshold,
    IReadOnlyList<string> AllowlistPatterns,
    IReadOnlyList<string> DenylistPatterns,
    IReadOnlyDictionary<string, IReadOnlyList<string>> LoggingSinks)
{
    public static MagicStringsAnalysisOptions CreateDefault() => new(
        MinOccurrences: 2,
        MaxFindingsPerDirectory: 50,
        MaxFindingsTotal: 500,
        EntropyThreshold: 4.2,
        AllowlistPatterns: [],
        DenylistPatterns: [],
        LoggingSinks: new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase));
}

public sealed record MagicStringOccurrence(
    string RawText,
    string NormalizedText,
    string FilePath,
    int Line,
    int Column,
    string Language,
    string ParentNodeType,
    string? CallsiteSymbol,
    bool IsComparisonUsage,
    bool IsConditionalUsage,
    bool IsExceptionMessage,
    bool IsTestCode,
    bool IsAstConfirmed,
    string? FilterReason);

public sealed record MagicStringCandidate(
    string RuleId,
    string NormalizedText,
    double MagicScore,
    int OccurrenceCount,
    string TopFilePath,
    int TopLine,
    int TopColumn,
    FindingSeverity Severity,
    FindingConfidence Confidence,
    string ContextSummary,
    string Metadata,
    IReadOnlyList<MagicStringOccurrence> Occurrences);
