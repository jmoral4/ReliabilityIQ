using System.Management.Automation.Language;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Analyzers.PowerShell;

public sealed class PowerShellPortabilityAnalyzer : IAnalyzer
{
    private static readonly Regex InlineSuppressionRegex = new(
        @"reliabilityiq:\s*ignore\s+(?<rule>[a-z0-9\.-]+)(?:\s+reason=(?<reason>.*))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly HashSet<string> TargetCmdlets = new(StringComparer.OrdinalIgnoreCase)
    {
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "New-Object",
        "Set-Content",
        "Out-File"
    };

    public string Name => "Portability.PowerShell.Ast";

    public string Version => "3.0.0";

    public IReadOnlyCollection<FileCategory> SupportedFileCategories { get; } =
    [
        FileCategory.Source
    ];

    public Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default)
    {
        if (context.FileCategory != FileCategory.Source ||
            !string.Equals(context.Language, "powershell", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<IEnumerable<Finding>>([]);
        }

        var ast = Parser.ParseInput(context.Content, out _, out _);
        var findings = new List<Finding>();
        var lines = context.Content.Split('\n');
        var inlineSuppressions = ParseInlineSuppressions(lines);
        var fileSuppressions = FileSuppressionSet.Load(context);
        var isTestCode = IsTestCode(context.FilePath);

        var candidates = ast.FindAll(node => node is StringConstantExpressionAst or ExpandableStringExpressionAst, searchNestedScriptBlocks: true);
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var command = FindParentCommand(candidate);
            if (command is null)
            {
                continue;
            }

            var commandName = command.GetCommandName() ?? string.Empty;
            if (!TargetCmdlets.Contains(commandName))
            {
                continue;
            }

            if (commandName.Equals("New-Object", StringComparison.OrdinalIgnoreCase) &&
                !command.Extent.Text.Contains("System.Uri", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = candidate switch
            {
                StringConstantExpressionAst constant => constant.Value,
                ExpandableStringExpressionAst expandable => expandable.Value,
                _ => string.Empty
            };

            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var ruleIds = PortabilityPatternMatcher.MatchRuleIds(value);
            if (ruleIds.Count == 0)
            {
                continue;
            }

            var line = candidate.Extent.StartLineNumber;
            var column = candidate.Extent.StartColumnNumber;

            foreach (var ruleId in ruleIds)
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

                findings.Add(new Finding
                {
                    RuleId = ruleId,
                    FilePath = context.FilePath,
                    Line = line,
                    Column = column,
                    Message = $"Hardcoded portability-sensitive value passed to PowerShell cmdlet '{commandName}'.",
                    Snippet = PortabilityPatternMatcher.GetSnippet(context.Content, line),
                    Severity = isTestCode ? FindingSeverity.Info : rule.DefaultSeverity,
                    Confidence = FindingConfidence.High,
                    Fingerprint = fingerprint,
                    Metadata = BuildMetadata(commandName)
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
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
            if (ruleId.Length == 0)
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

    private static bool IsTestCode(string filePath)
    {
        var normalized = filePath.Replace('\\', '/');
        return normalized.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(".tests.", StringComparison.OrdinalIgnoreCase);
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

    private static string BuildMetadata(string commandName)
    {
        return $$"""{"engine":"powershell-ast","astConfirmed":true,"callsite":"{{Escape(commandName)}}"}""";
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
