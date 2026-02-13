using System.Management.Automation.Language;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Analyzers.PowerShell;

public sealed class PowerShellPortabilityAnalyzer : IAnalyzer
{
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

                findings.Add(new Finding
                {
                    RuleId = ruleId,
                    FilePath = context.FilePath,
                    Line = line,
                    Column = column,
                    Message = $"Hardcoded portability-sensitive value passed to PowerShell cmdlet '{commandName}'.",
                    Snippet = PortabilityPatternMatcher.GetSnippet(context.Content, line),
                    Severity = rule.DefaultSeverity,
                    Confidence = FindingConfidence.High,
                    Fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, line, column, value),
                    Metadata = BuildMetadata(commandName)
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
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
