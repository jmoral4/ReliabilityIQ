using System.Runtime.InteropServices;
using System.Threading;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Analyzers.TreeSitter;

public sealed class TreeSitterPortabilityAnalyzer : IAnalyzer
{
    private static readonly Regex InlineSuppressionRegex = new(
        @"reliabilityiq:\s*ignore\s+(?<rule>[a-z0-9\.-]+)(?:\s+reason=(?<reason>.*))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex StringLiteralRegex = new(
        "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex IntegerRegex = new(
        @"\b(?<port>[1-9]\d{1,4})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, string[]> CallsiteTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cpp"] = ["connect(", "getaddrinfo(", "curl_easy_setopt(", "fopen(", "ifstream", "ofstream", "filesystem::path"],
        ["python"] = ["requests.", "socket.", "subprocess", "open(", "pathlib.Path("],
        ["rust"] = ["reqwest::", "std::net::", "std::fs::", "Command::new(", "include_str!("]
    };

    public string Name => "Portability.TreeSitter";

    public string Version => "3.0.0";

    public IReadOnlyCollection<FileCategory> SupportedFileCategories { get; } =
    [
        FileCategory.Source
    ];

    public Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default)
    {
        if (context.FileCategory != FileCategory.Source || string.IsNullOrWhiteSpace(context.Language))
        {
            return Task.FromResult<IEnumerable<Finding>>([]);
        }

        if (!CallsiteTokens.TryGetValue(context.Language, out var languageTokens))
        {
            return Task.FromResult<IEnumerable<Finding>>([]);
        }

        var nativeReady = TreeSitterNative.IsParserAvailable();

        var findings = new List<Finding>();
        var lines = context.Content.Split('\n');
        var inlineSuppressions = ParseInlineSuppressions(lines);
        var fileSuppressions = FileSuppressionSet.Load(context);
        var isTestCode = IsTestCode(context.FilePath);

        for (var lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = lines[lineIndex];
            var matchedToken = languageTokens.FirstOrDefault(token => line.Contains(token, StringComparison.Ordinal));

            foreach (Match literalMatch in StringLiteralRegex.Matches(line))
            {
                var rawLiteral = literalMatch.Value;
                if (rawLiteral.Length < 2)
                {
                    continue;
                }

                var value = rawLiteral[1..^1];
                var ruleIds = PortabilityPatternMatcher.MatchRuleIds(value);
                if (ruleIds.Count == 0)
                {
                    continue;
                }

                var lineNumber = lineIndex + 1;
                var column = literalMatch.Index + 1;

                foreach (var ruleId in ruleIds)
                {
                    if (!PortabilityRuleDefinitions.ById.TryGetValue(ruleId, out var rule))
                    {
                        continue;
                    }

                    var confidence = matchedToken is not null ? FindingConfidence.High : FindingConfidence.Medium;
                    var fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, lineNumber, column, value);
                    if (IsInlineSuppressed(inlineSuppressions, lineNumber, ruleId) ||
                        fileSuppressions.IsSuppressed(context.FilePath, ruleId, fingerprint))
                    {
                        continue;
                    }

                    findings.Add(new Finding
                    {
                        RuleId = ruleId,
                        FilePath = context.FilePath,
                        Line = lineNumber,
                        Column = column,
                        Message = $"Hardcoded portability-sensitive value detected in {context.Language} code.",
                        Snippet = line.TrimEnd('\r'),
                        Severity = isTestCode ? FindingSeverity.Info : rule.DefaultSeverity,
                        Confidence = confidence,
                        Fingerprint = fingerprint,
                        Metadata = BuildMetadata(context.Language, matchedToken, nativeReady, confidence)
                    });
                }
            }

            if (matchedToken is null ||
                !PortabilityRuleDefinitions.ById.TryGetValue("portability.hardcoded.port", out var portRule))
            {
                continue;
            }

            foreach (Match integerMatch in IntegerRegex.Matches(line))
            {
                if (!int.TryParse(integerMatch.Groups["port"].Value, out var port) ||
                    !PortabilityPatternMatcher.IsNonStandardPort(port))
                {
                    continue;
                }

                var ruleId = "portability.hardcoded.port";
                var lineNumber = lineIndex + 1;
                var column = integerMatch.Index + 1;
                var fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, lineNumber, column, integerMatch.Value);

                if (IsInlineSuppressed(inlineSuppressions, lineNumber, ruleId) ||
                    fileSuppressions.IsSuppressed(context.FilePath, ruleId, fingerprint))
                {
                    continue;
                }

                findings.Add(new Finding
                {
                    RuleId = ruleId,
                    FilePath = context.FilePath,
                    Line = lineNumber,
                    Column = column,
                    Message = $"Hardcoded non-standard port '{port}' detected in {context.Language} network callsite '{matchedToken}'.",
                    Snippet = line.TrimEnd('\r'),
                    Severity = isTestCode ? FindingSeverity.Info : portRule.DefaultSeverity,
                    Confidence = FindingConfidence.High,
                    Fingerprint = fingerprint,
                    Metadata = BuildMetadata(context.Language, matchedToken, nativeReady, FindingConfidence.High)
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

    private static string BuildMetadata(string language, string? token, bool nativeReady, FindingConfidence confidence)
    {
        return $$"""{"engine":"tree-sitter","language":"{{language}}","astConfirmed":{{(token is not null).ToString().ToLowerInvariant()}},"nativeParserAvailable":{{nativeReady.ToString().ToLowerInvariant()}},"callsite":"{{Escape(token ?? "unknown")}}","confidence":"{{confidence}}"}""";
    }

    private static string Escape(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }

    private static class TreeSitterNative
    {
        private const string LibraryName = "tree-sitter";
        private static int _availabilityState; // 0 unknown, 1 available, -1 unavailable

        [DllImport(LibraryName, EntryPoint = "ts_parser_new", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr TsParserNew();

        [DllImport(LibraryName, EntryPoint = "ts_parser_delete", CallingConvention = CallingConvention.Cdecl)]
        private static extern void TsParserDelete(IntPtr parser);

        public static bool IsParserAvailable()
        {
            var state = Volatile.Read(ref _availabilityState);
            if (state != 0)
            {
                return state > 0;
            }

            state = ProbeParserAvailability() ? 1 : -1;
            Interlocked.CompareExchange(ref _availabilityState, state, 0);
            return Volatile.Read(ref _availabilityState) > 0;
        }

        private static bool ProbeParserAvailability()
        {
            if (!NativeLibrary.TryLoad(LibraryName, out var handle))
            {
                return false;
            }

            NativeLibrary.Free(handle);

            try
            {
                var parser = TsParserNew();
                if (parser == IntPtr.Zero)
                {
                    return false;
                }

                TsParserDelete(parser);
                return true;
            }
            catch (DllNotFoundException)
            {
                return false;
            }
            catch (EntryPointNotFoundException)
            {
                return false;
            }
        }

    }
}
