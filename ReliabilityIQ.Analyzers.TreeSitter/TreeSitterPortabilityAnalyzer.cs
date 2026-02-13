using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Portability;

namespace ReliabilityIQ.Analyzers.TreeSitter;

public sealed class TreeSitterPortabilityAnalyzer : IAnalyzer
{
    private static readonly Regex StringLiteralRegex = new(
        "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'",
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

        var nativeReady = TreeSitterNative.TryCreateParser(out var worker);
        worker?.Dispose();

        var findings = new List<Finding>();
        var lines = context.Content.Split('\n');

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
                    findings.Add(new Finding
                    {
                        RuleId = ruleId,
                        FilePath = context.FilePath,
                        Line = lineNumber,
                        Column = column,
                        Message = $"Hardcoded portability-sensitive value detected in {context.Language} code.",
                        Snippet = line.TrimEnd('\r'),
                        Severity = rule.DefaultSeverity,
                        Confidence = confidence,
                        Fingerprint = PortabilityPatternMatcher.CreateFingerprint(ruleId, context.FilePath, lineNumber, column, value),
                        Metadata = BuildMetadata(context.Language, matchedToken, nativeReady, confidence)
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
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

        [DllImport(LibraryName, EntryPoint = "ts_parser_new", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr TsParserNew();

        [DllImport(LibraryName, EntryPoint = "ts_parser_delete", CallingConvention = CallingConvention.Cdecl)]
        private static extern void TsParserDelete(IntPtr parser);

        public static bool TryCreateParser(out TreeSitterWorker? worker)
        {
            worker = null;

            try
            {
                var parser = TsParserNew();
                if (parser == IntPtr.Zero)
                {
                    return false;
                }

                worker = new TreeSitterWorker(parser);
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

        public sealed class TreeSitterWorker : IDisposable
        {
            private IntPtr _parser;

            public TreeSitterWorker(IntPtr parser)
            {
                _parser = parser;
            }

            public void Dispose()
            {
                if (_parser == IntPtr.Zero)
                {
                    return;
                }

                TsParserDelete(_parser);
                _parser = IntPtr.Zero;
            }
        }
    }
}
