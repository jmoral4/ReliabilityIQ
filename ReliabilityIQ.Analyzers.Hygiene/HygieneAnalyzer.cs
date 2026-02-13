using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Hygiene;

namespace ReliabilityIQ.Analyzers.Hygiene;

public sealed record HygieneFileInput(string FilePath, string Content, string? Language);

public sealed class HygieneAnalyzer
{
    private static readonly Regex FeatureMacroRegex = new(
        @"^\s*#if\s+FEATURE_(?<flag>[A-Z0-9_]+)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex FeatureDefinitionMacroRegex = new(
        @"^\s*#define\s+FEATURE_(?<flag>[A-Z0-9_]+)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CSharpAsyncVoidRegex = new(
        @"\basync\s+void\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?<params>[^)]*)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CSharpAsyncMethodRegex = new(
        @"\basync\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CSharpWaitRegex = new(
        @"(?:\.\s*Result\b|\.\s*Wait\s*\(|GetAwaiter\s*\(\s*\)\s*\.\s*GetResult\s*\()",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CSharpLockBadTargetRegex = new(
        @"\block\s*\(\s*(this|typeof\s*\([^)]*\)|""[^""]*"")\s*\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PythonAsyncDefRegex = new(
        @"^\s*async\s+def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PythonAsyncioRunRegex = new(
        @"\basyncio\.run\s*\(",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex RustAsyncFnRegex = new(
        @"\basync\s+fn\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex RustBlockOnRegex = new(
        @"\bblock_on\s*\(",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex DefaultFeatureStringDefinitionRegex = new(
        @"\b(?:const|readonly|static\s+readonly)\s+string\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[""'](?<flag>[^""']+)[""']",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex DefaultFeatureConfigDefinitionRegex = new(
        @"[""'](?<flag>[^""']+)[""']\s*:\s*(?:true|false)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex CCommentTokenRegex = new(
        @"//|/\*|\*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex HashCommentTokenRegex = new(
        @"#",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public IReadOnlyList<Finding> AnalyzeRepository(
        string repoRoot,
        IReadOnlyList<HygieneFileInput> files,
        IReadOnlyDictionary<string, string>? settings = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repoRoot);
        ArgumentNullException.ThrowIfNull(files);

        var options = BuildOptions(settings);
        var now = DateTimeOffset.UtcNow;
        var findings = new List<Finding>();
        var featureOccurrences = new List<FeatureOccurrence>();
        var todoOccurrences = new List<TodoOccurrence>();
        var blameProvider = new GitBlameProvider(repoRoot);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeFile(
                file,
                options,
                featureOccurrences,
                todoOccurrences,
                findings,
                cancellationToken);
        }

        var featureByFile = featureOccurrences
            .GroupBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        var todoByFile = todoOccurrences
            .GroupBy(t => t.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var file in featureByFile.Keys.Concat(todoByFile.Keys).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!blameProvider.TryGetLineInfo(file, out var blameByLine))
            {
                continue;
            }

            if (featureByFile.TryGetValue(file, out var featureItems))
            {
                foreach (var item in featureItems)
                {
                    if (blameByLine.TryGetValue(item.Line, out var blame))
                    {
                        item.Author = blame.Author;
                        item.AuthorTime = blame.AuthorTime;
                    }
                }
            }

            if (todoByFile.TryGetValue(file, out var todoItems))
            {
                foreach (var item in todoItems)
                {
                    if (blameByLine.TryGetValue(item.Line, out var blame))
                    {
                        item.Author = blame.Author;
                        item.AuthorTime = blame.AuthorTime;
                    }
                }
            }
        }

        findings.AddRange(AnalyzeFeatureFlags(featureOccurrences, options, now));
        findings.AddRange(AnalyzeTodoDebt(todoOccurrences, options, now));

        return findings
            .OrderBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Line)
            .ThenBy(f => f.Column)
            .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void AnalyzeFile(
        HygieneFileInput file,
        HygieneOptions options,
        ICollection<FeatureOccurrence> featureOccurrences,
        ICollection<TodoOccurrence> todoOccurrences,
        ICollection<Finding> findings,
        CancellationToken cancellationToken)
    {
        var lines = SplitLines(file.Content);
        var language = (file.Language ?? string.Empty).Trim().ToLowerInvariant();

        AnalyzeFeatureFlagOccurrences(file.FilePath, lines, options, featureOccurrences);
        AnalyzeTodoComments(file.FilePath, lines, language, options, todoOccurrences);

        if (language == "csharp" || file.FilePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            AnalyzeCSharpAsyncAndThread(file.FilePath, lines, findings, cancellationToken);
            return;
        }

        if (language == "python" || file.FilePath.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
        {
            AnalyzePythonAsync(file.FilePath, lines, findings, cancellationToken);
            return;
        }

        if (language == "rust" || file.FilePath.EndsWith(".rs", StringComparison.OrdinalIgnoreCase))
        {
            AnalyzeRustAsync(file.FilePath, lines, findings, cancellationToken);
        }
    }

    private static void AnalyzeFeatureFlagOccurrences(
        string filePath,
        IReadOnlyList<string> lines,
        HygieneOptions options,
        ICollection<FeatureOccurrence> featureOccurrences)
    {
        for (var i = 0; i < lines.Count; i++)
        {
            var lineNumber = i + 1;
            var line = lines[i];

            foreach (var regex in options.FeatureReferencePatterns)
            {
                var match = regex.Match(line);
                if (!match.Success)
                {
                    continue;
                }

                var flag = ReadFlag(match);
                if (string.IsNullOrWhiteSpace(flag))
                {
                    continue;
                }

                featureOccurrences.Add(new FeatureOccurrence(filePath, lineNumber, flag, isDefinition: false, line.Trim()));
            }

            if (FeatureMacroRegex.IsMatch(line))
            {
                var macroMatch = FeatureMacroRegex.Match(line);
                var flag = ReadFlag(macroMatch);
                if (!string.IsNullOrWhiteSpace(flag))
                {
                    featureOccurrences.Add(new FeatureOccurrence(filePath, lineNumber, flag, isDefinition: false, line.Trim()));
                }
            }

            foreach (var regex in options.FeatureDefinitionPatterns)
            {
                var match = regex.Match(line);
                if (!match.Success)
                {
                    continue;
                }

                var flag = ReadFlag(match);
                if (string.IsNullOrWhiteSpace(flag))
                {
                    continue;
                }

                featureOccurrences.Add(new FeatureOccurrence(filePath, lineNumber, flag, isDefinition: true, line.Trim()));
            }

            if (FeatureDefinitionMacroRegex.IsMatch(line))
            {
                var macroMatch = FeatureDefinitionMacroRegex.Match(line);
                var flag = ReadFlag(macroMatch);
                if (!string.IsNullOrWhiteSpace(flag))
                {
                    featureOccurrences.Add(new FeatureOccurrence(filePath, lineNumber, flag, isDefinition: true, line.Trim()));
                }
            }
        }
    }

    private static void AnalyzeTodoComments(
        string filePath,
        IReadOnlyList<string> lines,
        string language,
        HygieneOptions options,
        ICollection<TodoOccurrence> todoOccurrences)
    {
        var keywordPattern = BuildKeywordRegex(options.TodoKeywords);
        if (keywordPattern is null)
        {
            return;
        }

        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (!TryExtractCommentSegment(line, language, out var comment))
            {
                continue;
            }

            var match = keywordPattern.Match(comment);
            if (!match.Success)
            {
                continue;
            }

            var keyword = match.Groups["kw"].Value.ToUpperInvariant();
            var lineNumber = i + 1;
            todoOccurrences.Add(new TodoOccurrence(filePath, lineNumber, keyword, comment.Trim()));
        }
    }

    private static void AnalyzeCSharpAsyncAndThread(
        string filePath,
        IReadOnlyList<string> lines,
        ICollection<Finding> findings,
        CancellationToken cancellationToken)
    {
        var braceDepth = 0;
        var asyncMethodDepths = new Stack<int>();
        var pendingAsyncMethod = false;

        for (var i = 0; i < lines.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = lines[i];
            var lineNumber = i + 1;
            var trimmed = line.Trim();

            var asyncVoidMatch = CSharpAsyncVoidRegex.Match(line);
            if (asyncVoidMatch.Success && !LooksLikeEventHandler(asyncVoidMatch.Groups["params"].Value))
            {
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.AsyncVoidRuleId,
                    filePath,
                    lineNumber,
                    "async void method detected outside of event-handler signature.",
                    FindingConfidence.High,
                    new
                    {
                        engine = "hygiene",
                        language = "csharp",
                        method = asyncVoidMatch.Groups["name"].Value
                    }));
            }

            var isAsyncSignature = CSharpAsyncMethodRegex.IsMatch(line) && line.Contains('(');
            if (isAsyncSignature && line.Contains('{'))
            {
                pendingAsyncMethod = false;
                asyncMethodDepths.Push(braceDepth + 1);
            }
            else if (isAsyncSignature)
            {
                pendingAsyncMethod = true;
            }
            else if (pendingAsyncMethod && line.Contains('{'))
            {
                pendingAsyncMethod = false;
                asyncMethodDepths.Push(braceDepth + 1);
            }

            if (asyncMethodDepths.Count > 0 && CSharpWaitRegex.IsMatch(line))
            {
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.SyncOverAsyncRuleId,
                    filePath,
                    lineNumber,
                    "Sync-over-async call detected inside an async C# method.",
                    FindingConfidence.Medium,
                    new
                    {
                        engine = "hygiene",
                        language = "csharp",
                        pattern = "sync-over-async"
                    }));
            }

            var lockMatch = CSharpLockBadTargetRegex.Match(trimmed);
            if (lockMatch.Success)
            {
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.BadLockTargetRuleId,
                    filePath,
                    lineNumber,
                    "Unsafe lock target detected. Avoid locking on this, typeof(...), or string literals.",
                    FindingConfidence.High,
                    new
                    {
                        engine = "hygiene",
                        language = "csharp",
                        target = lockMatch.Groups[1].Value
                    }));
            }

            braceDepth += CountChar(line, '{');
            braceDepth -= CountChar(line, '}');
            if (braceDepth < 0)
            {
                braceDepth = 0;
            }

            while (asyncMethodDepths.Count > 0 && braceDepth < asyncMethodDepths.Peek())
            {
                asyncMethodDepths.Pop();
            }
        }
    }

    private static void AnalyzePythonAsync(
        string filePath,
        IReadOnlyList<string> lines,
        ICollection<Finding> findings,
        CancellationToken cancellationToken)
    {
        var asyncDefIndentStack = new Stack<int>();

        for (var i = 0; i < lines.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = lines[i];
            var lineNumber = i + 1;
            var indent = CountIndent(line);
            var trimmed = line.Trim();

            if (trimmed.Length > 0 && !trimmed.StartsWith("#", StringComparison.Ordinal))
            {
                while (asyncDefIndentStack.Count > 0 && indent <= asyncDefIndentStack.Peek())
                {
                    asyncDefIndentStack.Pop();
                }
            }

            if (PythonAsyncDefRegex.IsMatch(line))
            {
                asyncDefIndentStack.Push(indent);
                continue;
            }

            if (asyncDefIndentStack.Count > 0 && PythonAsyncioRunRegex.IsMatch(line))
            {
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.NestedRuntimeRuleId,
                    filePath,
                    lineNumber,
                    "asyncio.run() detected inside an async Python function.",
                    FindingConfidence.High,
                    new
                    {
                        engine = "hygiene",
                        language = "python",
                        pattern = "asyncio.run-in-async-def"
                    }));
            }
        }
    }

    private static void AnalyzeRustAsync(
        string filePath,
        IReadOnlyList<string> lines,
        ICollection<Finding> findings,
        CancellationToken cancellationToken)
    {
        var braceDepth = 0;
        var asyncFnDepths = new Stack<int>();
        var pendingAsyncFn = false;

        for (var i = 0; i < lines.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = lines[i];
            var lineNumber = i + 1;
            var trimmed = line.Trim();

            var isAsyncFn = RustAsyncFnRegex.IsMatch(line);
            if (isAsyncFn && line.Contains('{'))
            {
                pendingAsyncFn = false;
                asyncFnDepths.Push(braceDepth + 1);
            }
            else if (isAsyncFn)
            {
                pendingAsyncFn = true;
            }
            else if (pendingAsyncFn && line.Contains('{'))
            {
                pendingAsyncFn = false;
                asyncFnDepths.Push(braceDepth + 1);
            }

            if (asyncFnDepths.Count > 0 && RustBlockOnRegex.IsMatch(trimmed))
            {
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.NestedRuntimeRuleId,
                    filePath,
                    lineNumber,
                    "block_on() detected inside an async Rust function.",
                    FindingConfidence.High,
                    new
                    {
                        engine = "hygiene",
                        language = "rust",
                        pattern = "block_on-in-async-fn"
                    }));
            }

            braceDepth += CountChar(line, '{');
            braceDepth -= CountChar(line, '}');
            if (braceDepth < 0)
            {
                braceDepth = 0;
            }

            while (asyncFnDepths.Count > 0 && braceDepth < asyncFnDepths.Peek())
            {
                asyncFnDepths.Pop();
            }
        }
    }

    private static IReadOnlyList<Finding> AnalyzeFeatureFlags(
        IReadOnlyList<FeatureOccurrence> occurrences,
        HygieneOptions options,
        DateTimeOffset now)
    {
        var findings = new List<Finding>();
        foreach (var group in occurrences.GroupBy(o => NormalizeFlagName(o.Flag), StringComparer.OrdinalIgnoreCase))
        {
            var flag = group.Key;
            var references = group.Where(o => !o.IsDefinition).ToList();
            var definitions = group.Where(o => o.IsDefinition).ToList();
            if (references.Count == 0 && definitions.Count == 0)
            {
                continue;
            }

            var withAge = group
                .Where(o => o.AuthorTime.HasValue)
                .Select(o => (Occurrence: o, AgeDays: (now - o.AuthorTime!.Value).TotalDays))
                .ToList();

            var oldestAgeDays = withAge.Count > 0 ? withAge.Max(x => x.AgeDays) : (double?)null;
            var newestAgeDays = withAge.Count > 0 ? withAge.Min(x => x.AgeDays) : (double?)null;

            if (references.Count > 0 &&
                oldestAgeDays.HasValue &&
                newestAgeDays.HasValue &&
                oldestAgeDays.Value >= options.FeatureFlagStaleDays &&
                newestAgeDays.Value >= options.FeatureFlagRecentChangeDays)
            {
                var anchor = references[0];
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.StaleFeatureFlagRuleId,
                    anchor.FilePath,
                    anchor.Line,
                    $"Feature flag '{flag}' appears stale ({references.Count} reference(s), last changed ~{Math.Round(newestAgeDays.Value)} days ago).",
                    withAge.Count > 0 ? FindingConfidence.High : FindingConfidence.Medium,
                    new
                    {
                        engine = "hygiene",
                        category = "feature-flag",
                        flagName = flag,
                        referenceCount = references.Count,
                        definitionCount = definitions.Count,
                        introducedDaysAgo = oldestAgeDays.HasValue ? (double?)Math.Round(oldestAgeDays.Value) : null,
                        lastChangedDaysAgo = newestAgeDays.HasValue ? (double?)Math.Round(newestAgeDays.Value) : null,
                        locations = references.Take(10).Select(r => new { r.FilePath, r.Line }).ToList()
                    }));
            }

            if (definitions.Count > 0 && references.Count == 0)
            {
                var anchor = definitions[0];
                findings.Add(CreateFinding(
                    HygieneRuleDefinitions.DeadFeatureFlagRuleId,
                    anchor.FilePath,
                    anchor.Line,
                    $"Feature flag '{flag}' appears dead (definition found, no runtime references detected).",
                    FindingConfidence.Medium,
                    new
                    {
                        engine = "hygiene",
                        category = "feature-flag",
                        flagName = flag,
                        referenceCount = references.Count,
                        definitionCount = definitions.Count,
                        locations = definitions.Take(10).Select(d => new { d.FilePath, d.Line }).ToList()
                    }));
            }
        }

        return findings;
    }

    private static IReadOnlyList<Finding> AnalyzeTodoDebt(
        IReadOnlyList<TodoOccurrence> occurrences,
        HygieneOptions options,
        DateTimeOffset now)
    {
        var findings = new List<Finding>();
        foreach (var occurrence in occurrences)
        {
            var ageDays = occurrence.AuthorTime.HasValue
                ? (int)Math.Round((now - occurrence.AuthorTime.Value).TotalDays)
                : (int?)null;

            var ruleId = occurrence.Keyword switch
            {
                "FIXME" => HygieneRuleDefinitions.FixmeRuleId,
                "HACK" or "WORKAROUND" or "TEMP" => HygieneRuleDefinitions.HackRuleId,
                _ when ageDays.HasValue && ageDays.Value >= options.TodoOldDays => HygieneRuleDefinitions.TodoOldRuleId,
                _ => null
            };

            if (ruleId is null)
            {
                continue;
            }

            var ageSuffix = ageDays.HasValue ? $" (age ~{ageDays.Value} days)" : string.Empty;
            findings.Add(CreateFinding(
                ruleId,
                occurrence.FilePath,
                occurrence.Line,
                $"{occurrence.Keyword} comment indicates tech debt{ageSuffix}.",
                occurrence.AuthorTime.HasValue ? FindingConfidence.High : FindingConfidence.Medium,
                new
                {
                    engine = "hygiene",
                    category = "todo",
                    keyword = occurrence.Keyword,
                    ageDays,
                    author = occurrence.Author
                }));
        }

        return findings;
    }

    private static HygieneOptions BuildOptions(IReadOnlyDictionary<string, string>? settings)
    {
        var featureRefPatterns = CompileRegexList(
            settings,
            "hygiene.featureFlagApiPatterns",
            [
                @"\bIsEnabled\s*\(\s*[""'](?<flag>[^""']+)[""']\s*\)",
                @"\bfeature_flag\s*\[\s*[""'](?<flag>[^""']+)[""']\s*\]",
                @"@feature_flag\s*\(\s*[""'](?<flag>[^""']+)[""']\s*\)"
            ]);

        var featureDefinitionPatterns = CompileRegexList(
            settings,
            "hygiene.featureFlagDefinitionPatterns",
            []);
        if (featureDefinitionPatterns.Count == 0)
        {
            featureDefinitionPatterns =
            [
                DefaultFeatureStringDefinitionRegex,
                DefaultFeatureConfigDefinitionRegex
            ];
        }

        var staleDays = ReadInt(settings, "hygiene.featureFlagStaleDays", 180);
        var recentDays = ReadInt(settings, "hygiene.featureFlagRecentChangeDays", 90);
        var todoOldDays = ReadInt(settings, "hygiene.todoOldDays", 180);
        var todoKeywords = ReadKeywords(settings, "hygiene.todoKeywords", ["TODO", "FIXME", "HACK", "XXX", "WORKAROUND", "TEMP"]);

        return new HygieneOptions(featureRefPatterns, featureDefinitionPatterns, staleDays, recentDays, todoOldDays, todoKeywords);
    }

    private static List<Regex> CompileRegexList(
        IReadOnlyDictionary<string, string>? settings,
        string key,
        IReadOnlyList<string> defaults)
    {
        var patterns = defaults;
        if (settings is not null &&
            settings.TryGetValue(key, out var raw) &&
            !string.IsNullOrWhiteSpace(raw))
        {
            patterns = raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        var compiled = new List<Regex>();
        foreach (var pattern in patterns)
        {
            try
            {
                compiled.Add(new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant));
            }
            catch
            {
                // Keep scanning with valid regexes only.
            }
        }

        return compiled;
    }

    private static int ReadInt(IReadOnlyDictionary<string, string>? settings, string key, int fallback)
    {
        if (settings is null || !settings.TryGetValue(key, out var raw))
        {
            return fallback;
        }

        return int.TryParse(raw, out var parsed) && parsed > 0 ? parsed : fallback;
    }

    private static IReadOnlySet<string> ReadKeywords(
        IReadOnlyDictionary<string, string>? settings,
        string key,
        IReadOnlyCollection<string> fallback)
    {
        if (settings is null || !settings.TryGetValue(key, out var raw) || string.IsNullOrWhiteSpace(raw))
        {
            return new HashSet<string>(fallback, StringComparer.OrdinalIgnoreCase);
        }

        return new HashSet<string>(
            raw.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Trim()),
            StringComparer.OrdinalIgnoreCase);
    }

    private static string[] SplitLines(string content)
    {
        return content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
    }

    private static Regex? BuildKeywordRegex(IReadOnlySet<string> keywords)
    {
        if (keywords.Count == 0)
        {
            return null;
        }

        var escaped = keywords.Select(Regex.Escape);
        var pattern = $@"\b(?<kw>{string.Join("|", escaped)})\b";
        return new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    }

    private static bool TryExtractCommentSegment(string line, string language, out string comment)
    {
        comment = string.Empty;
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        Regex tokenRegex = language switch
        {
            "python" or "yaml" or "yml" => HashCommentTokenRegex,
            _ => CCommentTokenRegex
        };

        var match = tokenRegex.Match(line);
        if (!match.Success)
        {
            if (language == "python")
            {
                var hash = line.IndexOf('#');
                if (hash >= 0)
                {
                    comment = line[hash..];
                    return true;
                }
            }

            return false;
        }

        comment = line[match.Index..];
        return true;
    }

    private static bool LooksLikeEventHandler(string parameters)
    {
        if (string.IsNullOrWhiteSpace(parameters))
        {
            return false;
        }

        var normalized = parameters.Replace(" ", string.Empty, StringComparison.Ordinal);
        return normalized.Contains("objectsender", StringComparison.OrdinalIgnoreCase) &&
               normalized.Contains("EventArgs", StringComparison.OrdinalIgnoreCase);
    }

    private static int CountChar(string text, char target)
    {
        var count = 0;
        foreach (var ch in text)
        {
            if (ch == target)
            {
                count++;
            }
        }

        return count;
    }

    private static int CountIndent(string line)
    {
        var indent = 0;
        foreach (var ch in line)
        {
            if (ch == ' ')
            {
                indent++;
                continue;
            }

            if (ch == '\t')
            {
                indent += 4;
                continue;
            }

            break;
        }

        return indent;
    }

    private static string ReadFlag(Match match)
    {
        var named = match.Groups["flag"];
        if (named.Success)
        {
            return named.Value.Trim();
        }

        if (match.Groups.Count > 1)
        {
            return match.Groups[1].Value.Trim();
        }

        return string.Empty;
    }

    private static string NormalizeFlagName(string raw)
    {
        return raw.Trim().Trim('"', '\'').Replace("__", "_", StringComparison.Ordinal);
    }

    private static Finding CreateFinding(
        string ruleId,
        string filePath,
        int line,
        string message,
        FindingConfidence confidence,
        object metadata)
    {
        return new Finding
        {
            RuleId = ruleId,
            FilePath = filePath,
            Line = Math.Max(1, line),
            Column = 1,
            Message = message,
            Snippet = null,
            Severity = HygieneRuleDefinitions.ById[ruleId].DefaultSeverity,
            Confidence = confidence,
            Fingerprint = CreateFingerprint(ruleId, filePath, line.ToString(), message),
            Metadata = JsonSerializer.Serialize(metadata)
        };
    }

    private static string CreateFingerprint(params string[] parts)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|', parts)));
        return Convert.ToHexString(hash);
    }

    private sealed record HygieneOptions(
        IReadOnlyList<Regex> FeatureReferencePatterns,
        IReadOnlyList<Regex> FeatureDefinitionPatterns,
        int FeatureFlagStaleDays,
        int FeatureFlagRecentChangeDays,
        int TodoOldDays,
        IReadOnlySet<string> TodoKeywords);

    private sealed class FeatureOccurrence
    {
        public FeatureOccurrence(string filePath, int line, string flag, bool isDefinition, string snippet)
        {
            FilePath = filePath;
            Line = line;
            Flag = flag;
            IsDefinition = isDefinition;
            Snippet = snippet;
        }

        public string FilePath { get; }
        public int Line { get; }
        public string Flag { get; }
        public bool IsDefinition { get; }
        public string Snippet { get; }
        public string? Author { get; set; }
        public DateTimeOffset? AuthorTime { get; set; }
    }

    private sealed class TodoOccurrence
    {
        public TodoOccurrence(string filePath, int line, string keyword, string snippet)
        {
            FilePath = filePath;
            Line = line;
            Keyword = keyword;
            Snippet = snippet;
        }

        public string FilePath { get; }
        public int Line { get; }
        public string Keyword { get; }
        public string Snippet { get; }
        public string? Author { get; set; }
        public DateTimeOffset? AuthorTime { get; set; }
    }

    private sealed record BlameLineInfo(string Author, DateTimeOffset? AuthorTime);

    private sealed class GitBlameProvider
    {
        private readonly string _repoRoot;
        private readonly Dictionary<string, IReadOnlyDictionary<int, BlameLineInfo>> _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _missing = new(StringComparer.OrdinalIgnoreCase);

        public GitBlameProvider(string repoRoot)
        {
            _repoRoot = repoRoot;
        }

        public bool TryGetLineInfo(string filePath, out IReadOnlyDictionary<int, BlameLineInfo> byLine)
        {
            if (_cache.TryGetValue(filePath, out byLine!))
            {
                return true;
            }

            if (_missing.Contains(filePath))
            {
                byLine = new Dictionary<int, BlameLineInfo>();
                return false;
            }

            var parsed = RunBlame(filePath);
            if (parsed is null)
            {
                _missing.Add(filePath);
                byLine = new Dictionary<int, BlameLineInfo>();
                return false;
            }

            _cache[filePath] = parsed;
            byLine = parsed;
            return true;
        }

        private IReadOnlyDictionary<int, BlameLineInfo>? RunBlame(string filePath)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                startInfo.ArgumentList.Add("-C");
                startInfo.ArgumentList.Add(_repoRoot);
                startInfo.ArgumentList.Add("blame");
                startInfo.ArgumentList.Add("--line-porcelain");
                startInfo.ArgumentList.Add("--");
                startInfo.ArgumentList.Add(filePath);

                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    return null;
                }

                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                {
                    return null;
                }

                return ParseBlame(output);
            }
            catch
            {
                return null;
            }
        }

        private static IReadOnlyDictionary<int, BlameLineInfo> ParseBlame(string output)
        {
            var map = new Dictionary<int, BlameLineInfo>();
            var lines = output.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

            var finalLine = 0;
            var groupSize = 0;
            var author = "unknown";
            DateTimeOffset? authorTime = null;

            foreach (var raw in lines)
            {
                if (string.IsNullOrEmpty(raw))
                {
                    continue;
                }

                if (raw.Length > 40 && raw[40] == ' ')
                {
                    var headerParts = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (headerParts.Length >= 4 &&
                        int.TryParse(headerParts[2], out var parsedFinalLine) &&
                        int.TryParse(headerParts[3], out var parsedGroupSize))
                    {
                        finalLine = parsedFinalLine;
                        groupSize = parsedGroupSize;
                        author = "unknown";
                        authorTime = null;
                        continue;
                    }
                }

                if (raw.StartsWith("author ", StringComparison.Ordinal))
                {
                    author = raw["author ".Length..].Trim();
                    continue;
                }

                if (raw.StartsWith("author-time ", StringComparison.Ordinal))
                {
                    if (long.TryParse(raw["author-time ".Length..].Trim(), out var unix))
                    {
                        authorTime = DateTimeOffset.FromUnixTimeSeconds(unix);
                    }

                    continue;
                }

                if (raw[0] != '\t')
                {
                    continue;
                }

                if (finalLine > 0)
                {
                    map[finalLine] = new BlameLineInfo(author, authorTime);
                    finalLine++;
                }

                if (groupSize > 0)
                {
                    groupSize--;
                }
            }

            return map;
        }
    }
}
