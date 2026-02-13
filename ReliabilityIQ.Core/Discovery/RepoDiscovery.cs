using System.Security.Cryptography;

namespace ReliabilityIQ.Core.Discovery;

public sealed record RepoDiscoveryOptions(
    bool UseGitIgnore = true,
    long MaxFileSizeBytes = 2 * 1024 * 1024,
    IReadOnlyCollection<string>? AdditionalExcludeDirectories = null,
    bool ExcludeDotDirectories = true);

public static class RepoDiscovery
{
    private static readonly string[] AlwaysExcludedFileSuffixes =
    [
        ".db-shm",
        ".db-wal",
        ".db-journal"
    ];

    private static readonly string[] AlwaysExcludedFileNames =
    [
        "thumbs.db",
        "desktop.ini"
    ];

    public static readonly string[] DefaultGeneratedDirectories =
    [
        "bin",
        "obj",
        "out",
        "dist",
        "target",
        "__pycache__"
    ];

    public static readonly string[] DefaultVendorDirectories =
    [
        "node_modules",
        "third_party",
        "vendor",
        "packages"
    ];

    public static readonly string[] DefaultIdeDirectories =
    [
        ".vs",
        ".vscode",
        ".idea"
    ];

    private static readonly string[] AlwaysExcludedDirectories =
    [
        ".git"
    ];

    public static string FindRepoRoot(string startPath)
    {
        if (string.IsNullOrWhiteSpace(startPath))
        {
            throw new ArgumentException("Start path is required.", nameof(startPath));
        }

        var fullPath = Path.GetFullPath(startPath);
        var directory = Directory.Exists(fullPath) ? new DirectoryInfo(fullPath) : new FileInfo(fullPath).Directory;
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return Directory.Exists(fullPath) ? fullPath : Path.GetDirectoryName(fullPath)!;
    }

    public static IReadOnlyList<DiscoveredFile> DiscoverFiles(
        string repoRoot,
        FileClassifier? classifier = null,
        RepoDiscoveryOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(repoRoot))
        {
            throw new ArgumentException("Repository root is required.", nameof(repoRoot));
        }

        classifier ??= new FileClassifier();
        options ??= new RepoDiscoveryOptions();
        var resolvedRepoRoot = Path.GetFullPath(repoRoot);
        if (!Directory.Exists(resolvedRepoRoot))
        {
            throw new DirectoryNotFoundException($"Repository root was not found: {resolvedRepoRoot}");
        }

        var additional = options.AdditionalExcludeDirectories ?? Array.Empty<string>();
        var excludedDirectories = BuildExcludedDirectorySet(additional);
        var gitIgnoreMatcher = options.UseGitIgnore ? GitIgnoreMatcher.Load(resolvedRepoRoot) : GitIgnoreMatcher.Empty;
        var discovered = new List<DiscoveredFile>();

        foreach (var file in Directory.EnumerateFiles(resolvedRepoRoot, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(resolvedRepoRoot, file).Replace('\\', '/');
            if (ShouldSkip(relativePath, excludedDirectories, gitIgnoreMatcher, options.ExcludeDotDirectories))
            {
                continue;
            }

            FileInfo info;
            try
            {
                info = new FileInfo(file);
                if (info.Length > options.MaxFileSizeBytes)
                {
                    continue;
                }

                var category = classifier.Classify(relativePath);
                if (category is FileCategory.Generated or FileCategory.Vendor or FileCategory.IDE)
                {
                    continue;
                }

                var hash = ComputeSha256(file);
                discovered.Add(new DiscoveredFile(
                    FullPath: file,
                    RelativePath: relativePath,
                    Category: category,
                    Language: classifier.DetectLanguage(relativePath),
                    SizeBytes: info.Length,
                    ContentHash: hash));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best-effort discovery: skip transiently locked or inaccessible files.
                continue;
            }
        }

        return discovered;
    }

    private static bool ShouldSkip(
        string relativePath,
        HashSet<string> excludedDirectories,
        GitIgnoreMatcher gitIgnoreMatcher,
        bool excludeDotDirectories)
    {
        if (IsAlwaysExcludedFile(relativePath))
        {
            return true;
        }

        var normalized = "/" + relativePath.TrimStart('/');
        if (FileClassifier.IsInDirectory(normalized, excludedDirectories))
        {
            return true;
        }

        if (excludeDotDirectories && IsInDotDirectory(relativePath))
        {
            return true;
        }

        return gitIgnoreMatcher.IsMatch(relativePath);
    }

    private static bool IsAlwaysExcludedFile(string relativePath)
    {
        var fileName = Path.GetFileName(relativePath);
        if (fileName.Length == 0)
        {
            return false;
        }

        foreach (var name in AlwaysExcludedFileNames)
        {
            if (string.Equals(fileName, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (var suffix in AlwaysExcludedFileSuffixes)
        {
            if (fileName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsInDotDirectory(string relativePath)
    {
        var normalized = relativePath.TrimStart('/').Replace('\\', '/');
        var slashIndex = normalized.IndexOf('/');
        while (slashIndex >= 0)
        {
            var segment = normalized[..slashIndex];
            if (segment.StartsWith(".", StringComparison.Ordinal))
            {
                return true;
            }

            normalized = normalized[(slashIndex + 1)..];
            slashIndex = normalized.IndexOf('/');
        }

        return false;
    }

    private static HashSet<string> BuildExcludedDirectorySet(IReadOnlyCollection<string> additional)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Add(set, DefaultGeneratedDirectories);
        Add(set, DefaultVendorDirectories);
        Add(set, DefaultIdeDirectories);
        Add(set, AlwaysExcludedDirectories);
        Add(set, additional);
        return set;
    }

    private static void Add(HashSet<string> set, IEnumerable<string> values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                set.Add(value.Trim().Trim('/'));
            }
        }
    }

    private static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed class GitIgnoreMatcher
    {
        private static readonly char[] Wildcards = ['*', '?'];
        private readonly List<string> _directorySuffixes;
        private readonly List<SimplePattern> _patterns;

        public static GitIgnoreMatcher Empty { get; } = new([], []);

        private GitIgnoreMatcher(List<string> directorySuffixes, List<SimplePattern> patterns)
        {
            _directorySuffixes = directorySuffixes;
            _patterns = patterns;
        }

        public static GitIgnoreMatcher Load(string repoRoot)
        {
            var path = Path.Combine(repoRoot, ".gitignore");
            if (!File.Exists(path))
            {
                return Empty;
            }

            var directorySuffixes = new List<string>();
            var patterns = new List<SimplePattern>();
            foreach (var rawLine in File.ReadAllLines(path))
            {
                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                {
                    continue;
                }

                if (line.StartsWith('!'))
                {
                    continue;
                }

                var normalized = line.TrimStart('/').Replace('\\', '/');
                if (line.EndsWith('/'))
                {
                    var suffix = "/" + normalized.TrimEnd('/') + "/";
                    directorySuffixes.Add(suffix);
                    continue;
                }

                var hasWildcard = normalized.IndexOfAny(Wildcards) >= 0;
                patterns.Add(new SimplePattern(normalized, hasWildcard));
            }

            return new GitIgnoreMatcher(directorySuffixes, patterns);
        }

        public bool IsMatch(string relativePath)
        {
            var normalized = "/" + relativePath.TrimStart('/').Replace('\\', '/');
            foreach (var suffix in _directorySuffixes)
            {
                if (normalized.Contains(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            foreach (var pattern in _patterns)
            {
                if (pattern.IsMatch(normalized))
                {
                    return true;
                }
            }

            return false;
        }

        private sealed record SimplePattern(string Pattern, bool HasWildcard)
        {
            public bool IsMatch(string normalizedPath)
            {
                if (!HasWildcard)
                {
                    if (normalizedPath.EndsWith("/" + Pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    return normalizedPath.Contains("/" + Pattern + "/", StringComparison.OrdinalIgnoreCase);
                }

                return WildcardMatch(normalizedPath.Trim('/'), Pattern);
            }

            private static bool WildcardMatch(string input, string pattern)
            {
                var text = input.AsSpan();
                var pat = pattern.AsSpan();
                var textIndex = 0;
                var patternIndex = 0;
                var starIndex = -1;
                var matchIndex = 0;

                while (textIndex < text.Length)
                {
                    if (patternIndex < pat.Length && (pat[patternIndex] == '?' || EqualsIgnoreCase(pat[patternIndex], text[textIndex])))
                    {
                        textIndex++;
                        patternIndex++;
                    }
                    else if (patternIndex < pat.Length && pat[patternIndex] == '*')
                    {
                        starIndex = patternIndex++;
                        matchIndex = textIndex;
                    }
                    else if (starIndex != -1)
                    {
                        patternIndex = starIndex + 1;
                        textIndex = ++matchIndex;
                    }
                    else
                    {
                        return false;
                    }
                }

                while (patternIndex < pat.Length && pat[patternIndex] == '*')
                {
                    patternIndex++;
                }

                return patternIndex == pat.Length;
            }

            private static bool EqualsIgnoreCase(char left, char right)
            {
                return char.ToLowerInvariant(left) == char.ToLowerInvariant(right);
            }
        }
    }
}
