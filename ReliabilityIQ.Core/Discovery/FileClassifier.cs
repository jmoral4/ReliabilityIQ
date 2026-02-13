using System.Collections.Frozen;

namespace ReliabilityIQ.Core.Discovery;

public sealed class FileClassifier
{
    private static readonly FrozenSet<string> SourceExtensions = new[]
    {
        ".cs", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh", ".hxx", ".py", ".ps1", ".rs", ".java", ".go", ".js",
        ".ts", ".tsx", ".jsx", ".swift", ".kt", ".kts"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<string> ConfigExtensions = new[]
    {
        ".json", ".yaml", ".yml", ".ini", ".config", ".toml", ".xml", ".properties"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<string> DocsExtensions = new[]
    {
        ".md", ".rst", ".txt", ".adoc"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] DeploymentPathMarkers =
    {
        "/ev2/",
        "/pipelines/",
        "/helm/",
        "/k8s/",
        "/manifests/",
        "/deploy/"
    };

    public FileCategory Classify(string relativePath)
    {
        var normalizedPath = Normalize(relativePath);
        if (IsInDirectory(normalizedPath, RepoDiscovery.DefaultGeneratedDirectories))
        {
            return FileCategory.Generated;
        }

        if (IsInDirectory(normalizedPath, RepoDiscovery.DefaultVendorDirectories))
        {
            return FileCategory.Vendor;
        }

        if (IsInDirectory(normalizedPath, RepoDiscovery.DefaultIdeDirectories))
        {
            return FileCategory.IDE;
        }

        if (HasAnyMarker(normalizedPath, DeploymentPathMarkers))
        {
            return FileCategory.DeploymentArtifact;
        }

        var extension = Path.GetExtension(normalizedPath);
        if (SourceExtensions.Contains(extension))
        {
            return FileCategory.Source;
        }

        if (ConfigExtensions.Contains(extension))
        {
            return FileCategory.Config;
        }

        if (DocsExtensions.Contains(extension))
        {
            return FileCategory.Docs;
        }

        return FileCategory.Unknown;
    }

    public string? DetectLanguage(string relativePath)
    {
        return Path.GetExtension(relativePath).ToLowerInvariant() switch
        {
            ".cs" => "csharp",
            ".cpp" or ".cc" or ".cxx" or ".c" or ".h" or ".hpp" or ".hh" or ".hxx" => "cpp",
            ".py" => "python",
            ".ps1" => "powershell",
            ".rs" => "rust",
            ".js" => "javascript",
            ".ts" or ".tsx" => "typescript",
            ".jsx" => "jsx",
            ".json" => "json",
            ".yaml" or ".yml" => "yaml",
            ".xml" => "xml",
            ".md" => "markdown",
            _ => null
        };
    }

    private static string Normalize(string relativePath) => relativePath.Replace('\\', '/');

    private static bool HasAnyMarker(string normalizedPath, IEnumerable<string> markers)
    {
        foreach (var marker in markers)
        {
            if (normalizedPath.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    internal static bool IsInDirectory(string normalizedPath, IEnumerable<string> directoryNames)
    {
        foreach (var directory in directoryNames)
        {
            var token = "/" + directory.Trim('/') + "/";
            if (normalizedPath.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalizedPath.StartsWith(directory.Trim('/') + "/", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
