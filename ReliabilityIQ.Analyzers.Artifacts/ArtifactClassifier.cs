namespace ReliabilityIQ.Analyzers.Artifacts;

public enum ArtifactKind
{
    Unknown = 0,
    Ev2 = 1,
    Ado = 2
}

public static class ArtifactClassifier
{
    private static readonly string[] DefaultEv2Markers =
    [
        "/ev2/",
        "/rollout",
        "/service-model",
        "/servicemodel",
        "/bindings/"
    ];

    private static readonly string[] DefaultAdoMarkers =
    [
        "/azure-pipelines",
        "/pipelines/",
        "/ado/",
        "/.azuredevops/",
        "/build/"
    ];

    public static ArtifactKind DetectKind(string filePath, string? content, IReadOnlyDictionary<string, string?>? configuration)
    {
        var normalizedPath = filePath.Replace('\\', '/');

        var ev2Markers = GetMarkers(configuration, "deploy.ev2.pathMarkers", DefaultEv2Markers);
        var adoMarkers = GetMarkers(configuration, "deploy.ado.pathMarkers", DefaultAdoMarkers);

        if (ContainsAny(normalizedPath, ev2Markers))
        {
            return ArtifactKind.Ev2;
        }

        if (ContainsAny(normalizedPath, adoMarkers))
        {
            return ArtifactKind.Ado;
        }

        var extension = Path.GetExtension(filePath);
        var isStructured = extension.Equals(".yaml", StringComparison.OrdinalIgnoreCase) ||
                           extension.Equals(".yml", StringComparison.OrdinalIgnoreCase) ||
                           extension.Equals(".json", StringComparison.OrdinalIgnoreCase);

        if (!isStructured || string.IsNullOrWhiteSpace(content))
        {
            return ArtifactKind.Unknown;
        }

        if (content.Contains("rolloutSpec", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("serviceModel", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("waitDuration", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.Ev2;
        }

        if (content.Contains("trigger:", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("stages:", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("pool:", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("variables:", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.Ado;
        }

        return ArtifactKind.Unknown;
    }

    private static IReadOnlyList<string> GetMarkers(
        IReadOnlyDictionary<string, string?>? configuration,
        string key,
        IReadOnlyList<string> defaults)
    {
        if (configuration is null || !configuration.TryGetValue(key, out var configured) || string.IsNullOrWhiteSpace(configured))
        {
            return defaults;
        }

        var split = configured
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(v => NormalizeMarker(v))
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return split.Count == 0 ? defaults : split;
    }

    private static bool ContainsAny(string value, IReadOnlyList<string> markers)
    {
        foreach (var marker in markers)
        {
            if (value.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var trimmed = marker.Trim('/');
            if (trimmed.Length > 0 &&
                value.StartsWith(trimmed + "/", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (trimmed.Length > 0 &&
                string.Equals(value, trimmed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string NormalizeMarker(string marker)
    {
        var normalized = marker.Replace('\\', '/').Trim();
        if (normalized.Length == 0)
        {
            return string.Empty;
        }

        if (!normalized.StartsWith("/", StringComparison.Ordinal))
        {
            normalized = "/" + normalized;
        }

        if (!normalized.EndsWith("/", StringComparison.Ordinal))
        {
            normalized += "/";
        }

        return normalized;
    }
}
