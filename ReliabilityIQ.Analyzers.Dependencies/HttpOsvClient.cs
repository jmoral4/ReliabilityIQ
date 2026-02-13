using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ReliabilityIQ.Analyzers.Dependencies;

public sealed class HttpOsvClient : IOsvClient
{
    private static readonly Uri QueryUri = new("https://api.osv.dev/v1/query", UriKind.Absolute);
    private readonly HttpClient _httpClient;

    public HttpOsvClient(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<IReadOnlyList<DependencyVulnerability>> QueryVulnerabilitiesAsync(
        DependencyEcosystem ecosystem,
        string packageName,
        string version,
        CancellationToken cancellationToken = default)
    {
        if (ecosystem == DependencyEcosystem.Unknown || string.IsNullOrWhiteSpace(packageName) || string.IsNullOrWhiteSpace(version))
        {
            return [];
        }

        var request = new OsvQueryRequest
        {
            Package = new OsvPackage
            {
                Name = packageName,
                Ecosystem = ToOsvEcosystem(ecosystem)
            },
            Version = version
        };

        try
        {
            using var response = await _httpClient.PostAsJsonAsync(QueryUri, request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return [];
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var payload = await JsonSerializer.DeserializeAsync<OsvQueryResponse>(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (payload?.Vulns is null || payload.Vulns.Count == 0)
            {
                return [];
            }

            return payload.Vulns.Select(v => new DependencyVulnerability(
                    AdvisoryId: v.Id ?? "unknown",
                    Severity: ResolveSeverity(v),
                    Summary: v.Summary))
                .ToList();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return [];
        }
    }

    public async Task<string?> QueryLatestVersionAsync(
        DependencyEcosystem ecosystem,
        string packageName,
        CancellationToken cancellationToken = default)
    {
        if (ecosystem == DependencyEcosystem.Unknown || string.IsNullOrWhiteSpace(packageName))
        {
            return null;
        }

        try
        {
            return ecosystem switch
            {
                DependencyEcosystem.NuGet => await QueryNuGetLatestVersionAsync(packageName, cancellationToken).ConfigureAwait(false),
                DependencyEcosystem.PyPI => await QueryPyPiLatestVersionAsync(packageName, cancellationToken).ConfigureAwait(false),
                DependencyEcosystem.Cargo => await QueryCargoLatestVersionAsync(packageName, cancellationToken).ConfigureAwait(false),
                DependencyEcosystem.Npm => await QueryNpmLatestVersionAsync(packageName, cancellationToken).ConfigureAwait(false),
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }

    private static DependencyVulnerabilitySeverity ResolveSeverity(OsvVuln vuln)
    {
        var labels = vuln.Severity?.Select(s => s.Score).Where(x => !string.IsNullOrWhiteSpace(x)).ToList() ?? [];
        var maxScore = labels
            .Select(ExtractCvssScore)
            .Where(s => s.HasValue)
            .Select(s => s!.Value)
            .DefaultIfEmpty(-1d)
            .Max();

        if (maxScore >= 9.0d)
        {
            return DependencyVulnerabilitySeverity.Critical;
        }

        if (maxScore >= 7.0d)
        {
            return DependencyVulnerabilitySeverity.High;
        }

        if (maxScore >= 0d)
        {
            return DependencyVulnerabilitySeverity.Medium;
        }

        var text = string.Join(' ', labels).ToLowerInvariant();
        if (text.Contains("critical", StringComparison.Ordinal))
        {
            return DependencyVulnerabilitySeverity.Critical;
        }

        if (text.Contains("high", StringComparison.Ordinal))
        {
            return DependencyVulnerabilitySeverity.High;
        }

        if (text.Contains("medium", StringComparison.Ordinal))
        {
            return DependencyVulnerabilitySeverity.Medium;
        }

        return DependencyVulnerabilitySeverity.Unknown;
    }

    private static double? ExtractCvssScore(string? score)
    {
        if (string.IsNullOrWhiteSpace(score))
        {
            return null;
        }

        if (double.TryParse(score, out var numeric))
        {
            return numeric;
        }

        var match = Regex.Match(score, @"(?<!\d)(10(?:\.0)?|[0-9](?:\.[0-9])?)(?!\d)");
        if (!match.Success)
        {
            return null;
        }

        return double.TryParse(match.Value, out var parsed) ? parsed : null;
    }

    private static string ToOsvEcosystem(DependencyEcosystem ecosystem)
    {
        return ecosystem switch
        {
            DependencyEcosystem.NuGet => "NuGet",
            DependencyEcosystem.PyPI => "PyPI",
            DependencyEcosystem.Cargo => "crates.io",
            DependencyEcosystem.Npm => "npm",
            _ => ""
        };
    }

    private async Task<string?> QueryNuGetLatestVersionAsync(string packageName, CancellationToken cancellationToken)
    {
        var url = $"https://api.nuget.org/v3-flatcontainer/{Uri.EscapeDataString(packageName.ToLowerInvariant())}/index.json";
        var payload = await _httpClient.GetFromJsonAsync<NuGetVersionsResponse>(url, cancellationToken).ConfigureAwait(false);
        return payload?.Versions?.LastOrDefault();
    }

    private async Task<string?> QueryPyPiLatestVersionAsync(string packageName, CancellationToken cancellationToken)
    {
        var url = $"https://pypi.org/pypi/{Uri.EscapeDataString(packageName)}/json";
        var payload = await _httpClient.GetFromJsonAsync<PyPiPackageResponse>(url, cancellationToken).ConfigureAwait(false);
        return payload?.Info?.Version;
    }

    private async Task<string?> QueryCargoLatestVersionAsync(string packageName, CancellationToken cancellationToken)
    {
        var url = $"https://crates.io/api/v1/crates/{Uri.EscapeDataString(packageName)}";
        var payload = await _httpClient.GetFromJsonAsync<CargoPackageResponse>(url, cancellationToken).ConfigureAwait(false);
        return payload?.Crate?.MaxStableVersion ?? payload?.Crate?.MaxVersion;
    }

    private async Task<string?> QueryNpmLatestVersionAsync(string packageName, CancellationToken cancellationToken)
    {
        var url = $"https://registry.npmjs.org/{Uri.EscapeDataString(packageName)}/latest";
        var payload = await _httpClient.GetFromJsonAsync<NpmPackageResponse>(url, cancellationToken).ConfigureAwait(false);
        return payload?.Version;
    }

    private sealed class OsvQueryRequest
    {
        public OsvPackage? Package { get; set; }
        public string? Version { get; set; }
    }

    private sealed class OsvPackage
    {
        public string? Name { get; set; }
        public string? Ecosystem { get; set; }
    }

    private sealed class OsvQueryResponse
    {
        public List<OsvVuln>? Vulns { get; set; }
    }

    private sealed class OsvVuln
    {
        public string? Id { get; set; }
        public string? Summary { get; set; }
        public List<OsvSeverity>? Severity { get; set; }
    }

    private sealed class OsvSeverity
    {
        public string? Type { get; set; }
        public string? Score { get; set; }
    }

    private sealed class NuGetVersionsResponse
    {
        public List<string>? Versions { get; set; }
    }

    private sealed class PyPiPackageResponse
    {
        public PyPiInfo? Info { get; set; }
    }

    private sealed class PyPiInfo
    {
        public string? Version { get; set; }
    }

    private sealed class CargoPackageResponse
    {
        public CargoCrate? Crate { get; set; }
    }

    private sealed class CargoCrate
    {
        public string? MaxVersion { get; set; }
        public string? MaxStableVersion { get; set; }
    }

    private sealed class NpmPackageResponse
    {
        public string? Version { get; set; }
    }
}
