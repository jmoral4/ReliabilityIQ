namespace ReliabilityIQ.Analyzers.Dependencies;

public interface IOsvClient
{
    Task<IReadOnlyList<DependencyVulnerability>> QueryVulnerabilitiesAsync(
        DependencyEcosystem ecosystem,
        string packageName,
        string version,
        CancellationToken cancellationToken = default);
}
