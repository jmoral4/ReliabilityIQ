namespace ReliabilityIQ.Analyzers.Dependencies;

public enum DependencyEcosystem
{
    NuGet,
    PyPI,
    Cargo,
    Npm,
    Unknown
}

public enum DependencyVulnerabilitySeverity
{
    Medium,
    High,
    Critical,
    Unknown
}

public sealed record DependencyRecord(
    string FilePath,
    int Line,
    DependencyEcosystem Ecosystem,
    string Name,
    string VersionSpec,
    bool IsPinned,
    string? ExactVersion,
    bool IsFrameworkReference = false);

public sealed record DependencyVulnerability(
    string AdvisoryId,
    DependencyVulnerabilitySeverity Severity,
    string? Summary);

public sealed record EolFrameworkMatch(
    string FilePath,
    int Line,
    string Framework,
    string Reason);
