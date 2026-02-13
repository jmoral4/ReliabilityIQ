namespace ReliabilityIQ.Core.Discovery;

public sealed record DiscoveredFile(
    string FullPath,
    string RelativePath,
    FileCategory Category,
    string? Language,
    long SizeBytes,
    string ContentHash);
