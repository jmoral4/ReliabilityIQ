namespace ReliabilityIQ.Core;

public sealed record AnalysisContext(
    string FilePath,
    string Content,
    FileCategory FileCategory,
    string? Language,
    IReadOnlyDictionary<string, string?>? Configuration);
