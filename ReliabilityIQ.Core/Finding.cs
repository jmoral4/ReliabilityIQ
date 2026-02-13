namespace ReliabilityIQ.Core;

public sealed record Finding
{
    public long? FindingId { get; init; }

    public string? RunId { get; init; }

    public required string RuleId { get; init; }

    public required string FilePath { get; init; }

    public int Line { get; init; }

    public int Column { get; init; }

    public required string Message { get; init; }

    public string? Snippet { get; init; }

    public required FindingSeverity Severity { get; init; }

    public required FindingConfidence Confidence { get; init; }

    public required string Fingerprint { get; init; }

    public string? Metadata { get; init; }
}
