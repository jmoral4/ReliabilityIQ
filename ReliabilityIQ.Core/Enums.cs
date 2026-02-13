namespace ReliabilityIQ.Core;

public enum FindingSeverity
{
    Error = 0,
    Warning = 1,
    Info = 2
}

public enum FindingConfidence
{
    High = 0,
    Medium = 1,
    Low = 2
}

public enum FileCategory
{
    Source = 0,
    Config = 1,
    DeploymentArtifact = 2,
    Docs = 3,
    Generated = 4,
    Vendor = 5,
    IDE = 6,
    Unknown = 7
}
