namespace ReliabilityIQ.Web.Configuration;

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    public string? Path { get; init; }
}
