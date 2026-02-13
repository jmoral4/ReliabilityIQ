namespace ReliabilityIQ.Core;

public interface IAnalyzerPlugin
{
    string Name { get; }

    string Version { get; }

    IReadOnlyCollection<FileCategory> SupportedFileCategories { get; }

    Task<IEnumerable<Finding>> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken = default);
}
