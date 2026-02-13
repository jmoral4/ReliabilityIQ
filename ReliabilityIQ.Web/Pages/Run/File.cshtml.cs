using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;
using System.Text.Json;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class FileModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public FileModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public long FileId { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool IncludeSuppressed { get; set; }

    public RunDetails? Run { get; private set; }

    public FileDetailItem? FileDetails { get; private set; }

    public IReadOnlyList<FindingListItem> Findings { get; private set; } = Array.Empty<FindingListItem>();

    public IReadOnlyList<DeploymentContextItem> DeploymentContexts { get; private set; } = Array.Empty<DeploymentContextItem>();

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(RunId) || FileId <= 0)
        {
            return RedirectToPage("/Index");
        }

        Run = await _queries.GetRunById(RunId, cancellationToken).ConfigureAwait(false);
        if (Run is null)
        {
            return NotFound();
        }

        FileDetails = await _queries.GetFileById(RunId, FileId, cancellationToken).ConfigureAwait(false);
        if (FileDetails is null)
        {
            return NotFound();
        }

        Findings = await _queries.GetFindingsForFile(RunId, FileId, IncludeSuppressed, cancellationToken).ConfigureAwait(false);
        DeploymentContexts = Findings
            .Where(finding => finding.RuleId.StartsWith("deploy.", StringComparison.OrdinalIgnoreCase))
            .Select(MapDeploymentContext)
            .ToList();

        ViewData["CurrentRunId"] = RunId;
        return Page();
    }

    private static DeploymentContextItem MapDeploymentContext(FindingListItem finding)
    {
        string? artifactPath = null;
        string? matchedValue = null;
        string parserMode = "n/a";

        if (!string.IsNullOrWhiteSpace(finding.Metadata))
        {
            try
            {
                using var document = JsonDocument.Parse(finding.Metadata);
                var root = document.RootElement;
                if (root.TryGetProperty("artifactPath", out var artifactPathElement))
                {
                    artifactPath = artifactPathElement.GetString();
                }

                if (root.TryGetProperty("matchedValue", out var matchedValueElement))
                {
                    matchedValue = matchedValueElement.GetString();
                }

                if (root.TryGetProperty("parserMode", out var parserModeElement))
                {
                    parserMode = parserModeElement.GetString() ?? "n/a";
                }
            }
            catch (JsonException)
            {
            }
        }

        var artifactType = finding.RuleId.StartsWith("deploy.ev2.", StringComparison.OrdinalIgnoreCase)
            ? "EV2"
            : finding.RuleId.StartsWith("deploy.ado.", StringComparison.OrdinalIgnoreCase)
                ? "ADO"
                : "Unknown";

        return new DeploymentContextItem(
            finding.RuleId,
            artifactType,
            artifactPath ?? "$",
            matchedValue,
            parserMode,
            finding.Message,
            finding.Snippet);
    }

    public sealed record DeploymentContextItem(
        string RuleId,
        string ArtifactType,
        string LocationPath,
        string? MatchedValue,
        string ParserMode,
        string Message,
        string? Snippet);
}
