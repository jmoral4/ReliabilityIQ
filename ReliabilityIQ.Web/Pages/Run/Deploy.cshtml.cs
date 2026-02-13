using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class DeployModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public DeployModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    public RunDetails? Run { get; private set; }

    public DeploymentSeveritySummaryItem Ev2Summary { get; private set; } = new("EV2", 0, 0, 0);

    public DeploymentSeveritySummaryItem AdoSummary { get; private set; } = new("ADO", 0, 0, 0);

    public IReadOnlyList<DeploymentArtifactRiskItem> TopRiskyArtifacts { get; private set; } = Array.Empty<DeploymentArtifactRiskItem>();

    public long ParameterizationOpportunities { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(RunId))
        {
            return RedirectToPage("/Index");
        }

        Run = await _queries.GetRunById(RunId, cancellationToken).ConfigureAwait(false);
        if (Run is null)
        {
            return NotFound();
        }

        var summaries = await _queries.GetDeploymentSeveritySummary(RunId, includeSuppressed: false, cancellationToken).ConfigureAwait(false);
        Ev2Summary = summaries.FirstOrDefault(item => item.ArtifactType.Equals("EV2", StringComparison.OrdinalIgnoreCase))
            ?? new DeploymentSeveritySummaryItem("EV2", 0, 0, 0);
        AdoSummary = summaries.FirstOrDefault(item => item.ArtifactType.Equals("ADO", StringComparison.OrdinalIgnoreCase))
            ?? new DeploymentSeveritySummaryItem("ADO", 0, 0, 0);

        TopRiskyArtifacts = await _queries.GetTopDeploymentArtifactsByRisk(RunId, 5, includeSuppressed: false, cancellationToken).ConfigureAwait(false);
        ParameterizationOpportunities = await _queries.GetDeploymentParameterizationOpportunityCount(RunId, includeSuppressed: false, cancellationToken).ConfigureAwait(false);

        ViewData["CurrentRunId"] = RunId;
        return Page();
    }
}
