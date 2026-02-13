using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class CompareModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public CompareModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? BaselineRunId { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? TargetRunId { get; set; }

    public IReadOnlyList<RunListItem> Runs { get; private set; } = Array.Empty<RunListItem>();

    public RunComparisonResult? Comparison { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(RunId))
        {
            return RedirectToPage("/Index");
        }

        Runs = await _queries.GetAllRuns(cancellationToken).ConfigureAwait(false);
        if (Runs.Count == 0)
        {
            ViewData["CurrentRunId"] = RunId;
            return Page();
        }

        TargetRunId = string.IsNullOrWhiteSpace(TargetRunId) ? RunId : TargetRunId;

        BaselineRunId ??= Runs
            .FirstOrDefault(run => !string.Equals(run.RunId, TargetRunId, StringComparison.OrdinalIgnoreCase))
            ?.RunId;

        if (!string.IsNullOrWhiteSpace(BaselineRunId) && !string.IsNullOrWhiteSpace(TargetRunId))
        {
            Comparison = await _queries.GetRunComparison(
                new RunComparisonRequest(BaselineRunId, TargetRunId),
                detailLimit: 200,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        ViewData["CurrentRunId"] = TargetRunId;
        return Page();
    }
}
