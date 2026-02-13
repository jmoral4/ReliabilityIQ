using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class SuppressionsModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public SuppressionsModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    public RunDetails? Run { get; private set; }

    public SuppressionOverview? Overview { get; private set; }

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

        Overview = await _queries.GetSuppressionOverview(RunId, cancellationToken).ConfigureAwait(false);
        ViewData["CurrentRunId"] = RunId;
        return Page();
    }
}
