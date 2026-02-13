using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class HeatmapModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public HeatmapModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    public RunDetails? Run { get; private set; }

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

        ViewData["CurrentRunId"] = RunId;
        return Page();
    }
}
