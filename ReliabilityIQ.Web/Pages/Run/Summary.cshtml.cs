using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class SummaryModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public SummaryModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    public RunDetails? Run { get; private set; }

    public IReadOnlyList<RuleSummaryItem> RuleSummary { get; private set; } = Array.Empty<RuleSummaryItem>();

    public IReadOnlyList<FileSummaryItem> TopFiles { get; private set; } = Array.Empty<FileSummaryItem>();

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

        RuleSummary = await _queries.GetRuleSummary(RunId, cancellationToken).ConfigureAwait(false);
        TopFiles = (await _queries.GetFileSummary(RunId, cancellationToken).ConfigureAwait(false))
            .Take(10)
            .ToList();

        ViewData["CurrentRunId"] = RunId;
        return Page();
    }
}
