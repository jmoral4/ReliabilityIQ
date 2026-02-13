using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages;

public sealed class IndexModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public IndexModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    public IReadOnlyList<RunListItem> Runs { get; private set; } = Array.Empty<RunListItem>();

    [BindProperty(SupportsGet = true)]
    public string? RunId { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Runs = await _queries.GetAllRuns(cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(RunId) && Runs.Count > 0)
        {
            RunId = Runs[0].RunId;
        }

        ViewData["CurrentRunId"] = RunId;
    }
}
