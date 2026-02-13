using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

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

        ViewData["CurrentRunId"] = RunId;
        return Page();
    }
}
