using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages.Run;

public sealed class FindingsModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public FindingsModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string RunId { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? RulePrefix { get; set; }

    public RunDetails? Run { get; private set; }

    public IReadOnlyList<RuleSummaryItem> RuleSummary { get; private set; } = Array.Empty<RuleSummaryItem>();

    public IReadOnlyList<string> FileCategories { get; private set; } = Array.Empty<string>();

    public IReadOnlyList<string> Languages { get; private set; } = Array.Empty<string>();

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

        var fileSummary = await _queries.GetFileSummary(RunId, cancellationToken).ConfigureAwait(false);
        FileCategories = fileSummary
            .Select(item => item.Category)
            .Where(category => !string.IsNullOrWhiteSpace(category))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(category => category, StringComparer.Ordinal)
            .Cast<string>()
            .ToList();

        Languages = fileSummary
            .Select(item => item.Language)
            .Where(language => !string.IsNullOrWhiteSpace(language))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(language => language, StringComparer.OrdinalIgnoreCase)
            .Cast<string>()
            .ToList();

        ViewData["CurrentRunId"] = RunId;
        return Page();
    }
}
