using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Pages;

public sealed class RulesModel : PageModel
{
    private readonly SqliteResultsQueries _queries;

    public RulesModel(SqliteResultsQueries queries)
    {
        _queries = queries;
    }

    [BindProperty(SupportsGet = true)]
    public string? Category { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? RuleId { get; set; }

    public IReadOnlyList<RuleCatalogItem> Rules { get; private set; } = Array.Empty<RuleCatalogItem>();

    public IReadOnlyList<RuleFindingAcrossRunsItem> RuleFindings { get; private set; } = Array.Empty<RuleFindingAcrossRunsItem>();

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Rules = await _queries.GetRuleCatalog(Category, cancellationToken).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(RuleId))
        {
            RuleFindings = await _queries.GetFindingsForRuleAcrossRuns(RuleId.Trim(), 500, cancellationToken).ConfigureAwait(false);
        }
    }
}
