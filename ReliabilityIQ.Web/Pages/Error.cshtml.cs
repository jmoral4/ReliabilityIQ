using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;

namespace ReliabilityIQ.Web.Pages;

public sealed class ErrorModel : PageModel
{
    public string? RequestId { get; private set; }

    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

    public void OnGet()
    {
        RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
    }
}
