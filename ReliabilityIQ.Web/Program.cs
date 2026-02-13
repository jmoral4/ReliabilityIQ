using ReliabilityIQ.Core.Persistence.Queries;
using ReliabilityIQ.Web.Configuration;
using ReliabilityIQ.Web.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddCommandLine(args, new Dictionary<string, string>
{
    ["--db"] = $"{DatabaseOptions.SectionName}:Path"
});

builder.Services.AddRazorPages();
builder.Services
    .AddOptions<DatabaseOptions>()
    .Bind(builder.Configuration.GetSection(DatabaseOptions.SectionName))
    .Validate(
        options => !string.IsNullOrWhiteSpace(options.Path),
        "Database path is required. Set Database:Path in configuration or pass --db <path>.")
    .ValidateOnStart();
builder.Services.AddSingleton<IReadOnlySqliteConnectionFactory, ReadOnlySqliteConnectionFactory>();
builder.Services.AddScoped<SqliteResultsQueries>(services =>
{
    var factory = services.GetRequiredService<IReadOnlySqliteConnectionFactory>();
    return new SqliteResultsQueries(factory.CreateConnection);
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.MapRazorPages();

app.MapGet("/health/db", async (IReadOnlySqliteConnectionFactory connectionFactory, CancellationToken cancellationToken) =>
{
    await using var connection = connectionFactory.CreateConnection();
    await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
    await using var command = connection.CreateCommand();
    command.CommandText = "SELECT 1;";
    var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);

    return Results.Ok(new
    {
        status = "ok",
        database = connectionFactory.DatabasePath,
        probe = result
    });
});

app.MapGet("/api/runs", async (SqliteResultsQueries queries, CancellationToken cancellationToken) =>
{
    var runs = await queries.GetAllRuns(cancellationToken).ConfigureAwait(false);
    return Results.Ok(runs.Select(run => new
    {
        runId = run.RunId,
        label = $"{run.RunId} ({run.StartedAt:yyyy-MM-dd HH:mm:ss} UTC)",
        repoRoot = run.RepoRoot,
        commitSha = run.CommitSha,
        startedAt = run.StartedAt,
        endedAt = run.EndedAt,
        toolVersion = run.ToolVersion,
        errorCount = run.ErrorCount,
        warningCount = run.WarningCount,
        infoCount = run.InfoCount,
        totalFindings = run.TotalFindings
    }));
});

app.MapGet("/api/run/{runId}/findings", async (
    string runId,
    HttpRequest request,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var draw = ParseInt(request.Query["draw"], 1);
    var start = ParseInt(request.Query["start"], 0);
    var length = ParseInt(request.Query["length"], 25);

    var sortColumnIndex = ParseInt(request.Query["order[0][column]"], 0);
    var sortDirectionRaw = request.Query["order[0][dir]"].ToString();
    var sortDirection = string.Equals(sortDirectionRaw, "desc", StringComparison.OrdinalIgnoreCase);
    var sortFieldRaw = request.Query[$"columns[{sortColumnIndex}][name]"].ToString();

    var filters = new FindingsQueryFilters(
        Severity: NullIfEmpty(request.Query["severity"].ToString()),
        RuleId: NullIfEmpty(request.Query["rule"].ToString()),
        FileCategory: NullIfEmpty(request.Query["fileCategory"].ToString()),
        Language: NullIfEmpty(request.Query["language"].ToString()),
        PathPrefix: NullIfEmpty(request.Query["pathPrefix"].ToString()));

    var requestModel = new FindingsQueryRequest(
        Offset: start,
        Limit: length,
        SortField: ParseSortField(sortFieldRaw),
        SortDescending: sortDirection,
        Filters: filters);

    var page = await queries.GetFindings(runId, requestModel, cancellationToken).ConfigureAwait(false);

    return Results.Ok(new
    {
        draw,
        recordsTotal = page.TotalCount,
        recordsFiltered = page.FilteredCount,
        data = page.Items.Select(item => new
        {
            findingId = item.FindingId,
            ruleId = item.RuleId,
            filePath = item.FilePath,
            line = item.Line,
            column = item.Column,
            message = item.Message,
            snippet = item.Snippet,
            severity = item.Severity,
            confidence = item.Confidence,
            fileCategory = item.FileCategory,
            language = item.Language
        })
    });
});
app.Run();

static int ParseInt(string? value, int fallback)
{
    return int.TryParse(value, out var parsed) ? parsed : fallback;
}

static string? NullIfEmpty(string? value)
{
    return string.IsNullOrWhiteSpace(value) ? null : value;
}

static FindingsSortField ParseSortField(string? sortField)
{
    return sortField?.Trim().ToLowerInvariant() switch
    {
        "severity" => FindingsSortField.Severity,
        "ruleid" => FindingsSortField.RuleId,
        "filepath" => FindingsSortField.FilePath,
        "line" => FindingsSortField.Line,
        "confidence" => FindingsSortField.Confidence,
        _ => FindingsSortField.Severity
    };
}

public partial class Program;
