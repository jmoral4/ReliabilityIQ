using ReliabilityIQ.Core.Persistence.Queries;
using ReliabilityIQ.Web.Configuration;
using ReliabilityIQ.Web.Data;
using ReliabilityIQ.Web.MagicStrings;

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
        RulePrefix: NullIfEmpty(request.Query["rulePrefix"].ToString()),
        Confidence: NullIfEmpty(request.Query["confidence"].ToString()),
        FileCategory: NullIfEmpty(request.Query["fileCategory"].ToString()),
        Language: NullIfEmpty(request.Query["language"].ToString()),
        PathPrefix: NullIfEmpty(request.Query["pathPrefix"].ToString()),
        IncludeSuppressed: ParseBool(request.Query["includeSuppressed"]));

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
            fileId = item.FileId,
            ruleId = item.RuleId,
            ruleTitle = item.RuleTitle,
            ruleDescription = item.RuleDescription,
            filePath = item.FilePath,
            line = item.Line,
            column = item.Column,
            message = item.Message,
            snippet = item.Snippet,
            severity = item.Severity,
            confidence = item.Confidence,
            fileCategory = item.FileCategory,
            language = item.Language,
            metadata = item.Metadata,
            astConfirmed = item.AstConfirmed,
            isSuppressed = item.IsSuppressed,
            suppressionReason = item.SuppressionReason
        })
    });
});

app.MapGet("/api/run/{runId}/magic-strings", async (
    string runId,
    HttpRequest request,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var draw = ParseInt(request.Query["draw"], 1);
    var minScore = ParseDouble(request.Query["minScore"], 0d);
    var minOccurrences = Math.Max(1, ParseInt(request.Query["minOccurrences"], 2));
    var topN = Math.Clamp(ParseInt(request.Query["topN"], 25), 1, 100);
    var scope = NullIfEmpty(request.Query["scope"].ToString()) ?? "overall";
    var language = NullIfEmpty(request.Query["language"].ToString());
    var pathPrefix = NullIfEmpty(request.Query["pathPrefix"].ToString());

    var findings = await queries.GetFindingsByRulePrefix(runId, "magic-string.", includeSuppressed: true, cancellationToken).ConfigureAwait(false);
    var projected = MagicStringsProjection.BuildCandidates(findings);
    var filtered = MagicStringsProjection.ApplyFilters(projected, minScore, minOccurrences, language, pathPrefix);
    var scoped = MagicStringsProjection.ApplyScope(filtered, scope, topN);

    return Results.Ok(new
    {
        draw,
        recordsTotal = projected.Count,
        recordsFiltered = filtered.Count,
        data = scoped.Select(candidate => new
        {
            findingId = candidate.FindingId,
            ruleId = candidate.RuleId,
            literal = candidate.Literal,
            magicScore = candidate.MagicScore,
            occurrenceCount = candidate.OccurrenceCount,
            topFilePath = candidate.TopFilePath,
            topLine = candidate.TopLine,
            topColumn = candidate.TopColumn,
            module = candidate.Module,
            contextSummary = candidate.ContextSummary,
            languages = candidate.Languages,
            occurrences = candidate.Occurrences
        })
    });
});

app.MapGet("/api/run/{runId}/magic-strings/modules", async (
    string runId,
    HttpRequest request,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var minScore = ParseDouble(request.Query["minScore"], 0d);
    var minOccurrences = Math.Max(1, ParseInt(request.Query["minOccurrences"], 2));
    var topN = Math.Clamp(ParseInt(request.Query["topN"], 10), 1, 100);
    var language = NullIfEmpty(request.Query["language"].ToString());
    var pathPrefix = NullIfEmpty(request.Query["pathPrefix"].ToString());

    var findings = await queries.GetFindingsByRulePrefix(runId, "magic-string.", includeSuppressed: true, cancellationToken).ConfigureAwait(false);
    var projected = MagicStringsProjection.BuildCandidates(findings);
    var filtered = MagicStringsProjection.ApplyFilters(projected, minScore, minOccurrences, language, pathPrefix);
    var moduleGroups = MagicStringsProjection.BuildModuleGroups(filtered, topN);

    return Results.Ok(moduleGroups.Select(group => new
    {
        module = group.Module,
        totalCandidates = group.TotalCandidates,
        candidates = group.Candidates.Select(candidate => new
        {
            findingId = candidate.FindingId,
            ruleId = candidate.RuleId,
            literal = candidate.Literal,
            magicScore = candidate.MagicScore,
            occurrenceCount = candidate.OccurrenceCount,
            topFilePath = candidate.TopFilePath,
            topLine = candidate.TopLine,
            topColumn = candidate.TopColumn,
            languages = candidate.Languages
        })
    }));
});

app.MapGet("/api/run/{runId}/magic-strings/filters", async (
    string runId,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var findings = await queries.GetFindingsByRulePrefix(runId, "magic-string.", includeSuppressed: true, cancellationToken).ConfigureAwait(false);
    var projected = MagicStringsProjection.BuildCandidates(findings);
    var languages = projected
        .SelectMany(candidate => candidate.Languages)
        .Where(language => !string.IsNullOrWhiteSpace(language))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(language => language, StringComparer.OrdinalIgnoreCase)
        .ToList();

    var modules = projected
        .Select(candidate => candidate.Module)
        .Where(module => !string.IsNullOrWhiteSpace(module))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(module => module, StringComparer.OrdinalIgnoreCase)
        .ToList();

    return Results.Ok(new
    {
        languages,
        modules,
        totalCandidates = projected.Count
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

static double ParseDouble(string? value, double fallback)
{
    return double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
        ? parsed
        : fallback;
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

static bool ParseBool(string? value)
{
    return bool.TryParse(value, out var parsed) && parsed;
}

public partial class Program;
