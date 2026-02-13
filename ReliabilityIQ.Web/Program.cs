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

app.MapGet("/api/run/{runId}/deploy", async (
    string runId,
    HttpRequest request,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var draw = ParseInt(request.Query["draw"], 1);
    var start = ParseInt(request.Query["start"], 0);
    var length = ParseInt(request.Query["length"], 25);

    var sortColumnIndex = ParseInt(request.Query["order[0][column]"], 2);
    var sortDirectionRaw = request.Query["order[0][dir]"].ToString();
    var sortDirection = string.Equals(sortDirectionRaw, "desc", StringComparison.OrdinalIgnoreCase);
    var sortFieldRaw = request.Query[$"columns[{sortColumnIndex}][name]"].ToString();

    var requestModel = new DeployFindingsQueryRequest(
        Offset: start,
        Limit: length,
        SortField: ParseDeploySortField(sortFieldRaw),
        SortDescending: sortDirection,
        Filters: new DeployFindingsQueryFilters(
            ArtifactType: NullIfEmpty(request.Query["artifactType"].ToString()),
            RuleSubcategory: NullIfEmpty(request.Query["subcategory"].ToString()),
            Severity: NullIfEmpty(request.Query["severity"].ToString()),
            IncludeSuppressed: ParseBool(request.Query["includeSuppressed"])));

    var page = await queries.GetDeployFindings(runId, requestModel, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new
    {
        draw,
        recordsTotal = page.TotalCount,
        recordsFiltered = page.FilteredCount,
        data = page.Items.Select(item => new
        {
            findingId = item.FindingId,
            fileId = item.FileId,
            artifactType = item.ArtifactType,
            ruleSubcategory = item.RuleSubcategory,
            ruleId = item.RuleId,
            ruleTitle = item.RuleTitle,
            ruleDescription = item.RuleDescription,
            filePath = item.FilePath,
            line = item.Line,
            column = item.Column,
            severity = item.Severity,
            message = item.Message,
            snippet = item.Snippet,
            locationPath = item.LocationPath,
            metadata = item.Metadata,
            isSuppressed = item.IsSuppressed
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

app.MapGet("/api/run/{runId}/churn", async (
    string runId,
    HttpRequest request,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var draw = ParseInt(request.Query["draw"], 1);
    var start = ParseInt(request.Query["start"], 0);
    var length = ParseInt(request.Query["length"], 25);

    var sortColumnIndex = ParseInt(request.Query["order[0][column]"], 1);
    var sortDirectionRaw = request.Query["order[0][dir]"].ToString();
    var sortDirection = string.Equals(sortDirectionRaw, "desc", StringComparison.OrdinalIgnoreCase);
    var sortFieldRaw = request.Query[$"columns[{sortColumnIndex}][name]"].ToString();

    var minChurn = ParseNullableDouble(request.Query["minChurnScore"]);
    var maxStale = ParseNullableDouble(request.Query["maxStaleScore"]);
    var pathPrefix = NullIfEmpty(request.Query["pathPrefix"].ToString());

    var requestModel = new GitMetricsQueryRequest(
        Offset: start,
        Limit: length,
        SortField: ParseGitMetricsSortField(sortFieldRaw),
        SortDescending: sortDirection,
        Filters: new GitMetricsQueryFilters(minChurn, maxStale, pathPrefix));

    var page = await queries.GetGitMetrics(runId, requestModel, cancellationToken).ConfigureAwait(false);

    return Results.Ok(new
    {
        draw,
        recordsTotal = page.TotalCount,
        recordsFiltered = page.FilteredCount,
        data = page.Items.Select(item => new
        {
            fileId = item.FileId,
            filePath = item.FilePath,
            churnScore = item.ChurnScore,
            staleScore = item.StaleScore,
            commits90d = item.Commits90d,
            authors365d = item.Authors365d,
            ownershipConcentration = item.OwnershipConcentration,
            topAuthor = item.TopAuthor,
            topAuthorPct = item.TopAuthorPct,
            lastCommitAt = item.LastCommitAt,
            isOrphaned = item.IsOrphaned > 0
        })
    });
});

app.MapGet("/api/run/{runId}/churn/ownership", async (
    string runId,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var page = await queries.GetGitMetrics(
        runId,
        new GitMetricsQueryRequest(
            Offset: 0,
            Limit: 200,
            SortField: GitMetricsSortField.OwnershipConcentration,
            SortDescending: true,
            Filters: new GitMetricsQueryFilters()),
        cancellationToken).ConfigureAwait(false);

    var ownershipRows = page.Items
        .Where(item => item.OwnershipConcentration >= 0.7d)
        .Take(50)
        .Select(item => new
        {
            fileId = item.FileId,
            filePath = item.FilePath,
            topAuthor = item.TopAuthor,
            topAuthorPct = item.TopAuthorPct,
            authors365d = item.Authors365d,
            lastCommitAt = item.LastCommitAt,
            isOrphaned = item.IsOrphaned > 0
        });

    return Results.Ok(ownershipRows);
});

app.MapGet("/api/run/{runId}/heatmap/treemap", async (
    string runId,
    string? metric,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var selectedMetric = ParseHeatmapMetric(metric);
    var tree = await queries.GetTreemapData(runId, selectedMetric, cancellationToken).ConfigureAwait(false);
    var maxMetric = FindMaxMetricValue(tree);

    return Results.Ok(new
    {
        metric = selectedMetric.ToString(),
        metricValueMax = maxMetric,
        root = tree
    });
});

app.MapGet("/api/run/{runId}/heatmap/directories", async (
    string runId,
    string? metric,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var selectedMetric = ParseHeatmapMetric(metric);
    var directories = await queries.GetDirectoryAggregates(runId, selectedMetric, cancellationToken).ConfigureAwait(false);
    return Results.Ok(directories);
});

app.MapGet("/api/run/{runId}/heatmap/directory-details", async (
    string runId,
    string? metric,
    string? path,
    SqliteResultsQueries queries,
    CancellationToken cancellationToken) =>
{
    var selectedMetric = ParseHeatmapMetric(metric);
    var details = await queries.GetDirectoryDrilldown(runId, path ?? ".", selectedMetric, cancellationToken).ConfigureAwait(false);
    if (details is null)
    {
        return Results.NotFound();
    }

    return Results.Ok(details);
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

static double? ParseNullableDouble(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    return double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
        ? parsed
        : null;
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

static DeployFindingsSortField ParseDeploySortField(string? sortField)
{
    return sortField?.Trim().ToLowerInvariant() switch
    {
        "artifacttype" => DeployFindingsSortField.ArtifactType,
        "severity" => DeployFindingsSortField.Severity,
        "ruleid" => DeployFindingsSortField.RuleId,
        "filepath" => DeployFindingsSortField.FilePath,
        "locationpath" => DeployFindingsSortField.LocationPath,
        _ => DeployFindingsSortField.Severity
    };
}

static GitMetricsSortField ParseGitMetricsSortField(string? sortField)
{
    return sortField?.Trim().ToLowerInvariant() switch
    {
        "filepath" => GitMetricsSortField.FilePath,
        "churnscore" => GitMetricsSortField.ChurnScore,
        "stalescore" => GitMetricsSortField.StaleScore,
        "commits90d" => GitMetricsSortField.Commits90d,
        "authors365d" => GitMetricsSortField.Authors365d,
        "ownershipconcentration" => GitMetricsSortField.OwnershipConcentration,
        "lastcommitat" => GitMetricsSortField.LastCommitAt,
        _ => GitMetricsSortField.ChurnScore
    };
}

static HeatmapMetric ParseHeatmapMetric(string? metric)
{
    return metric?.Trim().ToLowerInvariant() switch
    {
        "churnhotspots" => HeatmapMetric.ChurnHotspots,
        "stalerisk" => HeatmapMetric.StaleRisk,
        "ownershiprisk" => HeatmapMetric.OwnershipRisk,
        "portabilityblockers" => HeatmapMetric.PortabilityBlockers,
        "findingdensity" => HeatmapMetric.FindingDensity,
        _ => HeatmapMetric.ChurnHotspots
    };
}

static double FindMaxMetricValue(TreemapNode root)
{
    var max = root.MetricValue;
    foreach (var child in root.Children)
    {
        max = Math.Max(max, FindMaxMetricValue(child));
    }

    return max;
}

public partial class Program;
