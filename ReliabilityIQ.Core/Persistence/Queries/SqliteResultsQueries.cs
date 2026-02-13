using Dapper;
using Microsoft.Data.Sqlite;

namespace ReliabilityIQ.Core.Persistence.Queries;

public sealed class SqliteResultsQueries
{
    private readonly Func<SqliteConnection> _connectionFactory;

    public SqliteResultsQueries(Func<SqliteConnection> connectionFactory)
    {
        _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
    }

    public async Task<IReadOnlyList<RunListItem>> GetAllRuns(CancellationToken cancellationToken = default)
    {
        const string sql = """
                           SELECT
                               sr.run_id AS RunId,
                               sr.repo_root AS RepoRoot,
                               sr.commit_sha AS CommitSha,
                               sr.started_at AS StartedAt,
                               sr.ended_at AS EndedAt,
                               sr.tool_version AS ToolVersion,
                               COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount
                           FROM scan_runs sr
                           LEFT JOIN findings f ON f.run_id = sr.run_id
                           GROUP BY sr.run_id, sr.repo_root, sr.commit_sha, sr.started_at, sr.ended_at, sr.tool_version
                           ORDER BY sr.started_at DESC;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<RunRow>(new CommandDefinition(sql, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(MapRunListItem).ToList();
    }

    public async Task<RunDetails?> GetRunById(string runId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               sr.run_id AS RunId,
                               sr.repo_root AS RepoRoot,
                               sr.commit_sha AS CommitSha,
                               sr.started_at AS StartedAt,
                               sr.ended_at AS EndedAt,
                               sr.tool_version AS ToolVersion,
                               COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount
                           FROM scan_runs sr
                           LEFT JOIN findings f ON f.run_id = sr.run_id
                           WHERE sr.run_id = @RunId
                           GROUP BY sr.run_id, sr.repo_root, sr.commit_sha, sr.started_at, sr.ended_at, sr.tool_version;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var row = await connection.QuerySingleOrDefaultAsync<RunRow>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (row is null)
        {
            return null;
        }

        return new RunDetails(
            row.RunId,
            row.RepoRoot,
            row.CommitSha,
            ParseDate(row.StartedAt),
            ParseNullableDate(row.EndedAt),
            row.ToolVersion,
            row.ErrorCount,
            row.WarningCount,
            row.InfoCount);
    }

    public async Task<FindingsPage> GetFindings(string runId, FindingsQueryRequest? request = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var effectiveRequest = request ?? FindingsQueryRequest.Default;
        var safeLimit = Math.Clamp(effectiveRequest.Limit, 1, 500);
        var safeOffset = Math.Max(effectiveRequest.Offset, 0);
        var filters = effectiveRequest.Filters ?? new FindingsQueryFilters();

        var whereClause = "f.run_id = @RunId";
        var parameters = new DynamicParameters();
        parameters.Add("RunId", runId);

        if (!string.IsNullOrWhiteSpace(filters.Severity))
        {
            whereClause += " AND f.severity = @Severity";
            parameters.Add("Severity", filters.Severity);
        }

        if (!string.IsNullOrWhiteSpace(filters.RuleId))
        {
            whereClause += " AND f.rule_id = @RuleId";
            parameters.Add("RuleId", filters.RuleId);
        }

        if (!string.IsNullOrWhiteSpace(filters.FileCategory))
        {
            whereClause += " AND fl.category = @FileCategory";
            parameters.Add("FileCategory", filters.FileCategory);
        }

        if (!string.IsNullOrWhiteSpace(filters.Language))
        {
            whereClause += " AND fl.language = @Language";
            parameters.Add("Language", filters.Language);
        }

        if (!string.IsNullOrWhiteSpace(filters.PathPrefix))
        {
            whereClause += " AND f.file_path LIKE @PathPrefix";
            parameters.Add("PathPrefix", $"{filters.PathPrefix.Trim()}%");
        }

        var sortColumn = GetSortColumn(effectiveRequest.SortField);
        var sortDirection = effectiveRequest.SortDescending ? "DESC" : "ASC";

        var totalSql = "SELECT COUNT(*) FROM findings WHERE run_id = @RunId;";

        var filteredSql = $"""
                           SELECT COUNT(*)
                           FROM findings f
                           INNER JOIN files fl ON fl.file_id = f.file_id
                           WHERE {whereClause};
                           """;

        var pageSql = $"""
                       SELECT
                           f.finding_id AS FindingId,
                           f.rule_id AS RuleId,
                           f.file_path AS FilePath,
                           f.line AS Line,
                           f."column" AS "Column",
                           f.message AS Message,
                           f.snippet AS Snippet,
                           f.severity AS Severity,
                           f.confidence AS Confidence,
                           fl.category AS FileCategory,
                           fl.language AS Language
                       FROM findings f
                       INNER JOIN files fl ON fl.file_id = f.file_id
                       WHERE {whereClause}
                       ORDER BY {sortColumn} {sortDirection}, f.finding_id ASC
                       LIMIT @Limit OFFSET @Offset;
                       """;

        parameters.Add("Limit", safeLimit);
        parameters.Add("Offset", safeOffset);

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var totalCount = await connection.ExecuteScalarAsync<int>(
            new CommandDefinition(totalSql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var filteredCount = await connection.ExecuteScalarAsync<int>(
            new CommandDefinition(filteredSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var items = await connection.QueryAsync<FindingListItem>(
            new CommandDefinition(pageSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return new FindingsPage(totalCount, filteredCount, items.ToList());
    }

    public async Task<IReadOnlyList<FileSummaryItem>> GetFileSummary(string runId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               f.file_path AS FilePath,
                               fl.category AS Category,
                               fl.language AS Language,
                               COUNT(*) AS FindingCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount
                           FROM findings f
                           INNER JOIN files fl ON fl.file_id = f.file_id
                           WHERE f.run_id = @RunId
                           GROUP BY f.file_path, fl.category, fl.language
                           ORDER BY FindingCount DESC, f.file_path ASC;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<FileSummaryItem>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    public async Task<IReadOnlyList<RuleSummaryItem>> GetRuleSummary(string runId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               f.rule_id AS RuleId,
                               COALESCE(r.title, f.rule_id) AS Title,
                               COUNT(*) AS FindingCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount
                           FROM findings f
                           LEFT JOIN rules r ON r.rule_id = f.rule_id
                           WHERE f.run_id = @RunId
                           GROUP BY f.rule_id, r.title
                           ORDER BY FindingCount DESC, f.rule_id ASC;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<RuleSummaryItem>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    private static string GetSortColumn(FindingsSortField sortField) => sortField switch
    {
        FindingsSortField.Severity => "CASE f.severity WHEN 'Error' THEN 0 WHEN 'Warning' THEN 1 ELSE 2 END",
        FindingsSortField.RuleId => "f.rule_id",
        FindingsSortField.FilePath => "f.file_path",
        FindingsSortField.Line => "f.line",
        FindingsSortField.Confidence => "CASE f.confidence WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END",
        _ => "CASE f.severity WHEN 'Error' THEN 0 WHEN 'Warning' THEN 1 ELSE 2 END"
    };

    private static RunListItem MapRunListItem(RunRow row) => new(
        row.RunId,
        row.RepoRoot,
        row.CommitSha,
        ParseDate(row.StartedAt),
        ParseNullableDate(row.EndedAt),
        row.ToolVersion,
        row.ErrorCount,
        row.WarningCount,
        row.InfoCount);

    private static DateTimeOffset ParseDate(string value)
    {
        if (DateTimeOffset.TryParse(value, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException($"Unable to parse date value '{value}'.");
    }

    private static DateTimeOffset? ParseNullableDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParse(value, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private sealed record RunRow(
        string RunId,
        string RepoRoot,
        string? CommitSha,
        string StartedAt,
        string? EndedAt,
        string ToolVersion,
        int ErrorCount,
        int WarningCount,
        int InfoCount);
}
