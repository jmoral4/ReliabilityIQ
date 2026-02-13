using Dapper;
using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Text;

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
            ToInt(row.ErrorCount),
            ToInt(row.WarningCount),
            ToInt(row.InfoCount));
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

        if (!string.IsNullOrWhiteSpace(filters.RulePrefix))
        {
            whereClause += " AND f.rule_id LIKE @RulePrefix";
            parameters.Add("RulePrefix", $"{filters.RulePrefix.Trim()}%");
        }

        if (!string.IsNullOrWhiteSpace(filters.Confidence))
        {
            whereClause += " AND f.confidence = @Confidence";
            parameters.Add("Confidence", filters.Confidence);
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

        if (!filters.IncludeSuppressed)
        {
            whereClause += " AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";
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
                           f.file_id AS FileId,
                           f.rule_id AS RuleId,
                           COALESCE(r.title, f.rule_id) AS RuleTitle,
                           COALESCE(r.description, '') AS RuleDescription,
                           f.file_path AS FilePath,
                           f.line AS Line,
                           f."column" AS "Column",
                           f.message AS Message,
                           f.snippet AS Snippet,
                           f.severity AS Severity,
                           f.confidence AS Confidence,
                           fl.category AS FileCategory,
                           fl.language AS Language,
                           f.metadata AS Metadata,
                           CASE
                               WHEN COALESCE(f.metadata, '') LIKE '%\"astConfirmed\":true%' THEN 1
                               ELSE 0
                           END AS AstConfirmed,
                           CASE
                               WHEN COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%' THEN 1
                               ELSE 0
                           END AS IsSuppressed,
                           CASE
                               WHEN COALESCE(f.metadata, '') LIKE '%\"suppressionReason\":\"%' THEN
                                   substr(
                                       f.metadata,
                                       instr(f.metadata, '\"suppressionReason\":\"') + length('\"suppressionReason\":\"'),
                                       instr(substr(f.metadata, instr(f.metadata, '\"suppressionReason\":\"') + length('\"suppressionReason\":\"')), '\"') - 1)
                               WHEN COALESCE(f.metadata, '') LIKE '%\"reason\":\"%' THEN
                                   substr(
                                       f.metadata,
                                       instr(f.metadata, '\"reason\":\"') + length('\"reason\":\"'),
                                       instr(substr(f.metadata, instr(f.metadata, '\"reason\":\"') + length('\"reason\":\"')), '\"') - 1)
                               ELSE NULL
                           END AS SuppressionReason
                       FROM findings f
                       INNER JOIN files fl ON fl.file_id = f.file_id
                       LEFT JOIN rules r ON r.rule_id = f.rule_id
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

    public async Task<IReadOnlyList<FindingListItem>> GetFindingsByRulePrefix(
        string runId,
        string rulePrefix,
        bool includeSuppressed = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePrefix);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       f.finding_id AS FindingId,
                       f.file_id AS FileId,
                       f.rule_id AS RuleId,
                       COALESCE(r.title, f.rule_id) AS RuleTitle,
                       COALESCE(r.description, '') AS RuleDescription,
                       f.file_path AS FilePath,
                       f.line AS Line,
                       f."column" AS "Column",
                       f.message AS Message,
                       f.snippet AS Snippet,
                       f.severity AS Severity,
                       f.confidence AS Confidence,
                       fl.category AS FileCategory,
                       fl.language AS Language,
                       f.metadata AS Metadata,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"astConfirmed\":true%' THEN 1
                           ELSE 0
                       END AS AstConfirmed,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%' THEN 1
                           ELSE 0
                       END AS IsSuppressed,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"suppressionReason\":\"%' THEN
                               substr(
                                   f.metadata,
                                   instr(f.metadata, '\"suppressionReason\":\"') + length('\"suppressionReason\":\"'),
                                   instr(substr(f.metadata, instr(f.metadata, '\"suppressionReason\":\"') + length('\"suppressionReason\":\"')), '\"') - 1)
                           WHEN COALESCE(f.metadata, '') LIKE '%\"reason\":\"%' THEN
                               substr(
                                   f.metadata,
                                   instr(f.metadata, '\"reason\":\"') + length('\"reason\":\"'),
                                   instr(substr(f.metadata, instr(f.metadata, '\"reason\":\"') + length('\"reason\":\"')), '\"') - 1)
                           ELSE NULL
                       END AS SuppressionReason
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   LEFT JOIN rules r ON r.rule_id = f.rule_id
                   WHERE f.run_id = @RunId
                     AND f.rule_id LIKE @RulePrefix
                     {suppressionClause}
                   ORDER BY f.rule_id ASC, f.finding_id ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<FindingListItem>(
            new CommandDefinition(
                sql,
                new { RunId = runId, RulePrefix = $"{rulePrefix.Trim()}%" },
                cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    public async Task<IReadOnlyList<FileSummaryItem>> GetFileSummary(string runId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               f.file_id AS FileId,
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
                           GROUP BY f.file_id, f.file_path, fl.category, fl.language
                           ORDER BY FindingCount DESC, f.file_path ASC;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<FileSummaryRow>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(MapFileSummaryItem).ToList();
    }

    public async Task<IReadOnlyList<RuleSummaryItem>> GetRuleSummary(string runId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               f.rule_id AS RuleId,
                               COALESCE(r.title, f.rule_id) AS Title,
                               r.description AS Description,
                               COUNT(*) AS FindingCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                               COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount
                           FROM findings f
                           LEFT JOIN rules r ON r.rule_id = f.rule_id
                           WHERE f.run_id = @RunId
                           GROUP BY f.rule_id, r.title, r.description
                           ORDER BY FindingCount DESC, f.rule_id ASC;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<RuleSummaryItem>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    public async Task<FileDetailItem?> GetFileById(string runId, long fileId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               fl.file_id AS FileId,
                               fl.path AS FilePath,
                               fl.category AS Category,
                               fl.language AS Language,
                               fl.size_bytes AS SizeBytes,
                               fl.hash AS Hash
                           FROM files fl
                           WHERE fl.run_id = @RunId AND fl.file_id = @FileId
                           LIMIT 1;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        return await connection.QuerySingleOrDefaultAsync<FileDetailItem>(
            new CommandDefinition(sql, new { RunId = runId, FileId = fileId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<FindingListItem>> GetFindingsForFile(string runId, long fileId, bool includeSuppressed = true, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       f.finding_id AS FindingId,
                       f.file_id AS FileId,
                       f.rule_id AS RuleId,
                       COALESCE(r.title, f.rule_id) AS RuleTitle,
                       COALESCE(r.description, '') AS RuleDescription,
                       f.file_path AS FilePath,
                       f.line AS Line,
                       f."column" AS "Column",
                       f.message AS Message,
                       f.snippet AS Snippet,
                       f.severity AS Severity,
                       f.confidence AS Confidence,
                       fl.category AS FileCategory,
                       fl.language AS Language,
                       f.metadata AS Metadata,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"astConfirmed\":true%' THEN 1
                           ELSE 0
                       END AS AstConfirmed,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%' THEN 1
                           ELSE 0
                       END AS IsSuppressed,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"suppressionReason\":\"%' THEN
                               substr(
                                   f.metadata,
                                   instr(f.metadata, '\"suppressionReason\":\"') + length('\"suppressionReason\":\"'),
                                   instr(substr(f.metadata, instr(f.metadata, '\"suppressionReason\":\"') + length('\"suppressionReason\":\"')), '\"') - 1)
                           WHEN COALESCE(f.metadata, '') LIKE '%\"reason\":\"%' THEN
                               substr(
                                   f.metadata,
                                   instr(f.metadata, '\"reason\":\"') + length('\"reason\":\"'),
                                   instr(substr(f.metadata, instr(f.metadata, '\"reason\":\"') + length('\"reason\":\"')), '\"') - 1)
                           ELSE NULL
                       END AS SuppressionReason
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   LEFT JOIN rules r ON r.rule_id = f.rule_id
                   WHERE f.run_id = @RunId
                     AND f.file_id = @FileId
                     {suppressionClause}
                   ORDER BY f.line ASC, f."column" ASC, f.finding_id ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<FindingListItem>(
            new CommandDefinition(sql, new { RunId = runId, FileId = fileId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    public async Task<IReadOnlyList<ConfidenceSummaryItem>> GetConfidenceSummary(string runId, bool includeSuppressed = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       f.confidence AS Confidence,
                       COUNT(*) AS FindingCount
                   FROM findings f
                   WHERE f.run_id = @RunId
                     {suppressionClause}
                   GROUP BY f.confidence
                   ORDER BY CASE f.confidence
                       WHEN 'High' THEN 0
                       WHEN 'Medium' THEN 1
                       ELSE 2
                   END ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<ConfidenceSummaryItem>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    public async Task<IReadOnlyList<LanguageSummaryItem>> GetLanguageSummary(string runId, bool includeSuppressed = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       COALESCE(NULLIF(fl.language, ''), 'unknown') AS Language,
                       COUNT(*) AS FindingCount
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   WHERE f.run_id = @RunId
                     {suppressionClause}
                   GROUP BY COALESCE(NULLIF(fl.language, ''), 'unknown')
                   ORDER BY FindingCount DESC, Language ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<LanguageSummaryItem>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.ToList();
    }

    public async Task<AstSummary> GetAstSummary(string runId, bool includeSuppressed = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       COALESCE(SUM(CASE WHEN COALESCE(f.metadata, '') LIKE '%\"astConfirmed\":true%' THEN 1 ELSE 0 END), 0) AS AstConfirmedCount,
                       COALESCE(SUM(CASE WHEN COALESCE(f.metadata, '') NOT LIKE '%\"astConfirmed\":true%' THEN 1 ELSE 0 END), 0) AS RegexOnlyCount
                   FROM findings f
                   WHERE f.run_id = @RunId
                     {suppressionClause};
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        return await connection.QuerySingleAsync<AstSummary>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<FileSummaryItem>> GetTopFilesByHighConfidence(string runId, int limit = 10, bool includeSuppressed = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        var safeLimit = Math.Clamp(limit, 1, 200);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       f.file_id AS FileId,
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
                     AND f.confidence = 'High'
                     {suppressionClause}
                   GROUP BY f.file_id, f.file_path, fl.category, fl.language
                   ORDER BY FindingCount DESC, f.file_path ASC
                   LIMIT @Limit;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<FileSummaryRow>(
            new CommandDefinition(sql, new { RunId = runId, Limit = safeLimit }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(MapFileSummaryItem).ToList();
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
        ToInt(row.ErrorCount),
        ToInt(row.WarningCount),
        ToInt(row.InfoCount));

    private static FileSummaryItem MapFileSummaryItem(FileSummaryRow row) => new(
        row.FileId,
        row.FilePath,
        row.Category,
        row.Language,
        ToLong(row.FindingCount),
        ToLong(row.ErrorCount),
        ToLong(row.WarningCount),
        ToLong(row.InfoCount));

    private static int ToInt(long value)
    {
        return value switch
        {
            > int.MaxValue => int.MaxValue,
            < int.MinValue => int.MinValue,
            _ => (int)value
        };
    }

    private static long ToLong(object? value)
    {
        return value switch
        {
            null => 0L,
            long longValue => longValue,
            int intValue => intValue,
            short shortValue => shortValue,
            byte byteValue => byteValue,
            decimal decimalValue => decimal.ToInt64(decimalValue),
            double doubleValue => checked((long)doubleValue),
            float floatValue => checked((long)floatValue),
            string stringValue when long.TryParse(stringValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => parsed,
            byte[] bytes => ParseLong(bytes),
            _ => Convert.ToInt64(value, CultureInfo.InvariantCulture)
        };
    }

    private static long ParseLong(byte[] bytes)
    {
        if (bytes.Length == sizeof(long))
        {
            return BitConverter.ToInt64(bytes, 0);
        }

        var text = Encoding.UTF8.GetString(bytes);
        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException($"Unable to convert blob value of length {bytes.Length} to Int64.");
    }

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
        long ErrorCount,
        long WarningCount,
        long InfoCount);

    private sealed class FileSummaryRow
    {
        public long FileId { get; set; }

        public string FilePath { get; set; } = string.Empty;

        public string? Category { get; set; }

        public string? Language { get; set; }

        public object? FindingCount { get; set; }

        public object? ErrorCount { get; set; }

        public object? WarningCount { get; set; }

        public object? InfoCount { get; set; }
    }
}
