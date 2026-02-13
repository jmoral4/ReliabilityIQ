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

    public async Task<DeployFindingsPage> GetDeployFindings(
        string runId,
        DeployFindingsQueryRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var effectiveRequest = request ?? DeployFindingsQueryRequest.Default;
        var safeLimit = Math.Clamp(effectiveRequest.Limit, 1, 500);
        var safeOffset = Math.Max(effectiveRequest.Offset, 0);
        var filters = effectiveRequest.Filters ?? new DeployFindingsQueryFilters();

        var whereClause = "f.run_id = @RunId AND f.rule_id LIKE 'deploy.%'";
        var parameters = new DynamicParameters();
        parameters.Add("RunId", runId);

        if (!string.IsNullOrWhiteSpace(filters.ArtifactType))
        {
            whereClause += " AND " + GetArtifactTypeSqlExpression() + " = @ArtifactType";
            parameters.Add("ArtifactType", filters.ArtifactType.Trim());
        }

        if (!string.IsNullOrWhiteSpace(filters.RuleSubcategory))
        {
            whereClause += " AND " + GetDeploySubcategorySqlExpression() + " = @RuleSubcategory";
            parameters.Add("RuleSubcategory", filters.RuleSubcategory.Trim());
        }

        if (!string.IsNullOrWhiteSpace(filters.Severity))
        {
            whereClause += " AND f.severity = @Severity";
            parameters.Add("Severity", filters.Severity.Trim());
        }

        if (!filters.IncludeSuppressed)
        {
            whereClause += " AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";
        }

        var totalSql = "SELECT COUNT(*) FROM findings WHERE run_id = @RunId AND rule_id LIKE 'deploy.%';";
        var filteredSql = $"""
                           SELECT COUNT(*)
                           FROM findings f
                           INNER JOIN files fl ON fl.file_id = f.file_id
                           WHERE {whereClause};
                           """;

        var sortColumn = GetDeploySortColumn(effectiveRequest.SortField);
        var sortDirection = effectiveRequest.SortDescending ? "DESC" : "ASC";

        var pageSql = $"""
                       SELECT
                           f.finding_id AS FindingId,
                           f.file_id AS FileId,
                           {GetArtifactTypeSqlExpression()} AS ArtifactType,
                           {GetDeploySubcategorySqlExpression()} AS RuleSubcategory,
                           f.rule_id AS RuleId,
                           COALESCE(r.title, f.rule_id) AS RuleTitle,
                           COALESCE(r.description, '') AS RuleDescription,
                           f.file_path AS FilePath,
                           f.line AS Line,
                           f."column" AS "Column",
                           f.severity AS Severity,
                           f.message AS Message,
                           f.snippet AS Snippet,
                           {GetArtifactPathSqlExpression()} AS LocationPath,
                           f.metadata AS Metadata,
                           CASE
                               WHEN COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%' THEN 1
                               ELSE 0
                           END AS IsSuppressed
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

        var items = await connection.QueryAsync<DeployFindingListItem>(
            new CommandDefinition(pageSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return new DeployFindingsPage(totalCount, filteredCount, items.ToList());
    }

    public async Task<IReadOnlyList<DeploymentSeveritySummaryItem>> GetDeploymentSeveritySummary(
        string runId,
        bool includeSuppressed = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       {GetArtifactTypeSqlExpression()} AS ArtifactType,
                       COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                       COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                       COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   WHERE f.run_id = @RunId
                     AND f.rule_id LIKE 'deploy.%'
                     {suppressionClause}
                   GROUP BY {GetArtifactTypeSqlExpression()}
                   ORDER BY ArtifactType ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<DeploymentSeveritySummaryRow>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(row => new DeploymentSeveritySummaryItem(
            row.ArtifactType,
            ToLong(row.ErrorCount),
            ToLong(row.WarningCount),
            ToLong(row.InfoCount))).ToList();
    }

    public async Task<IReadOnlyList<DeploymentArtifactRiskItem>> GetTopDeploymentArtifactsByRisk(
        string runId,
        int limit = 5,
        bool includeSuppressed = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        var safeLimit = Math.Clamp(limit, 1, 100);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT
                       f.file_id AS FileId,
                       f.file_path AS FilePath,
                       {GetArtifactTypeSqlExpression()} AS ArtifactType,
                       COALESCE(SUM(CASE WHEN f.severity = 'Error' THEN 1 ELSE 0 END), 0) AS ErrorCount,
                       COALESCE(SUM(CASE WHEN f.severity = 'Warning' THEN 1 ELSE 0 END), 0) AS WarningCount,
                       COALESCE(SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END), 0) AS InfoCount,
                       COALESCE(SUM(CASE
                           WHEN f.severity = 'Error' THEN 5
                           WHEN f.severity = 'Warning' THEN 2
                           ELSE 1
                       END), 0) AS RiskScore
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   WHERE f.run_id = @RunId
                     AND f.rule_id LIKE 'deploy.%'
                     {suppressionClause}
                   GROUP BY f.file_id, f.file_path, {GetArtifactTypeSqlExpression()}
                   ORDER BY RiskScore DESC, f.file_path ASC
                   LIMIT @Limit;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.QueryAsync<DeploymentArtifactRiskRow>(
            new CommandDefinition(sql, new { RunId = runId, Limit = safeLimit }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(row => new DeploymentArtifactRiskItem(
            row.FileId,
            row.FilePath,
            row.ArtifactType,
            ToLong(row.ErrorCount),
            ToLong(row.WarningCount),
            ToLong(row.InfoCount),
            ToDouble(row.RiskScore))).ToList();
    }

    public async Task<long> GetDeploymentParameterizationOpportunityCount(
        string runId,
        bool includeSuppressed = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var suppressionClause = includeSuppressed
            ? string.Empty
            : "AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var sql = $"""
                   SELECT COUNT(*)
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   WHERE f.run_id = @RunId
                     AND f.rule_id LIKE 'deploy.%'
                     AND {GetDeploySubcategorySqlExpression()} = 'hardcoded-values'
                     {suppressionClause};
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        return await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
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

        var rows = await connection.QueryAsync<RuleSummaryRow>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(MapRuleSummaryItem).ToList();
    }

    public async Task<IReadOnlyList<RuleCatalogItem>> GetRuleCatalog(
        string? category = null,
        CancellationToken cancellationToken = default)
    {
        var whereClause = string.Empty;
        var parameters = new DynamicParameters();
        if (!string.IsNullOrWhiteSpace(category))
        {
            whereClause = "WHERE category = @Category";
            parameters.Add("Category", category.Trim().ToLowerInvariant());
        }

        var sql = $"""
                   SELECT
                       rule_id AS RuleId,
                       title AS Title,
                       default_severity AS DefaultSeverity,
                       description AS Description,
                       category AS Category,
                       CASE
                           WHEN total_findings = 0 THEN 'No Findings'
                           WHEN override_hits > 0 THEN 'Overridden'
                           ELSE 'Enabled'
                       END AS EffectiveState,
                       total_findings AS TotalFindings
                   FROM (
                       SELECT
                           r.rule_id,
                           r.title,
                           r.default_severity,
                           r.description,
                           CASE
                               WHEN r.rule_id LIKE 'portability.%' THEN 'portability'
                               WHEN r.rule_id LIKE 'magic-string.%' THEN 'magic-strings'
                               WHEN r.rule_id LIKE 'churn.%' OR r.rule_id LIKE 'git-history.%' THEN 'churn'
                               WHEN r.rule_id LIKE 'deploy.%' THEN 'deploy'
                               ELSE 'custom'
                           END AS category,
                           COALESCE(s.total_findings, 0) AS total_findings,
                           COALESCE(s.override_hits, 0) AS override_hits
                       FROM rules r
                       LEFT JOIN (
                           SELECT
                               f.rule_id,
                               COUNT(*) AS total_findings,
                               SUM(CASE WHEN f.severity <> COALESCE(rr.default_severity, f.severity) THEN 1 ELSE 0 END) AS override_hits
                           FROM findings f
                           LEFT JOIN rules rr ON rr.rule_id = f.rule_id
                           GROUP BY f.rule_id
                       ) s ON s.rule_id = r.rule_id
                   ) rc
                   {whereClause}
                   ORDER BY category ASC, rule_id ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<RuleCatalogRow>(
            new CommandDefinition(sql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(row => new RuleCatalogItem(
            ToText(row.RuleId),
            ToText(row.Title, ToText(row.RuleId)),
            ToText(row.DefaultSeverity, "Info"),
            ToText(row.Description),
            ToText(row.Category, "custom"),
            ToText(row.EffectiveState, "No Findings"),
            ToLong(row.TotalFindings))).ToList();
    }

    public async Task<IReadOnlyList<RuleFindingAcrossRunsItem>> GetFindingsForRuleAcrossRuns(
        string ruleId,
        int limit = 500,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        var safeLimit = Math.Clamp(limit, 1, 2000);

        const string sql = """
                           SELECT
                               sr.run_id AS RunId,
                               sr.repo_root AS RepoRoot,
                               sr.started_at AS StartedAt,
                               f.file_path AS FilePath,
                               f.line AS Line,
                               f."column" AS "Column",
                               f.severity AS Severity,
                               f.message AS Message,
                               f.confidence AS Confidence,
                               f.fingerprint AS Fingerprint
                           FROM findings f
                           INNER JOIN scan_runs sr ON sr.run_id = f.run_id
                           WHERE f.rule_id = @RuleId
                           ORDER BY sr.started_at DESC, f.finding_id DESC
                           LIMIT @Limit;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<RuleFindingAcrossRunsRow>(
            new CommandDefinition(sql, new { RuleId = ruleId, Limit = safeLimit }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(row => new RuleFindingAcrossRunsItem(
            row.RunId,
            row.RepoRoot,
            ParseDate(row.StartedAt),
            row.FilePath,
            row.Line,
            row.Column,
            row.Severity,
            row.Message,
            row.Confidence,
            row.Fingerprint)).ToList();
    }

    public async Task<SuppressionOverview> GetSuppressionOverview(string runId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        const string suppressedPredicate = "(COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";

        var activeSql = $"""
                         SELECT COUNT(*)
                         FROM findings f
                         WHERE f.run_id = @RunId
                           AND NOT {suppressedPredicate};
                         """;

        var suppressedSql = $"""
                             SELECT COUNT(*)
                             FROM findings f
                             WHERE f.run_id = @RunId
                               AND {suppressedPredicate};
                             """;

        var countsByRuleSql = $"""
                               SELECT
                                   f.rule_id AS RuleId,
                                   COALESCE(r.title, f.rule_id) AS Title,
                                   COUNT(*) AS SuppressedCount
                               FROM findings f
                               LEFT JOIN rules r ON r.rule_id = f.rule_id
                               WHERE f.run_id = @RunId
                                 AND {suppressedPredicate}
                               GROUP BY f.rule_id, r.title
                               ORDER BY SuppressedCount DESC, f.rule_id ASC;
                               """;

        var itemsSql = $"""
                        SELECT
                            f.finding_id AS FindingId,
                            f.file_id AS FileId,
                            f.file_path AS FilePath,
                            f.rule_id AS RuleId,
                            COALESCE(r.title, f.rule_id) AS RuleTitle,
                            f.severity AS Severity,
                            f.confidence AS Confidence,
                            f.message AS Message,
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
                            END AS SuppressionReason,
                            CASE
                                WHEN COALESCE(f.metadata, '') LIKE '%\"suppressionSource\":\"%' THEN
                                    lower(
                                        substr(
                                            f.metadata,
                                            instr(f.metadata, '\"suppressionSource\":\"') + length('\"suppressionSource\":\"'),
                                            instr(substr(f.metadata, instr(f.metadata, '\"suppressionSource\":\"') + length('\"suppressionSource\":\"')), '\"') - 1))
                                WHEN lower(COALESCE(f.metadata, '')) LIKE '%allowlist%' THEN 'allowlist'
                                WHEN lower(COALESCE(f.metadata, '')) LIKE '%inline%' THEN 'inline'
                                ELSE 'config'
                            END AS SuppressionSource,
                            f.metadata AS Metadata
                        FROM findings f
                        LEFT JOIN rules r ON r.rule_id = f.rule_id
                        WHERE f.run_id = @RunId
                          AND {suppressedPredicate}
                        ORDER BY f.rule_id ASC, f.file_path ASC, f.line ASC, f.finding_id ASC;
                        """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var activeCount = await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(activeSql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var suppressedCount = await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(suppressedSql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var byRule = await connection.QueryAsync<SuppressionSummary>(
            new CommandDefinition(countsByRuleSql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var rows = await connection.QueryAsync<SuppressedFindingRow>(
            new CommandDefinition(itemsSql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return new SuppressionOverview(
            ActiveFindingCount: activeCount,
            SuppressedFindingCount: suppressedCount,
            WhatIfTotalFindingCount: activeCount + suppressedCount,
            CountsByRule: byRule.ToList(),
            SuppressedFindings: rows.Select(row => new SuppressedFindingItem(
                row.FindingId,
                row.FileId,
                row.FilePath,
                row.RuleId,
                row.RuleTitle,
                row.Severity,
                row.Confidence,
                row.Message,
                row.SuppressionReason,
                NormalizeSuppressionSource(row.SuppressionSource),
                row.Metadata)).ToList());
    }

    public async Task<RunComparisonResult> GetRunComparison(
        RunComparisonRequest request,
        int detailLimit = 200,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.BaselineRunId);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.TargetRunId);
        var safeLimit = Math.Clamp(detailLimit, 1, 2000);

        const string newCountSql = """
                                   SELECT COUNT(*)
                                   FROM (
                                       SELECT DISTINCT f.fingerprint
                                       FROM findings f
                                       WHERE f.run_id = @TargetRunId
                                         AND COALESCE(f.fingerprint, '') <> ''
                                         AND NOT EXISTS (
                                             SELECT 1
                                             FROM findings b
                                             WHERE b.run_id = @BaselineRunId
                                               AND b.fingerprint = f.fingerprint)
                                   ) x;
                                   """;

        const string fixedCountSql = """
                                     SELECT COUNT(*)
                                     FROM (
                                         SELECT DISTINCT f.fingerprint
                                         FROM findings f
                                         WHERE f.run_id = @BaselineRunId
                                           AND COALESCE(f.fingerprint, '') <> ''
                                           AND NOT EXISTS (
                                               SELECT 1
                                               FROM findings t
                                               WHERE t.run_id = @TargetRunId
                                                 AND t.fingerprint = f.fingerprint)
                                     ) x;
                                     """;

        const string unchangedCountSql = """
                                         SELECT COUNT(*)
                                         FROM (
                                             SELECT DISTINCT t.fingerprint
                                             FROM findings t
                                             INNER JOIN findings b
                                                 ON b.fingerprint = t.fingerprint
                                             WHERE t.run_id = @TargetRunId
                                               AND b.run_id = @BaselineRunId
                                               AND COALESCE(t.fingerprint, '') <> ''
                                         ) x;
                                         """;

        const string newDetailsSql = """
                                     WITH ranked AS (
                                         SELECT
                                             f.fingerprint AS Fingerprint,
                                             f.rule_id AS RuleId,
                                             f.file_path AS FilePath,
                                             f.line AS Line,
                                             f.severity AS Severity,
                                             f.message AS Message,
                                             f.confidence AS Confidence,
                                             ROW_NUMBER() OVER (PARTITION BY f.fingerprint ORDER BY f.finding_id ASC) AS rn
                                         FROM findings f
                                         WHERE f.run_id = @TargetRunId
                                           AND COALESCE(f.fingerprint, '') <> ''
                                           AND NOT EXISTS (
                                               SELECT 1
                                               FROM findings b
                                               WHERE b.run_id = @BaselineRunId
                                                 AND b.fingerprint = f.fingerprint)
                                     )
                                     SELECT Fingerprint, RuleId, FilePath, Line, Severity, Message, Confidence
                                     FROM ranked
                                     WHERE rn = 1
                                     ORDER BY RuleId ASC, FilePath ASC, Line ASC
                                     LIMIT @Limit;
                                     """;

        const string fixedDetailsSql = """
                                       WITH ranked AS (
                                           SELECT
                                               f.fingerprint AS Fingerprint,
                                               f.rule_id AS RuleId,
                                               f.file_path AS FilePath,
                                               f.line AS Line,
                                               f.severity AS Severity,
                                               f.message AS Message,
                                               f.confidence AS Confidence,
                                               ROW_NUMBER() OVER (PARTITION BY f.fingerprint ORDER BY f.finding_id ASC) AS rn
                                           FROM findings f
                                           WHERE f.run_id = @BaselineRunId
                                             AND COALESCE(f.fingerprint, '') <> ''
                                             AND NOT EXISTS (
                                                 SELECT 1
                                                 FROM findings t
                                                 WHERE t.run_id = @TargetRunId
                                                   AND t.fingerprint = f.fingerprint)
                                       )
                                       SELECT Fingerprint, RuleId, FilePath, Line, Severity, Message, Confidence
                                       FROM ranked
                                       WHERE rn = 1
                                       ORDER BY RuleId ASC, FilePath ASC, Line ASC
                                       LIMIT @Limit;
                                       """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var parameters = new { request.BaselineRunId, request.TargetRunId, Limit = safeLimit };

        var newCount = await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(newCountSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var fixedCount = await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(fixedCountSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var unchangedCount = await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(unchangedCountSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var newRows = await connection.QueryAsync<RunComparisonFinding>(
            new CommandDefinition(newDetailsSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var fixedRows = await connection.QueryAsync<RunComparisonFinding>(
            new CommandDefinition(fixedDetailsSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return new RunComparisonResult(
            request.BaselineRunId,
            request.TargetRunId,
            newCount,
            fixedCount,
            unchangedCount,
            newRows.ToList(),
            fixedRows.ToList());
    }

    public async Task<IReadOnlyList<ExportFindingItem>> GetFindingsForExport(
        string runId,
        FindingsQueryFilters? filters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var effectiveFilters = filters ?? new FindingsQueryFilters();
        var whereClause = "f.run_id = @RunId";
        var parameters = new DynamicParameters();
        parameters.Add("RunId", runId);

        if (!string.IsNullOrWhiteSpace(effectiveFilters.Severity))
        {
            whereClause += " AND f.severity = @Severity";
            parameters.Add("Severity", effectiveFilters.Severity);
        }

        if (!string.IsNullOrWhiteSpace(effectiveFilters.RuleId))
        {
            whereClause += " AND f.rule_id = @RuleId";
            parameters.Add("RuleId", effectiveFilters.RuleId);
        }

        if (!string.IsNullOrWhiteSpace(effectiveFilters.RulePrefix))
        {
            whereClause += " AND f.rule_id LIKE @RulePrefix";
            parameters.Add("RulePrefix", $"{effectiveFilters.RulePrefix.Trim()}%");
        }

        if (!string.IsNullOrWhiteSpace(effectiveFilters.Confidence))
        {
            whereClause += " AND f.confidence = @Confidence";
            parameters.Add("Confidence", effectiveFilters.Confidence);
        }

        if (!string.IsNullOrWhiteSpace(effectiveFilters.FileCategory))
        {
            whereClause += " AND fl.category = @FileCategory";
            parameters.Add("FileCategory", effectiveFilters.FileCategory);
        }

        if (!string.IsNullOrWhiteSpace(effectiveFilters.Language))
        {
            whereClause += " AND fl.language = @Language";
            parameters.Add("Language", effectiveFilters.Language);
        }

        if (!string.IsNullOrWhiteSpace(effectiveFilters.PathPrefix))
        {
            whereClause += " AND f.file_path LIKE @PathPrefix";
            parameters.Add("PathPrefix", $"{effectiveFilters.PathPrefix.Trim()}%");
        }

        if (!effectiveFilters.IncludeSuppressed)
        {
            whereClause += " AND NOT (COALESCE(f.metadata, '') LIKE '%\"suppressed\":true%' OR COALESCE(f.metadata, '') LIKE '%\"isSuppressed\":true%')";
        }

        var sql = $"""
                   SELECT
                       f.finding_id AS FindingId,
                       f.run_id AS RunId,
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
                       f.fingerprint AS Fingerprint,
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
                       END AS SuppressionReason,
                       CASE
                           WHEN COALESCE(f.metadata, '') LIKE '%\"suppressionSource\":\"%' THEN
                               lower(
                                   substr(
                                       f.metadata,
                                       instr(f.metadata, '\"suppressionSource\":\"') + length('\"suppressionSource\":\"'),
                                       instr(substr(f.metadata, instr(f.metadata, '\"suppressionSource\":\"') + length('\"suppressionSource\":\"')), '\"') - 1))
                           WHEN lower(COALESCE(f.metadata, '')) LIKE '%allowlist%' THEN 'allowlist'
                           WHEN lower(COALESCE(f.metadata, '')) LIKE '%inline%' THEN 'inline'
                           ELSE NULL
                       END AS SuppressionSource
                   FROM findings f
                   INNER JOIN files fl ON fl.file_id = f.file_id
                   LEFT JOIN rules r ON r.rule_id = f.rule_id
                   WHERE {whereClause}
                   ORDER BY f.rule_id ASC, f.file_path ASC, f.line ASC, f.finding_id ASC;
                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<ExportFindingRow>(
            new CommandDefinition(sql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return rows.Select(row => new ExportFindingItem(
            row.FindingId,
            row.RunId,
            row.FileId,
            row.RuleId,
            row.RuleTitle,
            row.RuleDescription,
            row.FilePath,
            row.Line,
            row.Column,
            row.Message,
            row.Snippet,
            row.Severity,
            row.Confidence,
            row.FileCategory,
            row.Language,
            row.Fingerprint,
            row.Metadata,
            row.AstConfirmed,
            row.IsSuppressed,
            row.SuppressionReason,
            row.SuppressionSource)).ToList();
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

    public async Task<GitMetricsPage> GetGitMetrics(
        string runId,
        GitMetricsQueryRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var effectiveRequest = request ?? GitMetricsQueryRequest.Default;
        var safeLimit = Math.Clamp(effectiveRequest.Limit, 1, 500);
        var safeOffset = Math.Max(effectiveRequest.Offset, 0);
        var filters = effectiveRequest.Filters ?? new GitMetricsQueryFilters();

        var whereClause = "g.run_id = @RunId";
        var parameters = new DynamicParameters();
        parameters.Add("RunId", runId);

        if (filters.MinChurnScore.HasValue)
        {
            whereClause += " AND g.churn_score >= @MinChurnScore";
            parameters.Add("MinChurnScore", filters.MinChurnScore.Value);
        }

        if (filters.MaxStaleScore.HasValue)
        {
            whereClause += " AND COALESCE(g.stale_score, 0) <= @MaxStaleScore";
            parameters.Add("MaxStaleScore", filters.MaxStaleScore.Value);
        }

        if (!string.IsNullOrWhiteSpace(filters.PathPrefix))
        {
            whereClause += " AND g.file_path LIKE @PathPrefix";
            parameters.Add("PathPrefix", $"{filters.PathPrefix.Trim()}%");
        }

        var totalSql = "SELECT COUNT(*) FROM git_file_metrics WHERE run_id = @RunId;";
        var filteredSql = $"SELECT COUNT(*) FROM git_file_metrics g WHERE {whereClause};";
        var sortColumn = GetGitMetricsSortColumn(effectiveRequest.SortField);
        var sortDirection = effectiveRequest.SortDescending ? "DESC" : "ASC";
        var pageSql = $"""
                       SELECT
                           g.file_id AS FileId,
                           g.file_path AS FilePath,
                           g.churn_score AS ChurnScore,
                           g.stale_score AS StaleScore,
                           g.commits_90d AS Commits90d,
                           g.authors_365d AS Authors365d,
                           g.ownership_concentration AS OwnershipConcentration,
                           g.top_author AS TopAuthor,
                           g.top_author_pct AS TopAuthorPct,
                           g.last_commit_at AS LastCommitAt,
                           CASE
                               WHEN g.ownership_concentration > 0.8 AND g.commits_90d = 0 THEN 1
                               ELSE 0
                           END AS IsOrphaned
                       FROM git_file_metrics g
                       WHERE {whereClause}
                       ORDER BY {sortColumn} {sortDirection}, g.file_path ASC
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
        var items = await connection.QueryAsync<GitMetricListItem>(
            new CommandDefinition(pageSql, parameters, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return new GitMetricsPage(totalCount, filteredCount, items.ToList());
    }

    public async Task<IReadOnlyList<DirectoryAggregateItem>> GetDirectoryAggregates(
        string runId,
        HeatmapMetric metric,
        CancellationToken cancellationToken = default)
    {
        var rows = await GetHeatmapFileMetrics(runId, cancellationToken).ConfigureAwait(false);
        var root = BuildTree(rows, metric);
        var aggregates = new List<DirectoryAggregateItem>();
        FlattenDirectories(root, metric, depth: 0, aggregates);
        return aggregates;
    }

    public async Task<TreemapNode> GetTreemapData(
        string runId,
        HeatmapMetric metric,
        CancellationToken cancellationToken = default)
    {
        var rows = await GetHeatmapFileMetrics(runId, cancellationToken).ConfigureAwait(false);
        return BuildTree(rows, metric);
    }

    public async Task<DirectoryDrilldown?> GetDirectoryDrilldown(
        string runId,
        string directoryPath,
        HeatmapMetric metric,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        var normalizedPath = NormalizeDirectoryPath(directoryPath);

        var rows = await GetHeatmapFileMetrics(runId, cancellationToken).ConfigureAwait(false);
        var inDirectory = rows
            .Where(row => IsPathInDirectory(row.FilePath, normalizedPath))
            .ToList();

        if (inDirectory.Count == 0)
        {
            return null;
        }

        var totalSize = inDirectory.Sum(row => row.SizeBytes);
        var fileCount = inDirectory.Count;
        var metricValue = fileCount == 0 ? 0d : inDirectory.Average(row => row.GetMetricValue(metric));

        var prefix = normalizedPath == "." ? string.Empty : normalizedPath.TrimEnd('/') + "/";
        var likeValue = string.IsNullOrEmpty(prefix) ? "%" : $"{prefix}%";

        const string topFilesSql = """
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
                                     AND f.file_path LIKE @PathPrefix
                                   GROUP BY f.file_id, f.file_path, fl.category, fl.language
                                   ORDER BY FindingCount DESC, f.file_path ASC
                                   LIMIT 10;
                                   """;

        const string topRulesSql = """
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
                                     AND f.file_path LIKE @PathPrefix
                                   GROUP BY f.rule_id, r.title, r.description
                                   ORDER BY FindingCount DESC, f.rule_id ASC
                                   LIMIT 10;
                                   """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        var topFiles = await connection.QueryAsync<FileSummaryRow>(
            new CommandDefinition(topFilesSql, new { RunId = runId, PathPrefix = likeValue }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var topRules = await connection.QueryAsync<RuleSummaryRow>(
            new CommandDefinition(topRulesSql, new { RunId = runId, PathPrefix = likeValue }, cancellationToken: cancellationToken)).ConfigureAwait(false);

        return new DirectoryDrilldown(
            normalizedPath,
            fileCount,
            totalSize,
            metricValue,
            topFiles.Select(MapFileSummaryItem).ToList(),
            topRules.Select(MapRuleSummaryItem).ToList());
    }

    private async Task<IReadOnlyList<HeatmapFileMetricRow>> GetHeatmapFileMetrics(
        string runId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        const string sql = """
                           SELECT
                               fl.file_id AS FileId,
                               fl.path AS FilePath,
                               fl.size_bytes AS SizeBytes,
                               COALESCE(g.churn_score, 0.0) AS ChurnScore,
                               COALESCE(g.stale_score, 0.0) AS StaleScore,
                               COALESCE(g.ownership_concentration, 0.0) AS OwnershipRisk,
                               COALESCE(pf.PortabilityFindingCount, 0) AS PortabilityFindingCount,
                               COALESCE(tf.FindingCount, 0) AS FindingCount
                           FROM files fl
                           LEFT JOIN git_file_metrics g
                               ON g.run_id = fl.run_id
                              AND g.file_id = fl.file_id
                           LEFT JOIN (
                               SELECT f.file_id, COUNT(*) AS PortabilityFindingCount
                               FROM findings f
                               WHERE f.run_id = @RunId
                                 AND f.rule_id LIKE 'portability.%'
                               GROUP BY f.file_id
                           ) pf ON pf.file_id = fl.file_id
                           LEFT JOIN (
                               SELECT f.file_id, COUNT(*) AS FindingCount
                               FROM findings f
                               WHERE f.run_id = @RunId
                               GROUP BY f.file_id
                           ) tf ON tf.file_id = fl.file_id
                           WHERE fl.run_id = @RunId;
                           """;

        await using var connection = _connectionFactory();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<HeatmapFileMetricRow>(
            new CommandDefinition(sql, new { RunId = runId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.ToList();
    }

    private static TreemapNode BuildTree(IReadOnlyList<HeatmapFileMetricRow> rows, HeatmapMetric metric)
    {
        var root = new TreemapNode
        {
            Name = ".",
            Path = ".",
            IsDirectory = true
        };

        var directories = new Dictionary<string, TreemapNode>(StringComparer.OrdinalIgnoreCase)
        {
            ["."] = root
        };

        foreach (var row in rows)
        {
            var normalized = row.FilePath.Replace('\\', '/');
            var parts = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var currentPath = ".";
            var parent = root;

            for (var i = 0; i < parts.Length - 1; i++)
            {
                var segment = parts[i];
                currentPath = currentPath == "."
                    ? segment
                    : $"{currentPath}/{segment}";

                if (!directories.TryGetValue(currentPath, out var directoryNode))
                {
                    directoryNode = new TreemapNode
                    {
                        Name = segment,
                        Path = currentPath,
                        IsDirectory = true
                    };
                    directories[currentPath] = directoryNode;
                    parent.Children.Add(directoryNode);
                }

                parent = directoryNode;
            }

            var fileName = parts.Length == 0 ? normalized : parts[^1];
            var fileNode = new TreemapNode
            {
                Name = fileName,
                Path = normalized,
                IsDirectory = false,
                FileId = row.FileId,
                SizeBytes = row.SizeBytes,
                FileCount = 1,
                ChurnScore = row.ChurnScore,
                StaleScore = row.StaleScore,
                OwnershipRisk = row.OwnershipRisk,
                PortabilityBlockers = row.PortabilityBlockers,
                FindingDensity = row.FindingDensity,
                MetricValue = row.GetMetricValue(metric)
            };
            parent.Children.Add(fileNode);
        }

        ComputeDirectoryMetrics(root, metric);
        SortTree(root);
        return root;
    }

    private static void ComputeDirectoryMetrics(TreemapNode node, HeatmapMetric metric)
    {
        if (!node.IsDirectory)
        {
            return;
        }

        foreach (var child in node.Children)
        {
            ComputeDirectoryMetrics(child, metric);
        }

        var totalSize = 0L;
        var totalFiles = 0L;
        var churnWeighted = 0d;
        var staleWeighted = 0d;
        var ownershipWeighted = 0d;
        var portabilityWeighted = 0d;
        var densityWeighted = 0d;
        var weightTotal = 0d;

        foreach (var child in node.Children)
        {
            var childWeight = child.IsDirectory ? Math.Max(child.SizeBytes, child.FileCount) : Math.Max(child.SizeBytes, 1);
            totalSize += child.SizeBytes;
            totalFiles += child.FileCount;
            churnWeighted += child.ChurnScore * childWeight;
            staleWeighted += child.StaleScore * childWeight;
            ownershipWeighted += child.OwnershipRisk * childWeight;
            portabilityWeighted += child.PortabilityBlockers * childWeight;
            densityWeighted += child.FindingDensity * childWeight;
            weightTotal += childWeight;
        }

        node.SizeBytes = totalSize;
        node.FileCount = totalFiles;
        if (weightTotal <= 0d)
        {
            node.ChurnScore = 0d;
            node.StaleScore = 0d;
            node.OwnershipRisk = 0d;
            node.PortabilityBlockers = 0d;
            node.FindingDensity = 0d;
            node.MetricValue = 0d;
            return;
        }

        node.ChurnScore = churnWeighted / weightTotal;
        node.StaleScore = staleWeighted / weightTotal;
        node.OwnershipRisk = ownershipWeighted / weightTotal;
        node.PortabilityBlockers = portabilityWeighted / weightTotal;
        node.FindingDensity = densityWeighted / weightTotal;
        node.MetricValue = metric switch
        {
            HeatmapMetric.ChurnHotspots => node.ChurnScore,
            HeatmapMetric.StaleRisk => node.StaleScore,
            HeatmapMetric.OwnershipRisk => node.OwnershipRisk,
            HeatmapMetric.PortabilityBlockers => node.PortabilityBlockers,
            HeatmapMetric.FindingDensity => node.FindingDensity,
            _ => node.ChurnScore
        };
    }

    private static void FlattenDirectories(
        TreemapNode node,
        HeatmapMetric metric,
        int depth,
        List<DirectoryAggregateItem> output)
    {
        if (!node.IsDirectory)
        {
            return;
        }

        output.Add(new DirectoryAggregateItem(
            node.Path,
            depth,
            node.FileCount,
            node.SizeBytes,
            metric switch
            {
                HeatmapMetric.ChurnHotspots => node.ChurnScore,
                HeatmapMetric.StaleRisk => node.StaleScore,
                HeatmapMetric.OwnershipRisk => node.OwnershipRisk,
                HeatmapMetric.PortabilityBlockers => node.PortabilityBlockers,
                HeatmapMetric.FindingDensity => node.FindingDensity,
                _ => node.ChurnScore
            },
            node.ChurnScore,
            node.StaleScore,
            node.OwnershipRisk,
            node.PortabilityBlockers,
            node.FindingDensity));

        foreach (var child in node.Children.Where(c => c.IsDirectory))
        {
            FlattenDirectories(child, metric, depth + 1, output);
        }
    }

    private static void SortTree(TreemapNode node)
    {
        if (node.Children.Count == 0)
        {
            return;
        }

        node.Children.Sort((left, right) =>
        {
            if (left.IsDirectory != right.IsDirectory)
            {
                return left.IsDirectory ? -1 : 1;
            }

            var bySize = right.SizeBytes.CompareTo(left.SizeBytes);
            if (bySize != 0)
            {
                return bySize;
            }

            return string.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
        });

        foreach (var child in node.Children)
        {
            SortTree(child);
        }
    }

    private static bool IsPathInDirectory(string filePath, string directoryPath)
    {
        var normalizedFile = filePath.Replace('\\', '/');
        if (directoryPath == ".")
        {
            return true;
        }

        return normalizedFile.StartsWith(directoryPath.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(normalizedFile, directoryPath, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDirectoryPath(string? directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath) || directoryPath == ".")
        {
            return ".";
        }

        var normalized = directoryPath.Replace('\\', '/').Trim('/');
        return string.IsNullOrWhiteSpace(normalized) ? "." : normalized;
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

    private static string GetGitMetricsSortColumn(GitMetricsSortField sortField) => sortField switch
    {
        GitMetricsSortField.FilePath => "g.file_path",
        GitMetricsSortField.ChurnScore => "g.churn_score",
        GitMetricsSortField.StaleScore => "COALESCE(g.stale_score, 0)",
        GitMetricsSortField.Commits90d => "g.commits_90d",
        GitMetricsSortField.Authors365d => "g.authors_365d",
        GitMetricsSortField.OwnershipConcentration => "g.ownership_concentration",
        GitMetricsSortField.LastCommitAt => "COALESCE(g.last_commit_at, '')",
        _ => "g.churn_score"
    };

    private static string GetDeploySortColumn(DeployFindingsSortField sortField) => sortField switch
    {
        DeployFindingsSortField.ArtifactType => GetArtifactTypeSqlExpression(),
        DeployFindingsSortField.Severity => "CASE f.severity WHEN 'Error' THEN 0 WHEN 'Warning' THEN 1 ELSE 2 END",
        DeployFindingsSortField.RuleId => "f.rule_id",
        DeployFindingsSortField.FilePath => "f.file_path",
        DeployFindingsSortField.LocationPath => GetArtifactPathSqlExpression(),
        _ => "CASE f.severity WHEN 'Error' THEN 0 WHEN 'Warning' THEN 1 ELSE 2 END"
    };

    private static string GetArtifactTypeSqlExpression()
    {
        return """
               CASE
                   WHEN f.rule_id LIKE 'deploy.ev2.%' THEN 'EV2'
                   WHEN f.rule_id LIKE 'deploy.ado.%' THEN 'ADO'
                   WHEN lower(f.file_path) LIKE '%/ev2/%' OR lower(f.file_path) LIKE '%rollout%' OR lower(f.file_path) LIKE '%service-model%' THEN 'EV2'
                   WHEN lower(f.file_path) LIKE '%pipeline%' OR lower(f.file_path) LIKE '%/.azuredevops/%' OR lower(f.file_path) LIKE '%/ado/%' THEN 'ADO'
                   ELSE 'Unknown'
               END
               """;
    }

    private static string GetDeploySubcategorySqlExpression()
    {
        return """
               CASE
                   WHEN f.rule_id LIKE 'deploy.%.inline_secret' THEN 'inline-secrets'
                   WHEN f.rule_id LIKE 'deploy.%.hardcoded.%' OR f.rule_id LIKE 'deploy.%.env_constant' THEN 'hardcoded-values'
                   ELSE 'missing-safety'
               END
               """;
    }

    private static string GetArtifactPathSqlExpression()
    {
        return """
               CASE
                   WHEN COALESCE(f.metadata, '') LIKE '%\"artifactPath\":\"%' THEN
                       substr(
                           f.metadata,
                           instr(f.metadata, '\"artifactPath\":\"') + length('\"artifactPath\":\"'),
                           instr(substr(f.metadata, instr(f.metadata, '\"artifactPath\":\"') + length('\"artifactPath\":\"')), '\"') - 1)
                   ELSE '$'
               END
               """;
    }

    private static string NormalizeSuppressionSource(string? source)
    {
        return source?.Trim().ToLowerInvariant() switch
        {
            "inline" => "inline",
            "allowlist" => "allowlist",
            "config" => "config",
            _ => "config"
        };
    }

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

    private static RuleSummaryItem MapRuleSummaryItem(RuleSummaryRow row)
    {
        var ruleId = ToText(row.RuleId);
        return new RuleSummaryItem(
            ruleId,
            ToText(row.Title, ruleId),
            ToNullableText(row.Description),
            ToLong(row.FindingCount),
            ToLong(row.ErrorCount),
            ToLong(row.WarningCount),
            ToLong(row.InfoCount));
    }

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

    private static double ToDouble(object? value)
    {
        return value switch
        {
            null => 0d,
            double doubleValue => doubleValue,
            float floatValue => floatValue,
            decimal decimalValue => (double)decimalValue,
            long longValue => longValue,
            int intValue => intValue,
            string stringValue when double.TryParse(stringValue, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) => parsed,
            byte[] bytes => double.Parse(Encoding.UTF8.GetString(bytes), NumberStyles.Float, CultureInfo.InvariantCulture),
            _ => Convert.ToDouble(value, CultureInfo.InvariantCulture)
        };
    }

    private static string ToText(object? value, string fallback = "")
    {
        return value switch
        {
            null => fallback,
            string text => text,
            byte[] bytes => Encoding.UTF8.GetString(bytes),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? fallback
        };
    }

    private static string? ToNullableText(object? value)
    {
        if (value is null)
        {
            return null;
        }

        var text = ToText(value);
        return string.IsNullOrEmpty(text) ? null : text;
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

    private sealed class RuleSummaryRow
    {
        public object? RuleId { get; set; }

        public object? Title { get; set; }

        public object? Description { get; set; }

        public object? FindingCount { get; set; }

        public object? ErrorCount { get; set; }

        public object? WarningCount { get; set; }

        public object? InfoCount { get; set; }
    }

    private sealed class RuleCatalogRow
    {
        public object? RuleId { get; set; }

        public object? Title { get; set; }

        public object? DefaultSeverity { get; set; }

        public object? Description { get; set; }

        public object? Category { get; set; }

        public object? EffectiveState { get; set; }

        public object? TotalFindings { get; set; }
    }

    private sealed class RuleFindingAcrossRunsRow
    {
        public string RunId { get; set; } = string.Empty;

        public string RepoRoot { get; set; } = string.Empty;

        public string StartedAt { get; set; } = string.Empty;

        public string FilePath { get; set; } = string.Empty;

        public long Line { get; set; }

        public long Column { get; set; }

        public string Severity { get; set; } = string.Empty;

        public string Message { get; set; } = string.Empty;

        public string Confidence { get; set; } = string.Empty;

        public string? Fingerprint { get; set; }
    }

    private sealed class SuppressedFindingRow
    {
        public long FindingId { get; set; }

        public long FileId { get; set; }

        public string FilePath { get; set; } = string.Empty;

        public string RuleId { get; set; } = string.Empty;

        public string RuleTitle { get; set; } = string.Empty;

        public string Severity { get; set; } = string.Empty;

        public string Confidence { get; set; } = string.Empty;

        public string Message { get; set; } = string.Empty;

        public string? SuppressionReason { get; set; }

        public string? SuppressionSource { get; set; }

        public string? Metadata { get; set; }
    }

    private sealed class ExportFindingRow
    {
        public long FindingId { get; set; }

        public string RunId { get; set; } = string.Empty;

        public long FileId { get; set; }

        public string RuleId { get; set; } = string.Empty;

        public string RuleTitle { get; set; } = string.Empty;

        public string RuleDescription { get; set; } = string.Empty;

        public string FilePath { get; set; } = string.Empty;

        public long Line { get; set; }

        public long Column { get; set; }

        public string Message { get; set; } = string.Empty;

        public string? Snippet { get; set; }

        public string Severity { get; set; } = string.Empty;

        public string Confidence { get; set; } = string.Empty;

        public string? FileCategory { get; set; }

        public string? Language { get; set; }

        public string? Fingerprint { get; set; }

        public string? Metadata { get; set; }

        public bool AstConfirmed { get; set; }

        public bool IsSuppressed { get; set; }

        public string? SuppressionReason { get; set; }

        public string? SuppressionSource { get; set; }
    }

    private sealed class DeploymentArtifactRiskRow
    {
        public long FileId { get; set; }

        public string FilePath { get; set; } = string.Empty;

        public string ArtifactType { get; set; } = string.Empty;

        public object? ErrorCount { get; set; }

        public object? WarningCount { get; set; }

        public object? InfoCount { get; set; }

        public object? RiskScore { get; set; }
    }

    private sealed class DeploymentSeveritySummaryRow
    {
        public string ArtifactType { get; set; } = string.Empty;

        public object? ErrorCount { get; set; }

        public object? WarningCount { get; set; }

        public object? InfoCount { get; set; }
    }
}
