using Dapper;
using Microsoft.Data.Sqlite;

namespace ReliabilityIQ.Core.Persistence;

public sealed class SqliteResultsWriter
{
    private const int BatchSize = 1000;
    private const int BusyTimeoutMilliseconds = 30000;
    private const int MaxWriteAttempts = 3;
    private readonly string _connectionString;
    private readonly SqliteSchemaManager _schemaManager;

    public SqliteResultsWriter(string databasePath, SqliteSchemaManager? schemaManager = null)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            throw new ArgumentException("Database path is required.", nameof(databasePath));
        }

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(databasePath),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            DefaultTimeout = BusyTimeoutMilliseconds / 1000,
            Pooling = true
        }.ToString();
        _schemaManager = schemaManager ?? new SqliteSchemaManager();
    }

    public async Task WriteAsync(
        ScanRun run,
        IReadOnlyList<PersistedFile> files,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<RuleDefinition> rules,
        IReadOnlyList<GitFileMetric>? gitFileMetrics = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        await WriteWithRetryAsync(async () =>
        {
            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ConfigureConnectionAsync(connection, cancellationToken).ConfigureAwait(false);
            await _schemaManager.EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

            await UpsertRunAsync(connection, run).ConfigureAwait(false);
            await UpsertRulesAsync(connection, rules).ConfigureAwait(false);
            await ClearRunDataAsync(connection, run.RunId).ConfigureAwait(false);

            var fileIdByPath = await InsertFilesAsync(connection, run.RunId, files).ConfigureAwait(false);
            await InsertFindingsAsync(connection, run.RunId, findings, fileIdByPath).ConfigureAwait(false);
            await InsertGitFileMetricsAsync(connection, run.RunId, gitFileMetrics ?? [], fileIdByPath).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ConfigureConnectionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        const string sql = """
                           PRAGMA busy_timeout = 30000;
                           PRAGMA journal_mode = WAL;
                           PRAGMA synchronous = NORMAL;
                           """;

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteWithRetryAsync(Func<Task> writeOperation, CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromMilliseconds(200);

        for (var attempt = 1; attempt <= MaxWriteAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await writeOperation().ConfigureAwait(false);
                return;
            }
            catch (SqliteException ex) when (attempt < MaxWriteAttempts && IsTransientLock(ex))
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(delay.TotalMilliseconds * 2);
            }
        }
    }

    private static bool IsTransientLock(SqliteException ex)
    {
        return ex.SqliteErrorCode is 5 or 6 or 14 ||
               ex.Message.Contains("being used by another process", StringComparison.OrdinalIgnoreCase) ||
               ex.Message.Contains("database is locked", StringComparison.OrdinalIgnoreCase) ||
               ex.Message.Contains("database is busy", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task ClearRunDataAsync(SqliteConnection connection, string runId)
    {
        await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
        const string deleteFindings = "DELETE FROM findings WHERE run_id = @RunId;";
        const string deleteGitMetrics = "DELETE FROM git_file_metrics WHERE run_id = @RunId;";
        const string deleteFiles = "DELETE FROM files WHERE run_id = @RunId;";
        await connection.ExecuteAsync(deleteFindings, new { RunId = runId }, transaction).ConfigureAwait(false);
        await connection.ExecuteAsync(deleteGitMetrics, new { RunId = runId }, transaction).ConfigureAwait(false);
        await connection.ExecuteAsync(deleteFiles, new { RunId = runId }, transaction).ConfigureAwait(false);
        await transaction.CommitAsync().ConfigureAwait(false);
    }

    private static Task UpsertRunAsync(SqliteConnection connection, ScanRun run)
    {
        const string sql = """
                           INSERT INTO scan_runs (run_id, repo_root, commit_sha, started_at, ended_at, tool_version, config_hash)
                           VALUES (@RunId, @RepoRoot, @CommitSha, @StartedAt, @EndedAt, @ToolVersion, @ConfigHash)
                           ON CONFLICT(run_id) DO UPDATE SET
                               repo_root = excluded.repo_root,
                               commit_sha = excluded.commit_sha,
                               started_at = excluded.started_at,
                               ended_at = excluded.ended_at,
                               tool_version = excluded.tool_version,
                               config_hash = excluded.config_hash;
                           """;

        var parameters = new
        {
            run.RunId,
            run.RepoRoot,
            run.CommitSha,
            StartedAt = run.StartedAt.UtcDateTime.ToString("O"),
            EndedAt = run.EndedAt?.UtcDateTime.ToString("O"),
            run.ToolVersion,
            run.ConfigHash
        };
        return connection.ExecuteAsync(sql, parameters);
    }

    private static async Task UpsertRulesAsync(SqliteConnection connection, IReadOnlyList<RuleDefinition> rules)
    {
        if (rules.Count == 0)
        {
            return;
        }

        const string sql = """
                           INSERT INTO rules (rule_id, title, default_severity, description)
                           VALUES (@RuleId, @Title, @DefaultSeverity, @Description)
                           ON CONFLICT(rule_id) DO UPDATE SET
                               title = excluded.title,
                               default_severity = excluded.default_severity,
                               description = excluded.description;
                           """;

        foreach (var batch in Batch(rules))
        {
            await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
            var payload = batch.Select(rule => new
            {
                rule.RuleId,
                rule.Title,
                DefaultSeverity = rule.DefaultSeverity.ToString(),
                rule.Description
            });
            await connection.ExecuteAsync(sql, payload, transaction).ConfigureAwait(false);
            await transaction.CommitAsync().ConfigureAwait(false);
        }
    }

    private static async Task<Dictionary<string, long>> InsertFilesAsync(
        SqliteConnection connection,
        string runId,
        IReadOnlyList<PersistedFile> files)
    {
        var fileIdByPath = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        if (files.Count == 0)
        {
            return fileIdByPath;
        }

        const string insertSql = """
                                 INSERT INTO files (run_id, path, category, size_bytes, hash, language)
                                 VALUES (@RunId, @Path, @Category, @SizeBytes, @Hash, @Language);
                                 """;
        const string selectSql = "SELECT file_id, path FROM files WHERE run_id = @RunId;";

        foreach (var batch in Batch(files))
        {
            await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
            var payload = batch.Select(file => new
            {
                RunId = runId,
                file.Path,
                Category = file.Category.ToString(),
                file.SizeBytes,
                file.Hash,
                file.Language
            });
            await connection.ExecuteAsync(insertSql, payload, transaction).ConfigureAwait(false);
            await transaction.CommitAsync().ConfigureAwait(false);
        }

        var rows = await connection.QueryAsync<(long file_id, string path)>(selectSql, new { RunId = runId }).ConfigureAwait(false);
        foreach (var row in rows)
        {
            fileIdByPath[row.path] = row.file_id;
        }

        return fileIdByPath;
    }

    private static async Task InsertFindingsAsync(
        SqliteConnection connection,
        string runId,
        IReadOnlyList<Finding> findings,
        IReadOnlyDictionary<string, long> fileIdByPath)
    {
        if (findings.Count == 0)
        {
            return;
        }

        const string sql = """
                           INSERT INTO findings (
                               run_id, rule_id, file_id, file_path, line, "column", message,
                               snippet, severity, confidence, fingerprint, metadata)
                           VALUES (
                               @RunId, @RuleId, @FileId, @FilePath, @Line, @Column, @Message,
                               @Snippet, @Severity, @Confidence, @Fingerprint, @Metadata);
                           """;

        foreach (var batch in Batch(findings))
        {
            await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
            var payload = new List<object>(batch.Count);
            foreach (var finding in batch)
            {
                if (!fileIdByPath.TryGetValue(finding.FilePath, out var fileId))
                {
                    continue;
                }

                payload.Add(new
                {
                    RunId = runId,
                    finding.RuleId,
                    FileId = fileId,
                    finding.FilePath,
                    finding.Line,
                    finding.Column,
                    finding.Message,
                    finding.Snippet,
                    Severity = finding.Severity.ToString(),
                    Confidence = finding.Confidence.ToString(),
                    finding.Fingerprint,
                    finding.Metadata
                });
            }

            if (payload.Count > 0)
            {
                await connection.ExecuteAsync(sql, payload, transaction).ConfigureAwait(false);
            }

            await transaction.CommitAsync().ConfigureAwait(false);
        }
    }

    private static async Task InsertGitFileMetricsAsync(
        SqliteConnection connection,
        string runId,
        IReadOnlyList<GitFileMetric> metrics,
        IReadOnlyDictionary<string, long> fileIdByPath)
    {
        if (metrics.Count == 0)
        {
            return;
        }

        const string sql = """
                           INSERT INTO git_file_metrics (
                               run_id, file_id, file_path, last_commit_at, commits_30d, commits_90d, commits_180d,
                               commits_365d, authors_365d, ownership_concentration, lines_added_365d, lines_removed_365d,
                               churn_score, stale_score, top_author, top_author_pct)
                           VALUES (
                               @RunId, @FileId, @FilePath, @LastCommitAt, @Commits30d, @Commits90d, @Commits180d,
                               @Commits365d, @Authors365d, @OwnershipConcentration, @LinesAdded365d, @LinesRemoved365d,
                               @ChurnScore, @StaleScore, @TopAuthor, @TopAuthorPct);
                           """;

        foreach (var batch in Batch(metrics))
        {
            await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
            var payload = new List<object>(batch.Count);
            foreach (var metric in batch)
            {
                if (!fileIdByPath.TryGetValue(metric.FilePath, out var fileId))
                {
                    continue;
                }

                payload.Add(new
                {
                    RunId = runId,
                    FileId = fileId,
                    metric.FilePath,
                    LastCommitAt = metric.LastCommitAt?.UtcDateTime.ToString("O"),
                    metric.Commits30d,
                    metric.Commits90d,
                    metric.Commits180d,
                    metric.Commits365d,
                    metric.Authors365d,
                    metric.OwnershipConcentration,
                    metric.LinesAdded365d,
                    metric.LinesRemoved365d,
                    metric.ChurnScore,
                    metric.StaleScore,
                    metric.TopAuthor,
                    metric.TopAuthorPct
                });
            }

            if (payload.Count > 0)
            {
                await connection.ExecuteAsync(sql, payload, transaction).ConfigureAwait(false);
            }

            await transaction.CommitAsync().ConfigureAwait(false);
        }
    }

    private static IEnumerable<List<T>> Batch<T>(IReadOnlyList<T> source)
    {
        for (var i = 0; i < source.Count; i += BatchSize)
        {
            var count = Math.Min(BatchSize, source.Count - i);
            var list = new List<T>(count);
            for (var j = 0; j < count; j++)
            {
                list.Add(source[i + j]);
            }

            yield return list;
        }
    }
}
