using Dapper;
using Microsoft.Data.Sqlite;

namespace ReliabilityIQ.Core.Persistence;

public sealed class SqliteResultsWriter
{
    private const int BatchSize = 1000;
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
            Pooling = true
        }.ToString();
        _schemaManager = schemaManager ?? new SqliteSchemaManager();
    }

    public async Task WriteAsync(
        ScanRun run,
        IReadOnlyList<PersistedFile> files,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<RuleDefinition> rules,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await _schemaManager.EnsureSchemaAsync(connection, cancellationToken).ConfigureAwait(false);

        await UpsertRunAsync(connection, run).ConfigureAwait(false);
        await UpsertRulesAsync(connection, rules).ConfigureAwait(false);
        await ClearRunDataAsync(connection, run.RunId).ConfigureAwait(false);

        var fileIdByPath = await InsertFilesAsync(connection, run.RunId, files).ConfigureAwait(false);
        await InsertFindingsAsync(connection, run.RunId, findings, fileIdByPath).ConfigureAwait(false);
    }

    private static async Task ClearRunDataAsync(SqliteConnection connection, string runId)
    {
        await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
        const string deleteFindings = "DELETE FROM findings WHERE run_id = @RunId;";
        const string deleteFiles = "DELETE FROM files WHERE run_id = @RunId;";
        await connection.ExecuteAsync(deleteFindings, new { RunId = runId }, transaction).ConfigureAwait(false);
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
