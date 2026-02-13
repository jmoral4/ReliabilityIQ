using Microsoft.Data.Sqlite;

namespace ReliabilityIQ.Core.Persistence;

public sealed class SqliteSchemaManager
{
    public async Task EnsureSchemaAsync(SqliteConnection connection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }

        const string sql = """
                           CREATE TABLE IF NOT EXISTS scan_runs (
                               run_id TEXT PRIMARY KEY,
                               repo_root TEXT NOT NULL,
                               commit_sha TEXT,
                               started_at TEXT NOT NULL,
                               ended_at TEXT,
                               tool_version TEXT NOT NULL,
                               config_hash TEXT
                           );

                           CREATE TABLE IF NOT EXISTS files (
                               file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                               run_id TEXT NOT NULL,
                               path TEXT NOT NULL,
                               category TEXT NOT NULL,
                               size_bytes INTEGER NOT NULL,
                               hash TEXT NOT NULL,
                               language TEXT,
                               FOREIGN KEY(run_id) REFERENCES scan_runs(run_id)
                           );

                           CREATE TABLE IF NOT EXISTS findings (
                               finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                               run_id TEXT NOT NULL,
                               rule_id TEXT NOT NULL,
                               file_id INTEGER NOT NULL,
                               file_path TEXT NOT NULL,
                               line INTEGER NOT NULL,
                               "column" INTEGER NOT NULL,
                               message TEXT NOT NULL,
                               snippet TEXT,
                               severity TEXT NOT NULL,
                               confidence TEXT NOT NULL,
                               fingerprint TEXT NOT NULL,
                               metadata TEXT,
                               FOREIGN KEY(run_id) REFERENCES scan_runs(run_id),
                               FOREIGN KEY(file_id) REFERENCES files(file_id)
                           );

                           CREATE TABLE IF NOT EXISTS rules (
                               rule_id TEXT PRIMARY KEY,
                               title TEXT NOT NULL,
                               default_severity TEXT NOT NULL,
                               description TEXT NOT NULL
                           );

                           CREATE TABLE IF NOT EXISTS git_file_metrics (
                               metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                               run_id TEXT NOT NULL,
                               file_id INTEGER NOT NULL,
                               file_path TEXT NOT NULL,
                               last_commit_at TEXT,
                               commits_30d INTEGER NOT NULL,
                               commits_90d INTEGER NOT NULL,
                               commits_180d INTEGER NOT NULL,
                               commits_365d INTEGER NOT NULL,
                               authors_365d INTEGER NOT NULL,
                               ownership_concentration REAL NOT NULL,
                               lines_added_365d INTEGER NOT NULL,
                               lines_removed_365d INTEGER NOT NULL,
                               churn_score REAL NOT NULL,
                               stale_score REAL,
                               top_author TEXT,
                               top_author_pct REAL NOT NULL,
                               FOREIGN KEY(run_id) REFERENCES scan_runs(run_id),
                               FOREIGN KEY(file_id) REFERENCES files(file_id)
                           );

                           CREATE INDEX IF NOT EXISTS idx_findings_run_rule_severity
                               ON findings(run_id, rule_id, severity);

                           CREATE INDEX IF NOT EXISTS idx_findings_file_id
                               ON findings(file_id);

                           CREATE INDEX IF NOT EXISTS idx_git_file_metrics_run_churn
                               ON git_file_metrics(run_id, churn_score DESC);

                           CREATE INDEX IF NOT EXISTS idx_git_file_metrics_run_stale
                               ON git_file_metrics(run_id, stale_score DESC);
                           """;

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
