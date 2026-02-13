using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using ReliabilityIQ.Web.Configuration;

namespace ReliabilityIQ.Web.Data;

public sealed class ReadOnlySqliteConnectionFactory : IReadOnlySqliteConnectionFactory
{
    private readonly string _connectionString;

    public ReadOnlySqliteConnectionFactory(IOptions<DatabaseOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var configuredPath = options.Value.Path;
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            throw new InvalidOperationException("Database path must be configured before creating SQLite connections.");
        }

        DatabasePath = Path.GetFullPath(configuredPath);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        }.ToString();
    }

    public string DatabasePath { get; }

    public SqliteConnection CreateConnection() => new(_connectionString);
}
