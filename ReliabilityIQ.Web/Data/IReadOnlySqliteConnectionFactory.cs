using Microsoft.Data.Sqlite;

namespace ReliabilityIQ.Web.Data;

public interface IReadOnlySqliteConnectionFactory
{
    string DatabasePath { get; }

    SqliteConnection CreateConnection();
}
