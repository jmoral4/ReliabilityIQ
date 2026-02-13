using System.Diagnostics;
using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Analyzers.GitHistory;
using ReliabilityIQ.Cli;

namespace ReliabilityIQ.Tests;

public sealed class Phase7GitHistoryTests : IDisposable
{
    private readonly string _tempDir;

    public Phase7GitHistoryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase7-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void MathFunctions_GiniChurnStale_AreDeterministic()
    {
        var concentrated = GitHistoryMath.ComputeGiniCoefficient([10, 1]);
        var balanced = GitHistoryMath.ComputeGiniCoefficient([5, 5]);

        Assert.True(concentrated > balanced);

        var churn = GitHistoryMath.ComputeChurnScore(5, 100, 50);
        Assert.True(churn > 0d);

        var stale30 = GitHistoryMath.ComputeStaleScore(30);
        var stale365 = GitHistoryMath.ComputeStaleScore(365);
        Assert.True(stale365 > stale30);
    }

    [Fact]
    public void ModuleAggregation_ProjectBoundary_UsesNearestProjectFile()
    {
        var markers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["src/ServiceA"] = "src/ServiceA/ServiceA.csproj"
        };

        var projectKey = GitHistoryAnalyzer.GetProjectModuleKey("src/ServiceA/Sub/Handler.cs", markers);
        var fallback = GitHistoryAnalyzer.GetProjectModuleKey("tools/script.ps1", markers);

        Assert.Equal("src/ServiceA/ServiceA.csproj", projectKey);
        Assert.Equal("tools", fallback);
    }

    [Fact]
    public void ModuleAggregation_ServiceBoundary_MatchesConfiguredGlob()
    {
        var mappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ServiceA"] = "src/ServiceA/**",
            ["ServiceB"] = "src/ServiceB/**"
        };

        var serviceAKey = GitHistoryAnalyzer.GetServiceModuleKey("src/ServiceA/api/handler.cs", mappings);
        var unknownKey = GitHistoryAnalyzer.GetServiceModuleKey("tools/script.ps1", mappings);

        Assert.Equal("ServiceA", serviceAKey);
        Assert.Equal(".", unknownKey);
    }

    [Fact]
    public async Task ChurnScan_ComputesMetricsAndOwnershipRisk_PersistsToSqlite()
    {
        var repo = Path.Combine(_tempDir, "repo");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, "src"));
        Directory.CreateDirectory(Path.Combine(repo, "docs"));

        await File.WriteAllTextAsync(Path.Combine(repo, "src", "owned.cs"), "class Owned { }\n");
        await File.WriteAllTextAsync(Path.Combine(repo, "src", "active.cs"), "class Active { }\n");
        await File.WriteAllTextAsync(Path.Combine(repo, "docs", "readme.md"), "docs\n");
        await File.WriteAllTextAsync(Path.Combine(repo, "src", "Service.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\" />\n");

        RunGit(repo, "init .");
        RunGit(repo, "config user.name tester");
        RunGit(repo, "config user.email tester@example.com");

        RunGit(repo, "add .");
        CommitWithDate(repo, "initial", "alice@example.com", "Alice", DateTimeOffset.UtcNow.AddDays(-220));

        await File.AppendAllTextAsync(Path.Combine(repo, "src", "owned.cs"), "class Owned2 { }\nclass Owned3 { }\n");
        RunGit(repo, "add src/owned.cs");
        CommitWithDate(repo, "owned follow-up", "alice@example.com", "Alice", DateTimeOffset.UtcNow.AddDays(-150));

        await File.AppendAllTextAsync(Path.Combine(repo, "src", "active.cs"), "class Active2 { }\n");
        RunGit(repo, "add src/active.cs");
        CommitWithDate(repo, "active recent", "bob@example.com", "Bob", DateTimeOffset.UtcNow.AddDays(-10));

        var serviceMapPath = Path.Combine(repo, "service-map.txt");
        await File.WriteAllTextAsync(serviceMapPath, "ServiceOwned=src/owned.cs\n");

        var dbPath = Path.Combine(_tempDir, "phase7.db");
        var exitCode = await ChurnScanRunner.ExecuteAsync(
            new ChurnScanOptions(repo, dbPath, "365d", serviceMapPath),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var sourceMetrics = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM git_file_metrics WHERE file_path LIKE 'src/%' AND file_path LIKE '%.cs';");
        Assert.Equal(2, sourceMetrics);

        var owned = await connection.QuerySingleAsync<(string FilePath, long Commits365d, long Commits90d, long Authors365d, double OwnershipConcentration, double? StaleScore)>(
            "SELECT file_path AS FilePath, commits_365d AS Commits365d, commits_90d AS Commits90d, authors_365d AS Authors365d, ownership_concentration AS OwnershipConcentration, stale_score AS StaleScore FROM git_file_metrics WHERE file_path = 'src/owned.cs';");

        Assert.Equal(2, owned.Commits365d);
        Assert.Equal(0, owned.Commits90d);
        Assert.Equal(1, owned.Authors365d);
        Assert.True(owned.OwnershipConcentration > 0.8d);
        Assert.True(owned.StaleScore.HasValue);

        var docsStale = await connection.ExecuteScalarAsync<double?>(
            "SELECT stale_score FROM git_file_metrics WHERE file_path = 'docs/readme.md';");
        Assert.Null(docsStale);

        var ownershipRiskCount = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM findings WHERE rule_id = 'churn.ownership.orphaned_knowledge_risk' AND file_path = 'src/owned.cs';");
        Assert.Equal(1, ownershipRiskCount);

        var ownershipMetadata = await connection.ExecuteScalarAsync<string?>(
            "SELECT metadata FROM findings WHERE rule_id = 'churn.ownership.orphaned_knowledge_risk' AND file_path = 'src/owned.cs' LIMIT 1;");
        Assert.NotNull(ownershipMetadata);
        Assert.Contains("\"moduleService\":\"ServiceOwned\"", ownershipMetadata, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private static void CommitWithDate(string repo, string message, string email, string name, DateTimeOffset when)
    {
        var iso = when.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        RunGit(repo, $"commit -m \"{message}\"", new Dictionary<string, string>
        {
            ["GIT_AUTHOR_NAME"] = name,
            ["GIT_AUTHOR_EMAIL"] = email,
            ["GIT_AUTHOR_DATE"] = iso,
            ["GIT_COMMITTER_NAME"] = name,
            ["GIT_COMMITTER_EMAIL"] = email,
            ["GIT_COMMITTER_DATE"] = iso
        });
    }

    private static void RunGit(string repo, string arguments, IReadOnlyDictionary<string, string>? extraEnvironment = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "git",
            Arguments = arguments,
            WorkingDirectory = repo,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        if (extraEnvironment is not null)
        {
            foreach (var kvp in extraEnvironment)
            {
                psi.Environment[kvp.Key] = kvp.Value;
            }
        }

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start git process.");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            throw new InvalidOperationException($"git {arguments} failed ({process.ExitCode}): {stdout}\n{stderr}");
        }
    }

}
