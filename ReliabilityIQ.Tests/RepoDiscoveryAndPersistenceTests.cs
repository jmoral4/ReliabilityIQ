using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Discovery;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Tests;

public sealed class RepoDiscoveryAndPersistenceTests : IDisposable
{
    private readonly string _tempDir;

    public RepoDiscoveryAndPersistenceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void DiscoverFiles_AppliesDefaultExcludesAndGitIgnore()
    {
        Directory.CreateDirectory(Path.Combine(_tempDir, ".git"));
        Directory.CreateDirectory(Path.Combine(_tempDir, "src"));
        Directory.CreateDirectory(Path.Combine(_tempDir, "bin"));
        Directory.CreateDirectory(Path.Combine(_tempDir, ".venv", "lib"));
        Directory.CreateDirectory(Path.Combine(_tempDir, "src", ".cache"));
        Directory.CreateDirectory(Path.Combine(_tempDir, "node_modules", "leftpad"));

        File.WriteAllText(Path.Combine(_tempDir, ".gitignore"), "ignored.txt");
        File.WriteAllText(Path.Combine(_tempDir, "src", "program.cs"), "class P {}");
        File.WriteAllText(Path.Combine(_tempDir, ".venv", "lib", "site.py"), "print('skip')");
        File.WriteAllText(Path.Combine(_tempDir, "src", ".cache", "artifact.json"), "{\"skip\":true}");
        File.WriteAllText(Path.Combine(_tempDir, "bin", "output.dll"), "skip");
        File.WriteAllText(Path.Combine(_tempDir, "ignored.txt"), "skip");
        File.WriteAllText(Path.Combine(_tempDir, "node_modules", "leftpad", "index.js"), "skip");
        File.WriteAllText(Path.Combine(_tempDir, "reliabilityiq-results.db-shm"), "skip");
        File.WriteAllText(Path.Combine(_tempDir, "reliabilityiq-results.db-wal"), "skip");

        var files = RepoDiscovery.DiscoverFiles(_tempDir, options: new RepoDiscoveryOptions(UseGitIgnore: true));

        Assert.Contains(files, file => file.RelativePath == "src/program.cs");
        Assert.DoesNotContain(files, file => file.RelativePath == "ignored.txt");
        Assert.DoesNotContain(files, file => file.RelativePath.Contains("node_modules", StringComparison.Ordinal));
        Assert.DoesNotContain(files, file => file.RelativePath.StartsWith("bin/", StringComparison.Ordinal));
        Assert.DoesNotContain(files, file => file.RelativePath.StartsWith(".venv/", StringComparison.Ordinal));
        Assert.DoesNotContain(files, file => file.RelativePath.Contains("/.cache/", StringComparison.Ordinal));
        Assert.DoesNotContain(files, file => file.RelativePath.EndsWith(".db-shm", StringComparison.Ordinal));
        Assert.DoesNotContain(files, file => file.RelativePath.EndsWith(".db-wal", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SqliteResultsWriter_CreatesSchemaAndWritesRunFilesFindingsAndRules()
    {
        var dbPath = Path.Combine(_tempDir, "results.db");
        var writer = new SqliteResultsWriter(dbPath);

        var run = new ScanRun(
            RunId: "run-1",
            RepoRoot: "/repo",
            CommitSha: "abc123",
            StartedAt: DateTimeOffset.UtcNow.AddMinutes(-1),
            EndedAt: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            ConfigHash: "cfg");

        var files = new List<PersistedFile>
        {
            new("src/program.cs", FileCategory.Source, 120, "hash-1", "csharp"),
            new("config/appsettings.json", FileCategory.Config, 64, "hash-2", "json")
        };

        var findings = new List<Finding>
        {
            new()
            {
                RunId = "run-1",
                RuleId = "portability.hardcoded.ipv4",
                FilePath = "src/program.cs",
                Line = 10,
                Column = 5,
                Message = "Hardcoded IP",
                Snippet = "10.1.1.1",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-1",
                Metadata = "{\"kind\":\"ip\"}"
            }
        };

        var rules = new List<RuleDefinition>
        {
            new("portability.hardcoded.ipv4", "Hardcoded IPv4", FindingSeverity.Warning, "Avoid hardcoded IP addresses.")
        };

        await writer.WriteAsync(run, files, findings, rules);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = dbPath
        }.ToString());
        await connection.OpenAsync();

        var runCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM scan_runs;");
        var fileCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM files;");
        var findingCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM findings;");
        var ruleCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM rules;");
        var indexCount = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_findings_run_rule_severity', 'idx_findings_file_id');");

        Assert.Equal(1, runCount);
        Assert.Equal(2, fileCount);
        Assert.Equal(1, findingCount);
        Assert.Equal(1, ruleCount);
        Assert.Equal(2, indexCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
