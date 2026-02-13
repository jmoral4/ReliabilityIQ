using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Cli;
using ReliabilityIQ.Core;

namespace ReliabilityIQ.Tests;

public sealed class PortabilityCliIntegrationTests : IDisposable
{
    private readonly string _tempDir;

    public PortabilityCliIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-cli-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task ExecuteAsync_ScansFixture_WritesSqliteAndReturnsExpectedExitCodes()
    {
        var fixtureRoot = Path.Combine(AppContext.BaseDirectory, "Fixtures", "PortabilityFixture");
        var repoRoot = Path.Combine(_tempDir, "fixture-copy");
        CopyDirectory(fixtureRoot, repoRoot);

        Directory.CreateDirectory(Path.Combine(repoRoot, ".git"));
        File.WriteAllText(Path.Combine(repoRoot, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");

        var dbPath = Path.Combine(_tempDir, "results.db");

        var warningOutput = new StringWriter();
        var warningExitCode = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repoRoot, dbPath, FindingSeverity.Warning),
            warningOutput);

        Assert.Equal(1, warningExitCode);
        var summary = warningOutput.ToString();
        Assert.Contains("Findings by severity:", summary, StringComparison.Ordinal);
        Assert.Contains("Top files by finding count:", summary, StringComparison.Ordinal);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = dbPath
        }.ToString());
        await connection.OpenAsync();

        var runCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM scan_runs;");
        var findingsCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM findings;");
        var fileCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM files;");

        var ruleIds = (await connection.QueryAsync<string>("SELECT DISTINCT rule_id FROM findings;")).ToHashSet(StringComparer.Ordinal);
        var scannedFiles = (await connection.QueryAsync<string>("SELECT path FROM files;")).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(1, runCount);
        Assert.Equal(10, findingsCount);
        Assert.Equal(4, fileCount);

        Assert.Contains("portability.hardcoded.ipv4", ruleIds);
        Assert.Contains("portability.hardcoded.dns", ruleIds);
        Assert.Contains("portability.hardcoded.filepath.windows", ruleIds);
        Assert.Contains("portability.hardcoded.filepath.linux", ruleIds);
        Assert.Contains("portability.hardcoded.guid", ruleIds);
        Assert.Contains("portability.hardcoded.region", ruleIds);
        Assert.Contains("portability.hardcoded.endpoint", ruleIds);

        Assert.Contains("src/program.cs", scannedFiles);
        Assert.Contains("config/appsettings.json", scannedFiles);
        Assert.Contains("docs/readme.md", scannedFiles);
        Assert.Contains(".gitignore", scannedFiles);
        Assert.DoesNotContain("ignored.txt", scannedFiles);
        Assert.DoesNotContain(scannedFiles, p => p.StartsWith("bin/", StringComparison.Ordinal));
        Assert.DoesNotContain(scannedFiles, p => p.Contains("node_modules", StringComparison.Ordinal));

        var errorExitCode = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repoRoot, dbPath, FindingSeverity.Error),
            TextWriter.Null);

        Assert.Equal(0, errorExitCode);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);

        foreach (var directory in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, directory);
            Directory.CreateDirectory(Path.Combine(destination, relative));
        }

        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
