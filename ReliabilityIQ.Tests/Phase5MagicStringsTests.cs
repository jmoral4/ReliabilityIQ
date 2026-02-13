using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Analyzers.MagicStrings;
using ReliabilityIQ.Cli;

namespace ReliabilityIQ.Tests;

public sealed class Phase5MagicStringsTests : IDisposable
{
    private readonly string _tempDir;

    public Phase5MagicStringsTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase5-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void Heuristics_EntropyAndNaturalLanguage_BehaveAsExpected()
    {
        var entropySimple = MagicStringHeuristics.ShannonEntropy("AAAAABBBBBCCCCCDDDD");
        var entropyRandom = MagicStringHeuristics.ShannonEntropy("A92fQx1@bT7zLm3!pR8v");

        Assert.True(entropyRandom > entropySimple);
        Assert.True(MagicStringHeuristics.IsNaturalLanguage("This is a message, and this is for the status."));
        Assert.False(MagicStringHeuristics.IsNaturalLanguage("ACTIVE"));
    }

    [Fact]
    public async Task MagicStringsScan_ExcludesNoiseAndRanksComparisonUsageHighest()
    {
        var repoRoot = Path.Combine(_tempDir, "repo");
        Directory.CreateDirectory(repoRoot);
        Directory.CreateDirectory(Path.Combine(repoRoot, ".git"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "src"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "tests"));

        await File.WriteAllTextAsync(Path.Combine(repoRoot, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "src", "app.cs"),
            """
            using System;
            var state = "ACTIVE";
            if (state == "ACTIVE") { }
            if (state == "ACTIVE") { }
            Console.WriteLine("This is a very detailed status message, not a constant.");
            var endpoint = "management.azure.com";
            var token = "A92fQx1@bT7zLm3!pR8v";
            var shortOne = "ok";
            throw new InvalidOperationException("Something failed badly");
            """);

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "src", "module.py"),
            """
            mode = "ACTIVE"
            if mode == "ACTIVE":
                pass
            print("This is a very detailed status message, not a constant.")
            """);

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "tests", "sample.py"),
            """
            value = "TEST-ONLY"
            if value == "TEST-ONLY":
                pass
            """);

        var dbPath = Path.Combine(_tempDir, "magic.db");

        var exitCode = await MagicStringsScanRunner.ExecuteAsync(
            new MagicStringsScanOptions(repoRoot, dbPath, MinOccurrences: 2, Top: 50, ConfigPath: null),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var findings = (await connection.QueryAsync<FindingRow>(
            "SELECT rule_id AS RuleId, message AS Message, metadata AS Metadata FROM findings ORDER BY finding_id;"))
            .ToList();

        Assert.NotEmpty(findings);
        Assert.Contains(findings, f => f.RuleId == "magic-string.comparison-used" && f.Message.Contains("ACTIVE", StringComparison.Ordinal));
        Assert.DoesNotContain(findings, f => f.Message.Contains("management.azure.com", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(findings, f => f.Message.Contains("detailed status message", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(findings, f => f.Message.Contains("A92fQx1@bT7zLm3!pR8v", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Metadata.Contains("\"allOccurrences\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task MagicStringsScan_ConfigKnobs_ApplyFromYaml()
    {
        var repoRoot = Path.Combine(_tempDir, "repo-config");
        Directory.CreateDirectory(repoRoot);
        Directory.CreateDirectory(Path.Combine(repoRoot, ".git"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "src"));

        await File.WriteAllTextAsync(Path.Combine(repoRoot, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "src", "app.cs"),
            """
            var value = "MAGIC_KEY";
            if (value == "MAGIC_KEY") { }
            """);

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "reliabilityiq.magicstrings.yaml"),
            """
            minOccurrences: 2
            allowlist:
              - MAGIC_*
            """);

        var dbPath = Path.Combine(_tempDir, "magic-config.db");

        var exitCode = await MagicStringsScanRunner.ExecuteAsync(
            new MagicStringsScanOptions(repoRoot, dbPath, MinOccurrences: 0, Top: 50, ConfigPath: null),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var findingsCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM findings;");
        Assert.Equal(0, findingsCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private sealed record FindingRow(string RuleId, string Message, string Metadata);
}
