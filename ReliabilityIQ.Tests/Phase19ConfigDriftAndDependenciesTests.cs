using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Analyzers.Dependencies;
using ReliabilityIQ.Cli;

namespace ReliabilityIQ.Tests;

public sealed class Phase19ConfigDriftAndDependenciesTests : IDisposable
{
    private readonly string _tempDir;

    public Phase19ConfigDriftAndDependenciesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase19-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task ConfigDriftScan_DetectsMissingKeysOrphansAndHardcodedValueDifferences()
    {
        var repo = Path.Combine(_tempDir, "config-repo");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, ".git"));

        await File.WriteAllTextAsync(Path.Combine(repo, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");

        await File.WriteAllTextAsync(Path.Combine(repo, "appsettings.Development.json"),
            """
            {
              "ConnectionStrings": { "Main": "Server=dev-sql;Database=RiQ;" },
              "FeatureFlags": { "Alpha": true },
              "Shared": { "ApiTimeout": 30 },
              "OnlyDev": "x"
            }
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "appsettings.Production.json"),
            """
            {
              "ConnectionStrings": { "Main": "Server=prod-sql;Database=RiQ;" },
              "FeatureFlags": { "Alpha": true },
              "OnlyProd": "y"
            }
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "appsettings.Test.json"),
            """
            {
              "ConnectionStrings": { "Main": "${DB_CONNECTION}" },
              "FeatureFlags": { "Alpha": true },
              "Shared": { "ApiTimeout": 45 }
            }
            """);

        var dbPath = Path.Combine(_tempDir, "config-drift.db");
        var exitCode = await ConfigDriftScanRunner.ExecuteAsync(
            new ConfigDriftScanOptions(repo, dbPath),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var ruleIds = (await connection.QueryAsync<string>("SELECT DISTINCT rule_id FROM findings;")).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("config.drift.missing_key", ruleIds);
        Assert.Contains("config.drift.orphan_key", ruleIds);
        Assert.Contains("config.drift.hardcoded_env_value", ruleIds);

        var missingCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM findings WHERE rule_id='config.drift.missing_key';");
        Assert.True(missingCount > 0);
    }

    [Fact]
    public async Task DependenciesScan_ParsesNugetPipCargo_AndFlagsCveEolAndUnpinned()
    {
        var repo = Path.Combine(_tempDir, "deps-repo");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        Directory.CreateDirectory(Path.Combine(repo, "src"));

        await File.WriteAllTextAsync(Path.Combine(repo, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");

        await File.WriteAllTextAsync(Path.Combine(repo, "src", "App.csproj"),
            """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net5.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
                <PackageReference Include="Serilog" Version="[2.10.0,3.0.0)" />
              </ItemGroup>
            </Project>
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "requirements.txt"),
            """
            requests==2.19.0
            flask>=2.0
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "Cargo.toml"),
            """
            [package]
            name = "sample"
            version = "0.1.0"

            [dependencies]
            serde = "=1.0.0"
            tokio = "1.0"
            """);

        var dbPath = Path.Combine(_tempDir, "deps.db");
        var osvClient = new FakeOsvClient(new Dictionary<string, IReadOnlyList<DependencyVulnerability>>(StringComparer.OrdinalIgnoreCase)
        {
            ["NuGet|Newtonsoft.Json|13.0.1"] =
            [
                new DependencyVulnerability("GHSA-NUKE-HIGH", DependencyVulnerabilitySeverity.High, "High severity sample")
            ],
            ["PyPI|requests|2.19.0"] =
            [
                new DependencyVulnerability("GHSA-PIP-CRIT", DependencyVulnerabilitySeverity.Critical, "Critical severity sample")
            ],
            ["crates.io|serde|1.0.0"] =
            [
                new DependencyVulnerability("RUSTSEC-0000-0000", DependencyVulnerabilitySeverity.Medium, "Medium severity sample")
            ]
        });

        var exitCode = await DependenciesScanRunner.ExecuteAsync(
            new DependenciesScanOptions(repo, dbPath),
            TextWriter.Null,
            osvClient);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var ruleIds = (await connection.QueryAsync<string>("SELECT DISTINCT rule_id FROM findings;")).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("deps.vulnerable.critical", ruleIds);
        Assert.Contains("deps.vulnerable.high", ruleIds);
        Assert.Contains("deps.vulnerable.medium", ruleIds);
        Assert.Contains("deps.eol.framework", ruleIds);
        Assert.Contains("deps.unpinned_version", ruleIds);

        var unpinnedCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM findings WHERE rule_id='deps.unpinned_version';");
        Assert.True(unpinnedCount >= 2);

        var eolCount = await connection.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM findings WHERE rule_id='deps.eol.framework';");
        Assert.True(eolCount >= 1);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private sealed class FakeOsvClient : IOsvClient
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<DependencyVulnerability>> _responses;

        public FakeOsvClient(IReadOnlyDictionary<string, IReadOnlyList<DependencyVulnerability>> responses)
        {
            _responses = responses;
        }

        public Task<IReadOnlyList<DependencyVulnerability>> QueryVulnerabilitiesAsync(
            DependencyEcosystem ecosystem,
            string packageName,
            string version,
            CancellationToken cancellationToken = default)
        {
            var key = $"{ToOsvEcosystem(ecosystem)}|{packageName}|{version}";
            if (_responses.TryGetValue(key, out var vulnerabilities))
            {
                return Task.FromResult(vulnerabilities);
            }

            return Task.FromResult<IReadOnlyList<DependencyVulnerability>>([]);
        }

        private static string ToOsvEcosystem(DependencyEcosystem ecosystem)
        {
            return ecosystem switch
            {
                DependencyEcosystem.NuGet => "NuGet",
                DependencyEcosystem.PyPI => "PyPI",
                DependencyEcosystem.Cargo => "crates.io",
                DependencyEcosystem.Npm => "npm",
                _ => ""
            };
        }
    }
}
