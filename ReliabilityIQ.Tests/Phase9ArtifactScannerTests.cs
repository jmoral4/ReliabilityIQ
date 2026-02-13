using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Cli;
using ReliabilityIQ.Core.Discovery;

namespace ReliabilityIQ.Tests;

public sealed class Phase9ArtifactScannerTests : IDisposable
{
    private readonly string _tempDir;

    public Phase9ArtifactScannerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase9-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task DeployScan_FindsEv2AndAdoRules_AndPersistsStructuredLocationMetadata()
    {
        var repoRoot = Path.Combine(_tempDir, "repo");
        Directory.CreateDirectory(repoRoot);
        Directory.CreateDirectory(Path.Combine(repoRoot, ".git"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "deploy", "ev2"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "pipelines"));

        await File.WriteAllTextAsync(Path.Combine(repoRoot, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "deploy", "ev2", "rollout.yaml"),
            """
            rolloutSpec:
              subscriptionId: 11111111-1111-4111-8111-111111111111
              tenantId: 22222222-2222-4222-8222-222222222222
              endpoint: management.azure.com
              region: eastus
              waitDuration: PT0S
              environment: production
              secret: super-secret-value
            """);

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "pipelines", "azure-pipelines.yml"),
            """
            stages:
              - stage: Production
                jobs:
                  - job: Deploy
                    pool:
                      name: ProdPool
                    steps:
                      - powershell: |
                          Write-Host "deploy"
                          copy C:\\deploy\\artifact.txt C:\\temp\\artifact.txt
                      - script: C:\\build\\run.ps1
                      - task: AzureCLI@2
                        inputs:
                          connectedServiceName: ProdServiceConnection
                          clientSecret: plain-text-secret
                      - script: docker run myregistry.azurecr.io/app:latest
            """);

        var dbPath = Path.Combine(_tempDir, "deploy.db");
        var exitCode = await DeployScanRunner.ExecuteAsync(
            new DeployScanOptions(repoRoot, dbPath, Ev2PathMarkers: null, AdoPathMarkers: null),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var ruleIds = (await connection.QueryAsync<string>("SELECT DISTINCT rule_id FROM findings;")).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var requiredEv2Rules = new[]
        {
            "deploy.ev2.hardcoded.subscription",
            "deploy.ev2.hardcoded.tenant",
            "deploy.ev2.hardcoded.endpoint",
            "deploy.ev2.hardcoded.region",
            "deploy.ev2.zero_bake_time",
            "deploy.ev2.no_health_check",
            "deploy.ev2.single_region",
            "deploy.ev2.inline_secret",
            "deploy.ev2.env_constant"
        };

        foreach (var rule in requiredEv2Rules)
        {
            Assert.Contains(rule, ruleIds);
        }

        var requiredAdoRules = new[]
        {
            "deploy.ado.hardcoded.agentpool",
            "deploy.ado.hardcoded.path",
            "deploy.ado.hardcoded.endpoint",
            "deploy.ado.inline_secret",
            "deploy.ado.platform_assumption",
            "deploy.ado.missing_approval",
            "deploy.ado.container_latest"
        };

        foreach (var rule in requiredAdoRules)
        {
            Assert.Contains(rule, ruleIds);
        }

        var metadataRows = (await connection.QueryAsync<string>(
            "SELECT metadata FROM findings WHERE rule_id LIKE 'deploy.%' AND metadata IS NOT NULL;")).ToList();

        Assert.NotEmpty(metadataRows);
        Assert.Contains(metadataRows, m => m.Contains("\"artifactPath\":", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DeployScan_MalformedYamlOrJson_ProducesParseErrorFinding()
    {
        var repoRoot = Path.Combine(_tempDir, "repo-malformed");
        Directory.CreateDirectory(repoRoot);
        Directory.CreateDirectory(Path.Combine(repoRoot, ".git"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "deploy", "ev2"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "pipelines"));

        await File.WriteAllTextAsync(Path.Combine(repoRoot, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "deploy", "ev2", "broken.yaml"), "subscriptionId: \"11111111-1111-4111-8111-111111111111");
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "pipelines", "broken.json"), "{ \"stages\": [ { \"stage\": \"Production\" ");

        var dbPath = Path.Combine(_tempDir, "malformed.db");
        var exitCode = await DeployScanRunner.ExecuteAsync(
            new DeployScanOptions(repoRoot, dbPath, Ev2PathMarkers: null, AdoPathMarkers: null),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var parseErrors = (await connection.QueryAsync<(string FilePath, string Message, int Line, int Column)>(
            "SELECT file_path AS FilePath, message AS Message, line AS Line, \"column\" AS Column FROM findings WHERE rule_id = 'deploy.artifact.parse_error';"))
            .ToList();

        Assert.NotEmpty(parseErrors);
        Assert.Contains(parseErrors, error => error.FilePath.EndsWith("broken.json", StringComparison.OrdinalIgnoreCase));
        Assert.All(parseErrors, error =>
        {
            Assert.True(error.Line >= 1);
            Assert.True(error.Column >= 1);
            Assert.Contains("Failed to parse", error.Message, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Theory]
    [InlineData("deploy/ev2/rollout.yaml")]
    [InlineData("pipelines/azure-pipelines.yml")]
    [InlineData(".azuredevops/release.json")]
    public void FileClassifier_RecognizesDeploymentArtifactPatterns(string path)
    {
        var classifier = new FileClassifier();
        var category = classifier.Classify(path);
        Assert.Equal(Core.FileCategory.DeploymentArtifact, category);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
