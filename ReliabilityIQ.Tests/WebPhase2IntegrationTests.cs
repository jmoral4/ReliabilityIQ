using System.Net;
using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Persistence;

namespace ReliabilityIQ.Tests;

public sealed class WebPhase2IntegrationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;
    private readonly string _runId;
    private long _fileId;

    public WebPhase2IntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-web-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "results.db");
        _runId = "run-web-1";
    }

    [Fact]
    public async Task WebPages_Load_WithSeededDatabase()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var home = await client.GetAsync("/");
        var findings = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/findings");
        var summary = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/summary");
        var fileDetail = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/file/{_fileId}");

        Assert.Equal(HttpStatusCode.OK, home.StatusCode);
        Assert.Equal(HttpStatusCode.OK, findings.StatusCode);
        Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
        Assert.Equal(HttpStatusCode.OK, fileDetail.StatusCode);
    }

    [Fact]
    public async Task FindingsApi_ReturnsDataTablesShape()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var uri = $"/api/run/{Uri.EscapeDataString(_runId)}/findings?draw=7&start=0&length=10&order[0][column]=2&order[0][dir]=asc&columns[2][name]=severity&severity=Warning&rule=portability.hardcoded.dns&confidence=High&includeSuppressed=true";
        var response = await client.GetAsync(uri);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;

        Assert.Equal(7, root.GetProperty("draw").GetInt32());
        Assert.True(root.TryGetProperty("recordsTotal", out var recordsTotal));
        Assert.True(root.TryGetProperty("recordsFiltered", out var recordsFiltered));
        Assert.True(root.TryGetProperty("data", out var data));
        Assert.True(recordsTotal.GetInt32() >= 1);
        Assert.True(recordsFiltered.GetInt32() >= 1);
        Assert.Equal(JsonValueKind.Array, data.ValueKind);
        Assert.True(data.GetArrayLength() >= 1);

        var first = data.EnumerateArray().First();
        Assert.True(first.TryGetProperty("findingId", out _));
        Assert.True(first.TryGetProperty("fileId", out _));
        Assert.True(first.TryGetProperty("ruleId", out _));
        Assert.True(first.TryGetProperty("ruleTitle", out _));
        Assert.True(first.TryGetProperty("ruleDescription", out _));
        Assert.True(first.TryGetProperty("filePath", out _));
        Assert.True(first.TryGetProperty("line", out _));
        Assert.True(first.TryGetProperty("column", out _));
        Assert.True(first.TryGetProperty("message", out _));
        Assert.True(first.TryGetProperty("snippet", out _));
        Assert.True(first.TryGetProperty("severity", out _));
        Assert.True(first.TryGetProperty("confidence", out _));
        Assert.True(first.TryGetProperty("fileCategory", out _));
        Assert.True(first.TryGetProperty("language", out _));
        Assert.True(first.TryGetProperty("metadata", out _));
        Assert.True(first.TryGetProperty("astConfirmed", out _));
        Assert.True(first.TryGetProperty("isSuppressed", out _));
        Assert.True(first.TryGetProperty("suppressionReason", out _));
    }

    [Fact]
    public async Task FindingsApi_HidesSuppressedByDefault_AndShowsWhenRequested()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var hiddenUri = $"/api/run/{Uri.EscapeDataString(_runId)}/findings?draw=1&start=0&length=50&order[0][column]=2&order[0][dir]=asc&columns[2][name]=severity&rule=portability.hardcoded.endpoint";
        var shownUri = $"{hiddenUri}&includeSuppressed=true";

        var hiddenResponse = await client.GetAsync(hiddenUri);
        var shownResponse = await client.GetAsync(shownUri);

        Assert.Equal(HttpStatusCode.OK, hiddenResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, shownResponse.StatusCode);

        using var hiddenJson = JsonDocument.Parse(await hiddenResponse.Content.ReadAsStringAsync());
        using var shownJson = JsonDocument.Parse(await shownResponse.Content.ReadAsStringAsync());

        var hiddenCount = hiddenJson.RootElement.GetProperty("recordsFiltered").GetInt32();
        var shownCount = shownJson.RootElement.GetProperty("recordsFiltered").GetInt32();

        Assert.Equal(0, hiddenCount);
        Assert.Equal(1, shownCount);
    }

    private async Task SeedDatabaseAsync()
    {
        var writer = new SqliteResultsWriter(_dbPath);
        var run = new ScanRun(
            RunId: _runId,
            RepoRoot: "/repo",
            CommitSha: "abc123",
            StartedAt: DateTimeOffset.UtcNow.AddMinutes(-2),
            EndedAt: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            ConfigHash: null);

        var files = new List<PersistedFile>
        {
            new("src/program.cs", FileCategory.Source, 100, "hash-1", "csharp")
        };

        var findings = new List<Finding>
        {
            new()
            {
                RunId = _runId,
                RuleId = "portability.hardcoded.dns",
                FilePath = "src/program.cs",
                Line = 12,
                Column = 20,
                Message = "Hardcoded DNS endpoint detected.",
                Snippet = "service.core.windows.net",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-1",
                Metadata = """{"engine":"roslyn","astConfirmed":true,"callsite":"HttpClient.GetAsync","context":"InvocationExpression"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "portability.hardcoded.endpoint",
                FilePath = "src/program.cs",
                Line = 25,
                Column = 13,
                Message = "Hardcoded cloud management endpoint detected.",
                Snippet = "management.azure.com",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.Medium,
                Fingerprint = "fp-web-2",
                Metadata = """{"engine":"regex","suppressed":true,"suppressionReason":"fixture"}"""
            }
        };

        var rules = new List<RuleDefinition>
        {
            new("portability.hardcoded.dns", "Hardcoded DNS", FindingSeverity.Warning, "Use configuration for DNS names."),
            new("portability.hardcoded.endpoint", "Hardcoded Endpoint", FindingSeverity.Warning, "Replace hardcoded endpoint with IConfiguration lookup.")
        };

        await writer.WriteAsync(run, files, findings, rules);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath
        }.ToString());
        await connection.OpenAsync();
        _fileId = await connection.ExecuteScalarAsync<long>(
            "SELECT file_id FROM files WHERE run_id = @RunId LIMIT 1;",
            new { RunId = _runId });
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private sealed class TestWebApplicationFactory : WebApplicationFactory<global::Program>
    {
        private readonly string _dbPath;

        public TestWebApplicationFactory(string dbPath)
        {
            _dbPath = dbPath;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Database:Path"] = _dbPath
                });
            });
        }
    }
}
