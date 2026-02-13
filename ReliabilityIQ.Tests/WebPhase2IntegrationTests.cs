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
    private readonly string _baselineRunId;
    private readonly string _runId;
    private long _fileId;

    public WebPhase2IntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-web-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "results.db");
        _baselineRunId = "run-web-0";
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
        var deploy = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/deploy");
        var configDrift = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/config-drift");
        var dependencies = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/dependencies");
        var magicStrings = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/magic-strings");
        var hygiene = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/hygiene");
        var heatmap = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/heatmap");
        var churn = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/churn");
        var suppressions = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/suppressions");
        var export = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/export");
        var compare = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/compare");
        var rules = await client.GetAsync("/rules");
        var fileDetail = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/file/{_fileId}");

        Assert.Equal(HttpStatusCode.OK, home.StatusCode);
        Assert.Equal(HttpStatusCode.OK, findings.StatusCode);
        Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
        Assert.Equal(HttpStatusCode.OK, deploy.StatusCode);
        Assert.Equal(HttpStatusCode.OK, configDrift.StatusCode);
        Assert.Equal(HttpStatusCode.OK, dependencies.StatusCode);
        Assert.Equal(HttpStatusCode.OK, magicStrings.StatusCode);
        Assert.Equal(HttpStatusCode.OK, hygiene.StatusCode);
        Assert.Equal(HttpStatusCode.OK, heatmap.StatusCode);
        Assert.Equal(HttpStatusCode.OK, churn.StatusCode);
        Assert.Equal(HttpStatusCode.OK, suppressions.StatusCode);
        Assert.Equal(HttpStatusCode.OK, export.StatusCode);
        Assert.Equal(HttpStatusCode.OK, compare.StatusCode);
        Assert.Equal(HttpStatusCode.OK, rules.StatusCode);
        Assert.Equal(HttpStatusCode.OK, fileDetail.StatusCode);
    }

    [Fact]
    public async Task DeployApi_ReturnsDeploymentFindingsAndSupportsFilters()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var uri = $"/api/run/{Uri.EscapeDataString(_runId)}/deploy?draw=11&start=0&length=25&order[0][column]=2&order[0][dir]=asc&columns[2][name]=severity&artifactType=EV2&subcategory=hardcoded-values&severity=Warning";
        var response = await client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.Equal(11, root.GetProperty("draw").GetInt32());
        Assert.True(root.GetProperty("recordsTotal").GetInt32() >= 2);
        Assert.True(root.GetProperty("recordsFiltered").GetInt32() >= 1);

        var data = root.GetProperty("data");
        Assert.True(data.GetArrayLength() >= 1);
        var first = data.EnumerateArray().First();
        Assert.Equal("EV2", first.GetProperty("artifactType").GetString());
        Assert.Equal("hardcoded-values", first.GetProperty("ruleSubcategory").GetString());
        Assert.Equal("Warning", first.GetProperty("severity").GetString());
        Assert.True(first.TryGetProperty("locationPath", out _));
        Assert.True(first.TryGetProperty("ruleDescription", out _));
    }

    [Fact]
    public async Task FindingsApi_ContainsDeployFindingsViaMainTable()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var uri = $"/api/run/{Uri.EscapeDataString(_runId)}/findings?draw=4&start=0&length=25&order[0][column]=3&order[0][dir]=asc&columns[3][name]=ruleId&rulePrefix=deploy.";
        var response = await client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.True(root.GetProperty("recordsFiltered").GetInt32() >= 2);
        var ruleIds = root.GetProperty("data").EnumerateArray()
            .Select(item => item.GetProperty("ruleId").GetString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
        Assert.All(ruleIds, ruleId => Assert.StartsWith("deploy.", ruleId, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task FileDetail_ShowsDeploymentContext_ForDeploymentArtifactFiles()
    {
        await SeedDatabaseAsync();

        long deployFileId;
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _dbPath }.ToString()))
        {
            await connection.OpenAsync();
            deployFileId = await connection.ExecuteScalarAsync<long>(
                "SELECT file_id FROM files WHERE run_id = @RunId AND path = @Path LIMIT 1;",
                new { RunId = _runId, Path = "deploy/ev2/rollout.yaml" });
        }

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var response = await client.GetAsync($"/run/{Uri.EscapeDataString(_runId)}/file/{deployFileId}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("Deployment Context", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("$.rolloutSpec.subscriptionId", html, StringComparison.OrdinalIgnoreCase);
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

    [Fact]
    public async Task MagicStringsApis_ReturnRankedCandidates_WithFiltersAndModules()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var rankedResponse = await client.GetAsync(
            $"/api/run/{Uri.EscapeDataString(_runId)}/magic-strings?draw=3&minScore=3.0&minOccurrences=3&language=csharp&pathPrefix=src/domain/&scope=overall&topN=25");
        var moduleResponse = await client.GetAsync(
            $"/api/run/{Uri.EscapeDataString(_runId)}/magic-strings/modules?minScore=0.0&minOccurrences=2&topN=10");

        Assert.Equal(HttpStatusCode.OK, rankedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, moduleResponse.StatusCode);

        using var rankedJson = JsonDocument.Parse(await rankedResponse.Content.ReadAsStringAsync());
        var rankedRoot = rankedJson.RootElement;
        Assert.Equal(3, rankedRoot.GetProperty("draw").GetInt32());
        Assert.True(rankedRoot.GetProperty("recordsTotal").GetInt32() >= 2);
        Assert.True(rankedRoot.GetProperty("recordsFiltered").GetInt32() >= 1);
        var rankedData = rankedRoot.GetProperty("data");
        Assert.True(rankedData.GetArrayLength() >= 1);
        var firstCandidate = rankedData.EnumerateArray().First();
        Assert.Equal("magic-string.comparison-used", firstCandidate.GetProperty("ruleId").GetString());
        Assert.Equal("ACTIVE", firstCandidate.GetProperty("literal").GetString());
        Assert.True(firstCandidate.GetProperty("magicScore").GetDouble() >= 4.5d);
        Assert.True(firstCandidate.GetProperty("occurrenceCount").GetInt32() >= 4);
        Assert.Equal("src/domain/status.cs", firstCandidate.GetProperty("topFilePath").GetString());

        using var moduleJson = JsonDocument.Parse(await moduleResponse.Content.ReadAsStringAsync());
        var moduleRoot = moduleJson.RootElement;
        Assert.Equal(JsonValueKind.Array, moduleRoot.ValueKind);
        Assert.True(moduleRoot.GetArrayLength() >= 1);
        var firstModule = moduleRoot.EnumerateArray().First();
        Assert.True(firstModule.TryGetProperty("module", out _));
        Assert.True(firstModule.TryGetProperty("candidates", out var moduleCandidates));
        Assert.Equal(JsonValueKind.Array, moduleCandidates.ValueKind);
    }

    [Fact]
    public async Task FindingsApi_SupportsRulePrefix_ForMagicStrings()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var uri = $"/api/run/{Uri.EscapeDataString(_runId)}/findings?draw=9&start=0&length=50&order[0][column]=2&order[0][dir]=asc&columns[2][name]=severity&rulePrefix=magic-string.";
        var response = await client.GetAsync(uri);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.True(root.GetProperty("recordsFiltered").GetInt32() >= 2);
        var ruleIds = root.GetProperty("data").EnumerateArray()
            .Select(row => row.GetProperty("ruleId").GetString())
            .Where(ruleId => !string.IsNullOrWhiteSpace(ruleId))
            .ToList();
        Assert.All(ruleIds, ruleId => Assert.StartsWith("magic-string.", ruleId));
    }

    [Fact]
    public async Task ChurnApis_ReturnDataTablesAndOwnershipShape()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var churnResponse = await client.GetAsync(
            $"/api/run/{Uri.EscapeDataString(_runId)}/churn?draw=5&start=0&length=10&order[0][column]=1&order[0][dir]=desc&columns[1][name]=churnScore&minChurnScore=1.0&pathPrefix=src/");
        var ownershipResponse = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/churn/ownership");

        Assert.Equal(HttpStatusCode.OK, churnResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ownershipResponse.StatusCode);

        using var churnJson = JsonDocument.Parse(await churnResponse.Content.ReadAsStringAsync());
        var churnRoot = churnJson.RootElement;
        Assert.Equal(5, churnRoot.GetProperty("draw").GetInt32());
        Assert.True(churnRoot.GetProperty("recordsTotal").GetInt32() >= 2);
        Assert.True(churnRoot.GetProperty("recordsFiltered").GetInt32() >= 1);
        var churnData = churnRoot.GetProperty("data");
        Assert.Equal(JsonValueKind.Array, churnData.ValueKind);
        var firstRow = churnData.EnumerateArray().First();
        Assert.True(firstRow.TryGetProperty("fileId", out _));
        Assert.True(firstRow.TryGetProperty("filePath", out _));
        Assert.True(firstRow.TryGetProperty("churnScore", out _));
        Assert.True(firstRow.TryGetProperty("ownershipConcentration", out _));
        Assert.True(firstRow.TryGetProperty("isOrphaned", out _));

        using var ownershipJson = JsonDocument.Parse(await ownershipResponse.Content.ReadAsStringAsync());
        var ownershipRoot = ownershipJson.RootElement;
        Assert.Equal(JsonValueKind.Array, ownershipRoot.ValueKind);
        Assert.True(ownershipRoot.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task ConfigDriftApi_ReturnsMatrixAndMissingStatus()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var response = await client.GetAsync(
            $"/api/run/{Uri.EscapeDataString(_runId)}/config-drift/matrix?issuesOnly=true&sortBy=missing&desc=true&search=ConnectionStrings");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.True(root.GetProperty("totalRows").GetInt32() >= 1);
        Assert.True(root.GetProperty("filteredRows").GetInt32() >= 1);
        Assert.True(root.GetProperty("environments").GetArrayLength() >= 2);

        var first = root.GetProperty("data").EnumerateArray().First();
        Assert.True(first.TryGetProperty("configSet", out _));
        Assert.True(first.TryGetProperty("key", out _));
        Assert.True(first.TryGetProperty("cells", out var cells));
        var statuses = cells.EnumerateArray().Select(cell => cell.GetProperty("status").GetString()).ToList();
        Assert.Contains("missing", statuses);
    }

    [Fact]
    public async Task DependenciesApi_ReturnsPackagesWithCveAndEolData_AndSupportsSortingAndFiltering()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var response = await client.GetAsync(
            $"/api/run/{Uri.EscapeDataString(_runId)}/dependencies?sortBy=cveSeverity&desc=true&cveOnly=true&pinned=yes");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.True(root.GetProperty("totalPackages").GetInt32() >= 2);
        Assert.True(root.GetProperty("filteredPackages").GetInt32() >= 1);
        Assert.True(root.GetProperty("eolFrameworks").GetArrayLength() >= 1);

        var first = root.GetProperty("packages").EnumerateArray().First();
        Assert.True(first.GetProperty("pinned").GetBoolean());
        Assert.True(first.GetProperty("cveCount").GetInt32() >= 1);
        Assert.True(first.TryGetProperty("highestSeverity", out _));
        Assert.True(first.TryGetProperty("vulnerabilities", out var vulns));
        Assert.True(vulns.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task HeatmapApis_ReturnTreeAndDirectoryDrilldown()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var treemapResponse = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/heatmap/treemap?metric=churnHotspots");
        var directoriesResponse = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/heatmap/directories?metric=ownershipRisk");
        var detailsResponse = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/heatmap/directory-details?metric=findingDensity&path=src");

        Assert.Equal(HttpStatusCode.OK, treemapResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, directoriesResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, detailsResponse.StatusCode);

        using var treemapJson = JsonDocument.Parse(await treemapResponse.Content.ReadAsStringAsync());
        var treemapRoot = treemapJson.RootElement;
        Assert.True(treemapRoot.TryGetProperty("metricValueMax", out _));
        Assert.True(treemapRoot.TryGetProperty("root", out var treeRoot));
        Assert.True(treeRoot.TryGetProperty("path", out _));
        Assert.True(treeRoot.TryGetProperty("children", out _));

        using var detailsJson = JsonDocument.Parse(await detailsResponse.Content.ReadAsStringAsync());
        var detailsRoot = detailsJson.RootElement;
        Assert.Equal("src", detailsRoot.GetProperty("directoryPath").GetString());
        Assert.True(detailsRoot.GetProperty("fileCount").GetInt64() >= 1);
        Assert.Equal(JsonValueKind.Array, detailsRoot.GetProperty("topFiles").ValueKind);
        Assert.Equal(JsonValueKind.Array, detailsRoot.GetProperty("topRules").ValueKind);
    }

    [Fact]
    public async Task HygieneApi_ReturnsFeatureFlagsTechDebtAsyncAndAging()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var response = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/hygiene");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;

        var featureFlags = root.GetProperty("featureFlags");
        var techDebt = root.GetProperty("techDebt");
        var asyncIssues = root.GetProperty("asyncIssues");
        var aging = root.GetProperty("techDebtAging");
        var dashboard = root.GetProperty("dashboard");

        Assert.True(featureFlags.GetArrayLength() >= 2);
        Assert.True(techDebt.GetArrayLength() >= 3);
        Assert.True(asyncIssues.GetArrayLength() >= 2);
        Assert.Equal(5, aging.GetArrayLength());
        Assert.True(dashboard.GetProperty("techDebtCount").GetInt32() >= 3);
        Assert.True(dashboard.GetProperty("asyncIssueCount").GetInt32() >= 2);

        var firstFlag = featureFlags.EnumerateArray().First();
        Assert.True(firstFlag.TryGetProperty("flagName", out _));
        Assert.True(firstFlag.TryGetProperty("referenceCount", out _));
        Assert.True(firstFlag.TryGetProperty("status", out _));
        Assert.True(firstFlag.TryGetProperty("locations", out _));

        var firstDebt = techDebt.EnumerateArray().First();
        Assert.True(firstDebt.TryGetProperty("keyword", out _));
        Assert.True(firstDebt.TryGetProperty("author", out _));
        Assert.True(firstDebt.TryGetProperty("ageDays", out _));

        var firstAsync = asyncIssues.EnumerateArray().First();
        Assert.True(firstAsync.TryGetProperty("patternType", out _));
        Assert.True(firstAsync.TryGetProperty("line", out _));
        Assert.True(firstAsync.TryGetProperty("explanation", out _));
    }

    [Fact]
    public async Task RulesApis_ReturnCatalogAndFindingsAcrossRuns()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var rulesResponse = await client.GetAsync("/api/rules?category=portability");
        var findingsResponse = await client.GetAsync("/api/rules/portability.hardcoded.dns/findings");

        Assert.Equal(HttpStatusCode.OK, rulesResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, findingsResponse.StatusCode);

        using var rulesJson = JsonDocument.Parse(await rulesResponse.Content.ReadAsStringAsync());
        var rulesRoot = rulesJson.RootElement;
        Assert.Equal(JsonValueKind.Array, rulesRoot.ValueKind);
        Assert.True(rulesRoot.GetArrayLength() >= 1);
        var portabilityDns = rulesRoot.EnumerateArray()
            .First(item => item.GetProperty("ruleId").GetString() == "portability.hardcoded.dns");
        Assert.Equal("portability", portabilityDns.GetProperty("category").GetString());
        Assert.Equal("Overridden", portabilityDns.GetProperty("effectiveState").GetString());

        using var findingsJson = JsonDocument.Parse(await findingsResponse.Content.ReadAsStringAsync());
        var findingsRoot = findingsJson.RootElement;
        Assert.Equal(JsonValueKind.Array, findingsRoot.ValueKind);
        Assert.True(findingsRoot.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task SuppressionsApi_ReturnsOverviewAndSuppressedRows()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var response = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/suppressions");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.Equal(_runId, root.GetProperty("runId").GetString());
        Assert.True(root.GetProperty("suppressedFindings").GetInt64() >= 1);
        Assert.True(root.GetProperty("whatIfTotalFindings").GetInt64() > root.GetProperty("activeFindings").GetInt64());

        var items = root.GetProperty("items");
        Assert.Equal(JsonValueKind.Array, items.ValueKind);
        var first = items.EnumerateArray().First();
        Assert.Equal("allowlist", first.GetProperty("suppressionSource").GetString());
    }

    [Fact]
    public async Task ExportApi_ReturnsCsvJsonSarifAndHtml()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var csv = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/export/csv?rulePrefix=deploy.");
        var json = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/export/json?rulePrefix=deploy.");
        var sarif = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/export/sarif?rulePrefix=deploy.");
        var html = await client.GetAsync($"/api/run/{Uri.EscapeDataString(_runId)}/export/html?rulePrefix=deploy.");

        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        Assert.Equal(HttpStatusCode.OK, json.StatusCode);
        Assert.Equal(HttpStatusCode.OK, sarif.StatusCode);
        Assert.Equal(HttpStatusCode.OK, html.StatusCode);

        var csvText = await csv.Content.ReadAsStringAsync();
        Assert.Contains("findingId,runId,ruleId", csvText, StringComparison.Ordinal);
        Assert.Contains("deploy.ev2.inline_secret", csvText, StringComparison.Ordinal);

        using var jsonDoc = JsonDocument.Parse(await json.Content.ReadAsStringAsync());
        Assert.True(jsonDoc.RootElement.TryGetProperty("metadata", out _));
        Assert.True(jsonDoc.RootElement.TryGetProperty("findings", out var jsonFindings));
        Assert.True(jsonFindings.GetArrayLength() >= 1);

        using var sarifDoc = JsonDocument.Parse(await sarif.Content.ReadAsStringAsync());
        Assert.Equal("2.1.0", sarifDoc.RootElement.GetProperty("version").GetString());
        Assert.True(sarifDoc.RootElement.TryGetProperty("runs", out var runs));
        Assert.True(runs.GetArrayLength() == 1);

        var htmlText = await html.Content.ReadAsStringAsync();
        Assert.Contains("<!doctype html>", htmlText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ReliabilityIQ Report", htmlText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CompareApi_ReturnsNewFixedAndUnchanged()
    {
        await SeedDatabaseAsync();

        using var factory = new TestWebApplicationFactory(_dbPath);
        using var client = factory.CreateClient();

        var response = await client.GetAsync(
            $"/api/runs/compare?baselineRunId={Uri.EscapeDataString(_baselineRunId)}&targetRunId={Uri.EscapeDataString(_runId)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.True(root.GetProperty("newCount").GetInt64() >= 1);
        Assert.True(root.GetProperty("fixedCount").GetInt64() >= 1);
        Assert.True(root.GetProperty("unchangedCount").GetInt64() >= 1);
        Assert.True(root.GetProperty("newFindings").GetArrayLength() >= 1);
        Assert.True(root.GetProperty("fixedFindings").GetArrayLength() >= 1);
    }

    private async Task SeedDatabaseAsync()
    {
        var writer = new SqliteResultsWriter(_dbPath);
        var baselineRun = new ScanRun(
            RunId: _baselineRunId,
            RepoRoot: "/repo",
            CommitSha: "base123",
            StartedAt: DateTimeOffset.UtcNow.AddMinutes(-10),
            EndedAt: DateTimeOffset.UtcNow.AddMinutes(-9),
            ToolVersion: "0.1.0",
            ConfigHash: null);

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
            new("src/program.cs", FileCategory.Source, 100, "hash-1", "csharp"),
            new("src/domain/status.cs", FileCategory.Source, 160, "hash-2", "csharp"),
            new("src/payments/gateway.cs", FileCategory.Source, 140, "hash-3", "csharp"),
            new("deploy/ev2/rollout.yaml", FileCategory.DeploymentArtifact, 180, "hash-4", "yaml"),
            new("config/app.dev.json", FileCategory.Config, 120, "hash-5", "json"),
            new("config/app.prod.json", FileCategory.Config, 100, "hash-6", "json"),
            new("src/worker/Worker.csproj", FileCategory.Source, 120, "hash-7", "xml"),
            new("requirements.txt", FileCategory.Config, 50, "hash-8", "text")
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
                Fingerprint = "fp-shared-1",
                Metadata = """{"engine":"roslyn","astConfirmed":true,"callsite":"HttpClient.GetAsync","context":"InvocationExpression"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "portability.hardcoded.dns",
                FilePath = "src/program.cs",
                Line = 30,
                Column = 18,
                Message = "Hardcoded DNS endpoint escalated for critical path.",
                Snippet = "critical.service.windows.net",
                Severity = FindingSeverity.Error,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-override-1",
                Metadata = """{"engine":"regex","ruleVersion":"1.0.0"}"""
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
                Fingerprint = "fp-new-1",
                Metadata = """{"engine":"regex","suppressed":true,"suppressionReason":"fixture","suppressionSource":"allowlist"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "magic-string.comparison-used",
                FilePath = "src/domain/status.cs",
                Line = 10,
                Column = 15,
                Message = "Magic string candidate 'ACTIVE' score=4.5 occurrences=4.",
                Snippet = "if (status == \"ACTIVE\")",
                Severity = FindingSeverity.Info,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-3",
                Metadata = """{"strategy":"exclude-detect-score-threshold","contextSummary":"languages=csharp;contexts=EqualsExpressionSyntax","scoring":{"frequencyScore":2.3219,"usageBoost":2.0,"penalties":0.0,"magicScore":4.5},"topLocations":[{"file":"src/domain/status.cs","line":10,"column":15}],"allOccurrences":[{"file":"src/domain/status.cs","line":10,"column":15,"language":"csharp","astParent":"EqualsExpressionSyntax","callsite":"status ==","comparison":true,"conditional":true,"exception":false,"astConfirmed":true,"testCode":false,"raw":"ACTIVE"},{"file":"src/domain/status.cs","line":22,"column":19,"language":"csharp","astParent":"SwitchSectionSyntax","callsite":"switch","comparison":true,"conditional":false,"exception":false,"astConfirmed":true,"testCode":false,"raw":"ACTIVE"},{"file":"src/domain/status.cs","line":35,"column":21,"language":"csharp","astParent":"AssignmentExpressionSyntax","callsite":"dictionary","comparison":false,"conditional":false,"exception":false,"astConfirmed":true,"testCode":false,"raw":"ACTIVE"},{"file":"src/domain/status.cs","line":47,"column":14,"language":"csharp","astParent":"EqualsExpressionSyntax","callsite":"status ==","comparison":true,"conditional":true,"exception":false,"astConfirmed":true,"testCode":false,"raw":"ACTIVE"}]}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "magic-string.candidate",
                FilePath = "src/payments/gateway.cs",
                Line = 18,
                Column = 20,
                Message = "Magic string candidate 'pending_review' score=2.2 occurrences=2.",
                Snippet = "if (state == \"pending_review\")",
                Severity = FindingSeverity.Info,
                Confidence = FindingConfidence.Medium,
                Fingerprint = "fp-web-4",
                Metadata = """{"strategy":"exclude-detect-score-threshold","contextSummary":"languages=csharp;contexts=EqualsExpressionSyntax","scoring":{"frequencyScore":1.585,"usageBoost":1.5,"penalties":0.08,"magicScore":2.2},"topLocations":[{"file":"src/payments/gateway.cs","line":18,"column":20}],"allOccurrences":[{"file":"src/payments/gateway.cs","line":18,"column":20,"language":"csharp","astParent":"EqualsExpressionSyntax","callsite":"state ==","comparison":true,"conditional":true,"exception":false,"astConfirmed":true,"testCode":false,"raw":"pending_review"},{"file":"src/payments/gateway.cs","line":43,"column":28,"language":"csharp","astParent":"ArgumentSyntax","callsite":"MapState","comparison":false,"conditional":false,"exception":false,"astConfirmed":true,"testCode":false,"raw":"pending_review"}]}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "deploy.ev2.hardcoded.subscription",
                FilePath = "deploy/ev2/rollout.yaml",
                Line = 3,
                Column = 19,
                Message = "EV2 Hardcoded Subscription: '11111111-1111-4111-8111-111111111111' at $.rolloutSpec.subscriptionId.",
                Snippet = "subscriptionId: 11111111-1111-4111-8111-111111111111",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-5",
                Metadata = """{"engine":"artifact-structured","parserMode":"structured","artifactPath":"$.rolloutSpec.subscriptionId","matchedValue":"11111111-1111-4111-8111-111111111111"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "deploy.ev2.inline_secret",
                FilePath = "deploy/ev2/rollout.yaml",
                Line = 7,
                Column = 15,
                Message = "EV2 Inline Secret: 'plain-text-secret' at $.rolloutSpec.secret.",
                Snippet = "secret: plain-text-secret",
                Severity = FindingSeverity.Error,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-6",
                Metadata = """{"engine":"artifact-structured","parserMode":"structured","artifactPath":"$.rolloutSpec.secret","matchedValue":"plain-text-secret"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "config.drift.missing_key",
                FilePath = "config/app.dev.json",
                Line = 1,
                Column = 1,
                Message = "Config key 'ConnectionStrings.Default' exists in [dev] but is missing in 'prod'.",
                Snippet = null,
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-7",
                Metadata = """{"engine":"config-drift","key":"ConnectionStrings.Default","configSet":"app.json","environments":["dev","prod"],"presentEnvironments":["dev"],"missingEnvironments":["prod"],"valueDiffers":false}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "config.drift.hardcoded_env_value",
                FilePath = "config/app.dev.json",
                Line = 1,
                Column = 1,
                Message = "Config key 'FeatureFlags.Rollout' has differing environment values and appears hardcoded.",
                Snippet = null,
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.Medium,
                Fingerprint = "fp-web-8",
                Metadata = """{"engine":"config-drift","key":"FeatureFlags.Rollout","configSet":"app.json","environments":["dev","prod"],"presentEnvironments":["dev","prod"],"missingEnvironments":[],"valueDiffers":true,"valuePreviews":[{"environment":"dev","value":"enabled"},{"environment":"prod","value":"disabled"}]}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "deps.vulnerable.high",
                FilePath = "src/worker/Worker.csproj",
                Line = 8,
                Column = 1,
                Message = "Dependency 'Newtonsoft.Json 12.0.1' has 1 known vulnerabilities.",
                Snippet = null,
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-9",
                Metadata = """{"engine":"deps","dependency":"Newtonsoft.Json","ecosystem":"NuGet","version":"12.0.1","latestVersion":"13.0.3","vulnerabilities":[{"id":"GHSA-5crp-9r3c-p9vr","severity":"High","summary":"Deserialization issue in specific scenarios."}]}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "deps.unpinned_version",
                FilePath = "requirements.txt",
                Line = 1,
                Column = 1,
                Message = "Dependency 'requests' is not pinned (version spec '>=2.0').",
                Snippet = null,
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-10",
                Metadata = """{"engine":"deps","dependency":"requests","ecosystem":"PyPI","versionSpec":">=2.0","latestVersion":"2.32.3"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "deps.eol.framework",
                FilePath = "requirements.txt",
                Line = 2,
                Column = 1,
                Message = "EOL framework detected: Python 3.6.",
                Snippet = null,
                Severity = FindingSeverity.Error,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-11",
                Metadata = """{"engine":"deps","type":"framework","framework":"Python 3.6","reason":"Out-of-support Python runtime."}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "hygiene.stale_feature_flag",
                FilePath = "src/program.cs",
                Line = 61,
                Column = 13,
                Message = "Feature flag 'legacy_checkout' appears stale (3 reference(s), last changed ~260 days ago).",
                Snippet = "IsEnabled(\"legacy_checkout\")",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-12",
                Metadata = """{"engine":"hygiene","category":"feature-flag","flagName":"legacy_checkout","referenceCount":3,"definitionCount":1,"introducedDaysAgo":420,"lastChangedDaysAgo":260,"locations":[{"FilePath":"src/program.cs","Line":61},{"FilePath":"src/payments/gateway.cs","Line":22}]}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "hygiene.dead_feature_flag",
                FilePath = "src/program.cs",
                Line = 88,
                Column = 9,
                Message = "Feature flag 'dark_launch_old' appears dead (definition found, no runtime references detected).",
                Snippet = "dark_launch_old",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.Medium,
                Fingerprint = "fp-web-13",
                Metadata = """{"engine":"hygiene","category":"feature-flag","flagName":"dark_launch_old","referenceCount":0,"definitionCount":1,"locations":[{"FilePath":"src/program.cs","Line":88}]}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "hygiene.todo_old",
                FilePath = "src/program.cs",
                Line = 7,
                Column = 1,
                Message = "TODO comment indicates tech debt (age ~420 days).",
                Snippet = "// TODO: replace with rollout config",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-14",
                Metadata = """{"engine":"hygiene","category":"todo","keyword":"TODO","ageDays":420,"author":"alice@example.com"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "hygiene.fixme",
                FilePath = "src/payments/gateway.cs",
                Line = 14,
                Column = 1,
                Message = "FIXME comment indicates tech debt (age ~120 days).",
                Snippet = "// FIXME: retry policy is brittle",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-15",
                Metadata = """{"engine":"hygiene","category":"todo","keyword":"FIXME","ageDays":120,"author":"bob@example.com"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "hygiene.hack",
                FilePath = "src/domain/status.cs",
                Line = 5,
                Column = 1,
                Message = "HACK comment indicates tech debt (age ~12 days).",
                Snippet = "// HACK: temporary state mapping",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-16",
                Metadata = """{"engine":"hygiene","category":"todo","keyword":"HACK","ageDays":12,"author":"carol@example.com"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "async.sync_over_async",
                FilePath = "src/program.cs",
                Line = 45,
                Column = 20,
                Message = "Sync-over-async call detected inside an async C# method.",
                Snippet = "task.Result",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-17",
                Metadata = """{"engine":"hygiene","category":"async","pattern":"sync-over-async","method":"RunAsync"}"""
            },
            new()
            {
                RunId = _runId,
                RuleId = "thread.bad_lock_target",
                FilePath = "src/program.cs",
                Line = 48,
                Column = 17,
                Message = "Lock target uses string literal.",
                Snippet = "lock(\"global-lock\")",
                Severity = FindingSeverity.Error,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-web-18",
                Metadata = """{"engine":"hygiene","category":"thread","pattern":"lock-string-literal","target":"string-literal"}"""
            }
        };

        var rules = new List<RuleDefinition>
        {
            new("portability.hardcoded.dns", "Hardcoded DNS", FindingSeverity.Warning, "Use configuration for DNS names."),
            new("portability.hardcoded.endpoint", "Hardcoded Endpoint", FindingSeverity.Warning, "Replace hardcoded endpoint with IConfiguration lookup."),
            new("magic-string.comparison-used", "Comparison-driven magic string", FindingSeverity.Info, "Extract to enum or constant."),
            new("magic-string.candidate", "Magic string candidate", FindingSeverity.Info, "Promote to configuration or typed constant."),
            new("deploy.ev2.hardcoded.subscription", "EV2 Hardcoded Subscription", FindingSeverity.Warning, "Parameterize subscription identifiers in EV2 artifacts instead of hardcoding concrete values."),
            new("deploy.ev2.inline_secret", "EV2 Inline Secret", FindingSeverity.Error, "Replace inline secrets in EV2 artifacts with Key Vault references or secure variable resolution."),
            new("config.drift.missing_key", "Config Drift Missing Key", FindingSeverity.Warning, "A configuration key exists in one environment file but is missing in another."),
            new("config.drift.hardcoded_env_value", "Config Drift Hardcoded Value", FindingSeverity.Warning, "Configuration values differ by environment and appear hardcoded."),
            new("deps.vulnerable.high", "Dependency Vulnerability High", FindingSeverity.Warning, "Dependency has a known high-severity vulnerability."),
            new("deps.unpinned_version", "Unpinned Dependency Version", FindingSeverity.Warning, "Dependency is not pinned to an exact version."),
            new("deps.eol.framework", "EOL Framework", FindingSeverity.Error, "Out-of-support framework/runtime detected."),
            new("hygiene.stale_feature_flag", "Stale Feature Flag", FindingSeverity.Warning, "Feature flag appears stale based on age and lack of recent changes."),
            new("hygiene.dead_feature_flag", "Dead Feature Flag", FindingSeverity.Warning, "Feature flag appears defined but has no observed runtime references."),
            new("hygiene.todo_old", "Old TODO Tech Debt", FindingSeverity.Warning, "TODO-like comment is older than configured age threshold."),
            new("hygiene.fixme", "FIXME Tech Debt", FindingSeverity.Warning, "FIXME comment indicates acknowledged defect or risky behavior."),
            new("hygiene.hack", "HACK Tech Debt", FindingSeverity.Warning, "HACK/WORKAROUND/TEMP marker indicates admitted technical debt."),
            new("async.sync_over_async", "Sync-over-Async Anti-pattern", FindingSeverity.Warning, "Synchronous wait on async operation may cause deadlocks or thread starvation."),
            new("thread.bad_lock_target", "Bad Lock Target", FindingSeverity.Error, "Lock target is unsafe and can cause deadlocks."),
            new("custom.dormant.rule", "Dormant Custom Rule", FindingSeverity.Info, "No findings expected for this test rule.")
        };

        var gitMetrics = new List<GitFileMetric>
        {
            new(
                FilePath: "src/program.cs",
                LastCommitAt: DateTimeOffset.UtcNow.AddDays(-12),
                Commits30d: 2,
                Commits90d: 5,
                Commits180d: 6,
                Commits365d: 9,
                Authors365d: 3,
                OwnershipConcentration: 0.58d,
                LinesAdded365d: 220,
                LinesRemoved365d: 44,
                ChurnScore: 4.8d,
                StaleScore: 12d,
                TopAuthor: "alice@example.com",
                TopAuthorPct: 0.54d),
            new(
                FilePath: "src/domain/status.cs",
                LastCommitAt: DateTimeOffset.UtcNow.AddDays(-190),
                Commits30d: 0,
                Commits90d: 0,
                Commits180d: 1,
                Commits365d: 3,
                Authors365d: 1,
                OwnershipConcentration: 0.91d,
                LinesAdded365d: 40,
                LinesRemoved365d: 11,
                ChurnScore: 1.9d,
                StaleScore: 190d,
                TopAuthor: "bob@example.com",
                TopAuthorPct: 0.91d),
            new(
                FilePath: "src/payments/gateway.cs",
                LastCommitAt: DateTimeOffset.UtcNow.AddDays(-6),
                Commits30d: 4,
                Commits90d: 6,
                Commits180d: 7,
                Commits365d: 11,
                Authors365d: 4,
                OwnershipConcentration: 0.47d,
                LinesAdded365d: 340,
                LinesRemoved365d: 92,
                ChurnScore: 6.1d,
                StaleScore: 6d,
                TopAuthor: "carol@example.com",
                TopAuthorPct: 0.42d)
        };

        var baselineFindings = new List<Finding>
        {
            new()
            {
                RunId = _baselineRunId,
                RuleId = "portability.hardcoded.dns",
                FilePath = "src/program.cs",
                Line = 11,
                Column = 20,
                Message = "Hardcoded DNS endpoint detected.",
                Snippet = "service.core.windows.net",
                Severity = FindingSeverity.Warning,
                Confidence = FindingConfidence.High,
                Fingerprint = "fp-shared-1",
                Metadata = """{"engine":"roslyn","astConfirmed":true}"""
            },
            new()
            {
                RunId = _baselineRunId,
                RuleId = "magic-string.candidate",
                FilePath = "src/payments/gateway.cs",
                Line = 18,
                Column = 20,
                Message = "Magic string candidate 'pending_review' score=2.0 occurrences=2.",
                Snippet = "if (state == \"pending_review\")",
                Severity = FindingSeverity.Info,
                Confidence = FindingConfidence.Medium,
                Fingerprint = "fp-fixed-1",
                Metadata = """{"strategy":"exclude-detect-score-threshold"}"""
            }
        };

        var baselineGitMetrics = new List<GitFileMetric>
        {
            new(
                FilePath: "src/program.cs",
                LastCommitAt: DateTimeOffset.UtcNow.AddDays(-18),
                Commits30d: 1,
                Commits90d: 3,
                Commits180d: 5,
                Commits365d: 8,
                Authors365d: 2,
                OwnershipConcentration: 0.62d,
                LinesAdded365d: 180,
                LinesRemoved365d: 40,
                ChurnScore: 3.2d,
                StaleScore: 18d,
                TopAuthor: "alice@example.com",
                TopAuthorPct: 0.62d)
        };

        await writer.WriteAsync(baselineRun, files, baselineFindings, rules, baselineGitMetrics);
        await writer.WriteAsync(run, files, findings, rules, gitMetrics);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath
        }.ToString());
        await connection.OpenAsync();
        _fileId = await connection.ExecuteScalarAsync<long>(
            "SELECT file_id FROM files WHERE run_id = @RunId AND path = @Path LIMIT 1;",
            new { RunId = _runId, Path = "src/program.cs" });
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
