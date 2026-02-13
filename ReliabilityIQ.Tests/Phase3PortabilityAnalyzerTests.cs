using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Analyzers.CSharp;
using ReliabilityIQ.Analyzers.PowerShell;
using ReliabilityIQ.Analyzers.TreeSitter;
using ReliabilityIQ.Cli;
using ReliabilityIQ.Core;

namespace ReliabilityIQ.Tests;

public sealed class Phase3PortabilityAnalyzerTests : IDisposable
{
    private readonly string _tempDir;

    public Phase3PortabilityAnalyzerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase3-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task CSharpAnalyzer_FlagsCloudSdkAndPort_AsHighConfidence()
    {
        var analyzer = new CSharpPortabilityAnalyzer();
        const string content = """
                             using Azure.Storage.Blobs;
                             using System.Net;
                             using System.Net.Sockets;
                             var blob = new BlobServiceClient("https://account.blob.core.windows.net");
                             var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                             socket.Bind(new IPEndPoint(IPAddress.Any, 7001));
                             """;

        var findings = (await analyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "src/app.cs",
            Content: content,
            FileCategory: FileCategory.Source,
            Language: "csharp",
            Configuration: null))).ToList();

        Assert.Contains(findings, finding => finding.RuleId == "portability.cloud.sdk.no_abstraction" && finding.Confidence == FindingConfidence.High);
        Assert.Contains(findings, finding => finding.RuleId == "portability.hardcoded.port" && finding.Confidence == FindingConfidence.High);
    }

    [Fact]
    public async Task CSharpAnalyzer_SupportsInlineAndFileSuppressions()
    {
        var analyzer = new CSharpPortabilityAnalyzer();
        var repoRoot = Path.Combine(_tempDir, "repo-csharp");
        Directory.CreateDirectory(Path.Combine(repoRoot, "src"));
        var suppressionPath = Path.Combine(repoRoot, "reliabilityiq.suppressions.yaml");
        await File.WriteAllTextAsync(suppressionPath, """
                                             - path: src/*.cs
                                               rule: portability.hardcoded.dns
                                             """);

        const string content = """
                             // reliabilityiq: ignore portability.hardcoded.dns reason=fixture
                             var dns = "service.core.windows.net";
                             var endpoint = "management.azure.com";
                             """;

        var findings = (await analyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "src/app.cs",
            Content: content,
            FileCategory: FileCategory.Source,
            Language: "csharp",
            Configuration: new Dictionary<string, string?>
            {
                ["repoRoot"] = repoRoot
            }))).ToList();

        Assert.DoesNotContain(findings, finding => finding.RuleId == "portability.hardcoded.dns");
    }

    [Fact]
    public async Task TreeSitterAndPowerShell_ApplySuppressionAndTestDowngrade()
    {
        var treeSitterAnalyzer = new TreeSitterPortabilityAnalyzer();
        var pythonFindings = (await treeSitterAnalyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "tests/net_client.py",
            Content: """
                     # reliabilityiq: ignore portability.hardcoded.dns reason=fixture
                     requests.get("service.core.windows.net")
                     socket.connect(("example.com", 7001))
                     """,
            FileCategory: FileCategory.Source,
            Language: "python",
            Configuration: null))).ToList();

        Assert.DoesNotContain(pythonFindings, finding => finding.RuleId == "portability.hardcoded.dns");
        Assert.Contains(pythonFindings, finding => finding.RuleId == "portability.hardcoded.port" && finding.Severity == FindingSeverity.Info);

        var repoRoot = Path.Combine(_tempDir, "repo-ps");
        Directory.CreateDirectory(Path.Combine(repoRoot, "scripts"));
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "reliabilityiq.suppressions.yaml"), """
                                                                                               - path: scripts/*.ps1
                                                                                                 rule: portability.hardcoded.endpoint
                                                                                               """);

        var powerShellAnalyzer = new PowerShellPortabilityAnalyzer();
        var powerShellFindings = (await powerShellAnalyzer.AnalyzeAsync(new AnalysisContext(
            FilePath: "scripts/deploy.ps1",
            Content: "Invoke-WebRequest \"management.azure.com\"",
            FileCategory: FileCategory.Source,
            Language: "powershell",
            Configuration: new Dictionary<string, string?>
            {
                ["repoRoot"] = repoRoot
            }))).ToList();

        Assert.DoesNotContain(powerShellFindings, finding => finding.RuleId == "portability.hardcoded.endpoint");
    }

    [Fact]
    public async Task ScanRunner_RoutesToAstAndRegexAnalyzers()
    {
        var repoRoot = Path.Combine(_tempDir, "repo-routing");
        Directory.CreateDirectory(repoRoot);
        Directory.CreateDirectory(Path.Combine(repoRoot, ".git"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "src"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "scripts"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "config"));

        await File.WriteAllTextAsync(Path.Combine(repoRoot, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567");
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "src", "app.cs"), "var uri = new Uri(\"management.azure.com\");");
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "src", "main.py"), "requests.get(\"service.core.windows.net\")");
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "scripts", "deploy.ps1"), "Invoke-WebRequest \"management.azure.com\"");
        await File.WriteAllTextAsync(Path.Combine(repoRoot, "config", "appsettings.json"), "{\"endpoint\":\"management.azure.com\"}");

        var dbPath = Path.Combine(_tempDir, "routing.db");
        var exitCode = await PortabilityScanRunner.ExecuteAsync(
            new PortabilityScanOptions(repoRoot, dbPath, FindingSeverity.Warning),
            TextWriter.Null);

        Assert.Equal(1, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = dbPath
        }.ToString());
        await connection.OpenAsync();

        var metadataRows = await connection.QueryAsync<string>("SELECT metadata FROM findings WHERE metadata IS NOT NULL;");
        var metadata = metadataRows.ToList();

        Assert.Contains(metadata, row => row.Contains("\"engine\":\"roslyn\"", StringComparison.Ordinal));
        Assert.Contains(metadata, row => row.Contains("\"engine\":\"tree-sitter\"", StringComparison.Ordinal));
        Assert.Contains(metadata, row => row.Contains("\"engine\":\"powershell-ast\"", StringComparison.Ordinal));
        Assert.Contains(metadata, row => row.Contains("\"engine\":\"regex\"", StringComparison.Ordinal));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
