using System.Diagnostics;
using Dapper;
using Microsoft.Data.Sqlite;
using ReliabilityIQ.Cli;

namespace ReliabilityIQ.Tests;

public sealed class Phase25HygieneScannerTests : IDisposable
{
    private readonly string _tempDir;

    public Phase25HygieneScannerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "riq-phase25-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task HygieneScan_DetectsFeatureFlagTodoAsyncAndThreadPatterns()
    {
        var repo = Path.Combine(_tempDir, "repo");
        Directory.CreateDirectory(repo);
        Directory.CreateDirectory(Path.Combine(repo, "src"));
        Directory.CreateDirectory(Path.Combine(repo, "scripts"));
        Directory.CreateDirectory(Path.Combine(repo, "rust"));
        Directory.CreateDirectory(Path.Combine(repo, "config"));

        await File.WriteAllTextAsync(Path.Combine(repo, "src", "Sample.cs"),
            """
            using System;
            using System.Threading.Tasks;

            public class Sample
            {
                // TODO: remove once rollout is complete
                // FIXME: known transient issue
                // HACK: temporary lock implementation
                public async Task RunAsync(Task task)
                {
                    var x = task.Result;
                    task.Wait();
                    task.GetAwaiter().GetResult();
                    lock(this)
                    {
                    }

                    lock("literal")
                    {
                    }

                    var enabled = IsEnabled("old_flag");
                }

                public async void FireAndForget()
                {
                    await Task.Delay(1);
                }

                public async void Button_Click(object sender, EventArgs e)
                {
                    await Task.Delay(1);
                }

                private bool IsEnabled(string flagName) => true;
            }
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "scripts", "app.py"),
            """
            import asyncio

            async def run():
                asyncio.run(main())
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "rust", "lib.rs"),
            """
            async fn run() {
                let _value = futures::executor::block_on(async { 42 });
            }
            """);

        await File.WriteAllTextAsync(Path.Combine(repo, "config", "flags.json"),
            """
            {
              "dead_flag": true
            }
            """);

        RunGit(repo, "init .");
        RunGit(repo, "config user.name tester");
        RunGit(repo, "config user.email tester@example.com");
        RunGit(repo, "add .");
        CommitWithDate(repo, "seed hygiene fixtures", "alice@example.com", "Alice", DateTimeOffset.UtcNow.AddDays(-220));

        await File.WriteAllTextAsync(Path.Combine(repo, "README.md"), "recent touch\n");
        RunGit(repo, "add README.md");
        CommitWithDate(repo, "recent change", "bob@example.com", "Bob", DateTimeOffset.UtcNow.AddDays(-5));

        var dbPath = Path.Combine(_tempDir, "phase25.db");
        var exitCode = await HygieneScanRunner.ExecuteAsync(
            new HygieneScanOptions(repo, dbPath),
            TextWriter.Null);

        Assert.Equal(0, exitCode);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
        await connection.OpenAsync();

        var ruleIds = (await connection.QueryAsync<string>("SELECT DISTINCT rule_id FROM findings;")).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("hygiene.stale_feature_flag", ruleIds);
        Assert.Contains("hygiene.dead_feature_flag", ruleIds);
        Assert.Contains("hygiene.todo_old", ruleIds);
        Assert.Contains("hygiene.fixme", ruleIds);
        Assert.Contains("hygiene.hack", ruleIds);
        Assert.Contains("async.sync_over_async", ruleIds);
        Assert.Contains("async.async_void", ruleIds);
        Assert.Contains("async.nested_runtime", ruleIds);
        Assert.Contains("thread.bad_lock_target", ruleIds);

        var staleFlagMessage = await connection.ExecuteScalarAsync<string?>(
            "SELECT message FROM findings WHERE rule_id='hygiene.stale_feature_flag' LIMIT 1;");
        Assert.NotNull(staleFlagMessage);
        Assert.Contains("old_flag", staleFlagMessage, StringComparison.OrdinalIgnoreCase);

        var asyncVoidCount = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM findings WHERE rule_id='async.async_void';");
        Assert.Equal(1, asyncVoidCount);

        var nestedRuntimeCount = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM findings WHERE rule_id='async.nested_runtime';");
        Assert.True(nestedRuntimeCount >= 2);

        var badLockCount = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM findings WHERE rule_id='thread.bad_lock_target';");
        Assert.True(badLockCount >= 2);
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
