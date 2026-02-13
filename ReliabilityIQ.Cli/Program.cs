using System.CommandLine;
using System.Diagnostics;
using ReliabilityIQ.Core;

namespace ReliabilityIQ.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("ReliabilityIQ scanner CLI");

        var scan = new Command("scan", "Run scans");
        scan.AddCommand(CreatePortabilityCommand());
        root.AddCommand(scan);

        var server = new Command("server", "Run the ReliabilityIQ web server");
        server.AddCommand(CreateServerStartCommand());
        root.AddCommand(server);

        var invokeExitCode = await root.InvokeAsync(args).ConfigureAwait(false);
        return Environment.ExitCode != 0 ? Environment.ExitCode : invokeExitCode;
    }

    private static Command CreatePortabilityCommand()
    {
        var command = new Command("portability", "Run portability scan (AST + regex fallback) and persist findings to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");
        var suppressionsOption = new Option<FileInfo?>("--suppressions", "Optional suppression file path (default: <repo-root>/reliabilityiq.suppressions.yaml)");

        var failOnOption = new Option<string>("--fail-on", () => "error",
            "Exit with code 1 when findings at or above this severity are present. Values: error|warning|info.");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(suppressionsOption);
        command.AddOption(failOnOption);

        command.SetHandler(async (repo, db, suppressions, failOn) =>
        {
            if (!TryParseFailOn(failOn, out var failOnSeverity))
            {
                Console.Error.WriteLine("Invalid value for --fail-on. Allowed values: error, warning, info.");
                Environment.ExitCode = 2;
                return;
            }

            var options = new PortabilityScanOptions(repo.FullName, db?.FullName, failOnSeverity, suppressions?.FullName);
            var exitCode = await PortabilityScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption, suppressionsOption, failOnOption);

        return command;
    }

    private static bool TryParseFailOn(string value, out FindingSeverity severity)
    {
        severity = FindingSeverity.Error;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "error" => Assign(FindingSeverity.Error, out severity),
            "warning" => Assign(FindingSeverity.Warning, out severity),
            "info" => Assign(FindingSeverity.Info, out severity),
            _ => false
        };
    }

    private static bool Assign(FindingSeverity value, out FindingSeverity severity)
    {
        severity = value;
        return true;
    }

    private static Command CreateServerStartCommand()
    {
        var command = new Command("start", "Start the ReliabilityIQ web UI server");

        var dbOption = new Option<FileInfo>("--db", "SQLite database file path")
        {
            IsRequired = true
        };

        var portOption = new Option<int>("--port", () => 5100, "HTTP port for Kestrel");
        var noBrowserOption = new Option<bool>("--no-browser", "Do not automatically open a browser");

        command.AddOption(dbOption);
        command.AddOption(portOption);
        command.AddOption(noBrowserOption);

        command.SetHandler(async (db, port, noBrowser) =>
        {
            if (port is < 1 or > 65535)
            {
                Console.Error.WriteLine("Invalid value for --port. Allowed range: 1-65535.");
                Environment.ExitCode = 2;
                return;
            }

            var dbPath = Path.GetFullPath(db.FullName);
            if (!File.Exists(dbPath))
            {
                Console.Error.WriteLine($"Database file not found: {dbPath}");
                Environment.ExitCode = 2;
                return;
            }

            var webProjectPath = ResolveWebProjectPath();
            if (webProjectPath is null)
            {
                Console.Error.WriteLine("Unable to locate ReliabilityIQ.Web/ReliabilityIQ.Web.csproj.");
                Environment.ExitCode = 2;
                return;
            }

            var url = $"http://localhost:{port}";
            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"run --project \"{webProjectPath}\" -- --db \"{dbPath}\" --urls \"{url}\"",
                UseShellExecute = false
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                Console.Error.WriteLine("Failed to start web server process.");
                Environment.ExitCode = 2;
                return;
            }

            Console.WriteLine($"Starting web UI at {url}");
            Console.WriteLine("Press Ctrl+C to stop.");

            if (!noBrowser)
            {
                TryOpenBrowser(url);
            }

            using var cts = new CancellationTokenSource();
            ConsoleCancelEventHandler? handler = null;
            handler = (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                TryStopProcess(process);
            };
            Console.CancelKeyPress += handler;

            try
            {
                await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
                Environment.ExitCode = process.ExitCode;
            }
            catch (OperationCanceledException)
            {
                Environment.ExitCode = 0;
            }
            finally
            {
                Console.CancelKeyPress -= handler;
            }
        }, dbOption, portOption, noBrowserOption);

        return command;
    }

    private static string? ResolveWebProjectPath()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, "ReliabilityIQ.Web", "ReliabilityIQ.Web.csproj");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        return null;
    }

    private static void TryOpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch
        {
            // Browser launch is best-effort only.
        }
    }

    private static void TryStopProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best-effort shutdown.
        }
    }
}
