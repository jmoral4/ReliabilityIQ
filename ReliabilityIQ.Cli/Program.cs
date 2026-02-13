using System.CommandLine;
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

        var invokeExitCode = await root.InvokeAsync(args).ConfigureAwait(false);
        return Environment.ExitCode != 0 ? Environment.ExitCode : invokeExitCode;
    }

    private static Command CreatePortabilityCommand()
    {
        var command = new Command("portability", "Run portability regex scan and persist findings to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");

        var failOnOption = new Option<string>("--fail-on", () => "error",
            "Exit with code 1 when findings at or above this severity are present. Values: error|warning|info.");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(failOnOption);

        command.SetHandler(async (repo, db, failOn) =>
        {
            if (!TryParseFailOn(failOn, out var failOnSeverity))
            {
                Console.Error.WriteLine("Invalid value for --fail-on. Allowed values: error, warning, info.");
                Environment.ExitCode = 2;
                return;
            }

            var options = new PortabilityScanOptions(repo.FullName, db?.FullName, failOnSeverity);
            var exitCode = await PortabilityScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption, failOnOption);

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
}
