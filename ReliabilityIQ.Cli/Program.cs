using System.CommandLine;
using System.Diagnostics;
using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Configuration;
using ReliabilityIQ.Core.Discovery;

namespace ReliabilityIQ.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("ReliabilityIQ scanner CLI");

        var scan = new Command("scan", "Run scans");
        scan.AddCommand(CreatePortabilityCommand());
        scan.AddCommand(CreateMagicStringsCommand());
        scan.AddCommand(CreateChurnCommand());
        scan.AddCommand(CreateDeployCommand());
        scan.AddCommand(CreateConfigDriftCommand());
        scan.AddCommand(CreateDependenciesCommand());
        scan.AddCommand(CreateHygieneCommand());
        scan.AddCommand(CreateAllScansCommand());
        root.AddCommand(scan);

        var rules = new Command("rules", "Rule configuration commands");
        rules.AddCommand(CreateRulesValidateCommand());
        rules.AddCommand(CreateRulesListCommand());
        rules.AddCommand(CreateRulesInitCommand());
        root.AddCommand(rules);

        root.AddCommand(CreateInitCommand());

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

        var failOnOption = new Option<string?>("--fail-on",
            "Exit with code 1 when findings at or above this severity are present. Values: error|warning|info.");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(suppressionsOption);
        command.AddOption(failOnOption);

        command.SetHandler(async (repo, db, suppressions, failOn) =>
        {
            FindingSeverity? failOnSeverity = null;
            if (!string.IsNullOrWhiteSpace(failOn))
            {
                if (!TryParseFailOn(failOn, out var parsedSeverity))
                {
                    Console.Error.WriteLine("Invalid value for --fail-on. Allowed values: error, warning, info.");
                    Environment.ExitCode = 2;
                    return;
                }

                failOnSeverity = parsedSeverity;
            }

            var options = new PortabilityScanOptions(repo.FullName, db?.FullName, failOnSeverity, suppressions?.FullName);
            var exitCode = await PortabilityScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption, suppressionsOption, failOnOption);

        return command;
    }

    private static bool TryParseFailOn(string? value, out FindingSeverity severity)
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

    private static Command CreateMagicStringsCommand()
    {
        var command = new Command("magic-strings", "Run magic strings scan and persist ranked candidates to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");
        var minOccurrencesOption = new Option<int?>("--min-occurrences", "Minimum occurrence count required for a candidate.");
        var topOption = new Option<int?>("--top", "Maximum number of ranked candidates to persist.");
        var configOption = new Option<FileInfo?>("--config", "Optional magic strings YAML config path (default: <repo-root>/reliabilityiq.magicstrings.yaml)");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(minOccurrencesOption);
        command.AddOption(topOption);
        command.AddOption(configOption);

        command.SetHandler(async (repo, db, minOccurrences, top, config) =>
        {
            var options = new MagicStringsScanOptions(
                RepoPath: repo.FullName,
                DatabasePath: db?.FullName,
                MinOccurrences: minOccurrences ?? 0,
                Top: top ?? 0,
                ConfigPath: config?.FullName);

            var exitCode = await MagicStringsScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption, minOccurrencesOption, topOption, configOption);

        return command;
    }

    private static Command CreateAllScansCommand()
    {
        var command = new Command("all", "Run portability, magic strings, churn, and deploy scans");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };
        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");
        var failOnOption = new Option<string?>("--fail-on", "Exit with code 1 when portability findings at or above this severity are present. Values: error|warning|info.");
        var suppressionsOption = new Option<FileInfo?>("--suppressions", "Optional suppression file path (default: <repo-root>/reliabilityiq.suppressions.yaml)");
        var minOccurrencesOption = new Option<int?>("--min-occurrences", "Minimum occurrence count required for magic string candidates.");
        var topOption = new Option<int?>("--top", "Maximum number of ranked magic string candidates to persist.");
        var configOption = new Option<FileInfo?>("--config", "Optional magic strings YAML config path (default: <repo-root>/reliabilityiq.magicstrings.yaml)");
        var sinceOption = new Option<string?>("--since", "Git lookback window for churn scan (e.g., 90d, 180d, 365d).");
        var serviceMapOption = new Option<FileInfo?>("--service-map", "Optional service boundary mapping file (format: ServiceName=glob).");
        var ev2PathMarkersOption = new Option<string?>("--ev2-path-markers", "Semicolon-delimited EV2 path markers override.");
        var adoPathMarkersOption = new Option<string?>("--ado-path-markers", "Semicolon-delimited ADO path markers override.");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(failOnOption);
        command.AddOption(suppressionsOption);
        command.AddOption(minOccurrencesOption);
        command.AddOption(topOption);
        command.AddOption(configOption);
        command.AddOption(sinceOption);
        command.AddOption(serviceMapOption);
        command.AddOption(ev2PathMarkersOption);
        command.AddOption(adoPathMarkersOption);

        command.SetHandler(async context =>
        {
            var repo = context.ParseResult.GetValueForOption(repoOption)!;
            var db = context.ParseResult.GetValueForOption(dbOption);
            var failOn = context.ParseResult.GetValueForOption(failOnOption)!;
            var suppressions = context.ParseResult.GetValueForOption(suppressionsOption);
            var minOccurrences = context.ParseResult.GetValueForOption(minOccurrencesOption);
            var top = context.ParseResult.GetValueForOption(topOption);
            var config = context.ParseResult.GetValueForOption(configOption);
            var since = context.ParseResult.GetValueForOption(sinceOption)!;
            var serviceMap = context.ParseResult.GetValueForOption(serviceMapOption);
            var ev2PathMarkers = context.ParseResult.GetValueForOption(ev2PathMarkersOption);
            var adoPathMarkers = context.ParseResult.GetValueForOption(adoPathMarkersOption);

            FindingSeverity? failOnSeverity = null;
            if (!string.IsNullOrWhiteSpace(failOn))
            {
                if (!TryParseFailOn(failOn, out var parsedSeverity))
                {
                    Console.Error.WriteLine("Invalid value for --fail-on. Allowed values: error, warning, info.");
                    Environment.ExitCode = 2;
                    return;
                }

                failOnSeverity = parsedSeverity;
            }

            var portabilityExitCode = await PortabilityScanRunner.ExecuteAsync(
                new PortabilityScanOptions(repo.FullName, db?.FullName, failOnSeverity, suppressions?.FullName),
                Console.Out,
                CancellationToken.None).ConfigureAwait(false);

            if (portabilityExitCode == 2)
            {
                Environment.ExitCode = 2;
                return;
            }

            var magicExitCode = await MagicStringsScanRunner.ExecuteAsync(
                new MagicStringsScanOptions(repo.FullName, db?.FullName, minOccurrences ?? 0, top ?? 0, config?.FullName),
                Console.Out,
                CancellationToken.None).ConfigureAwait(false);

            if (magicExitCode == 2)
            {
                Environment.ExitCode = 2;
                return;
            }

            var churnExitCode = await ChurnScanRunner.ExecuteAsync(
                new ChurnScanOptions(repo.FullName, db?.FullName, since, serviceMap?.FullName),
                Console.Out,
                CancellationToken.None).ConfigureAwait(false);

            if (churnExitCode == 2)
            {
                Environment.ExitCode = 2;
                return;
            }

            var deployExitCode = await DeployScanRunner.ExecuteAsync(
                new DeployScanOptions(repo.FullName, db?.FullName, ev2PathMarkers, adoPathMarkers),
                Console.Out,
                CancellationToken.None).ConfigureAwait(false);

            Environment.ExitCode = deployExitCode == 2 ? 2 : portabilityExitCode;
        });

        return command;
    }

    private static Command CreateChurnCommand()
    {
        var command = new Command("churn", "Run Git churn/staleness scan and persist metrics to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");
        var sinceOption = new Option<string?>("--since", "Git lookback window (e.g., 90d, 180d, 365d).");
        var serviceMapOption = new Option<FileInfo?>("--service-map", "Optional service boundary mapping file (format: ServiceName=glob).");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(sinceOption);
        command.AddOption(serviceMapOption);

        command.SetHandler(async (repo, db, since, serviceMap) =>
        {
            var options = new ChurnScanOptions(repo.FullName, db?.FullName, since, serviceMap?.FullName);
            var exitCode = await ChurnScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption, sinceOption, serviceMapOption);

        return command;
    }

    private static Command CreateConfigDriftCommand()
    {
        var command = new Command("config-drift", "Run configuration drift scan and persist findings to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");

        command.AddOption(repoOption);
        command.AddOption(dbOption);

        command.SetHandler(async (repo, db) =>
        {
            var options = new ConfigDriftScanOptions(
                RepoPath: repo.FullName,
                DatabasePath: db?.FullName);

            var exitCode = await ConfigDriftScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption);

        return command;
    }

    private static Command CreateDependenciesCommand()
    {
        var command = new Command("deps", "Run dependency freshness/vulnerability scan and persist findings to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");

        command.AddOption(repoOption);
        command.AddOption(dbOption);

        command.SetHandler(async (repo, db) =>
        {
            var options = new DependenciesScanOptions(
                RepoPath: repo.FullName,
                DatabasePath: db?.FullName);

            var exitCode = await DependenciesScanRunner.ExecuteAsync(options, Console.Out, cancellationToken: CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption);

        return command;
    }

    private static Command CreateHygieneCommand()
    {
        var command = new Command("hygiene", "Run feature-flag, TODO/FIXME debt, and async/thread anti-pattern scans");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };
        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");

        command.AddOption(repoOption);
        command.AddOption(dbOption);

        command.SetHandler(async (repo, db) =>
        {
            var options = new HygieneScanOptions(repo.FullName, db?.FullName);
            var exitCode = await HygieneScanRunner.ExecuteAsync(options, Console.Out, cancellationToken: CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption);

        return command;
    }

    private static Command CreateRulesValidateCommand()
    {
        var command = new Command("validate", "Validate rule and allowlist configuration");
        var configOption = new Option<DirectoryInfo?>("--config", "Path to repo root or .reliabilityiq directory.");
        command.AddOption(configOption);

        command.SetHandler((configPath) =>
        {
            var result = RuleConfigurationValidator.Validate(configPath?.FullName);
            foreach (var issue in result.Issues.OrderBy(i => i.Severity).ThenBy(i => i.File, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[{issue.Severity}] {issue.File}: {issue.Message}");
            }

            if (result.Issues.Count == 0)
            {
                Console.WriteLine("Configuration is valid.");
            }

            Environment.ExitCode = result.IsValid ? 0 : 2;
        }, configOption);

        return command;
    }

    private static Command CreateRulesListCommand()
    {
        var command = new Command("list", "List effective merged rules");
        var configOption = new Option<DirectoryInfo?>("--config", "Path to repo root or .reliabilityiq directory.");
        var enabledOnlyOption = new Option<bool>("--enabled-only", "Only list enabled rules.");
        var categoryOption = new Option<string?>("--category", "Filter category (portability, magic-strings, churn, deploy-ev2, deploy-ado, config-drift, dependencies, incidents, custom).");

        command.AddOption(configOption);
        command.AddOption(enabledOnlyOption);
        command.AddOption(categoryOption);

        command.SetHandler((configPath, enabledOnly, category) =>
        {
            var bundle = RuleConfigurationLoader.LoadFromPath(configPath?.FullName);
            var rows = bundle.EffectiveRules.Values
                .OrderBy(e => RuleCatalog.GetCategory(e.Definition.RuleId), StringComparer.OrdinalIgnoreCase)
                .ThenBy(e => e.Definition.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (!string.IsNullOrWhiteSpace(category))
            {
                rows = rows.Where(r => string.Equals(RuleCatalog.GetCategory(r.Definition.RuleId), category, StringComparison.OrdinalIgnoreCase)).ToList();
            }

            if (enabledOnly)
            {
                rows = rows.Where(r => r.Enabled).ToList();
            }

            foreach (var row in rows)
            {
                Console.WriteLine($"{RuleCatalog.GetCategory(row.Definition.RuleId),-12} {row.Definition.RuleId,-55} enabled={row.Enabled,-5} severity={row.Severity,-7} source={Path.GetFileName(row.Source)}");
            }

            if (rows.Count == 0)
            {
                Console.WriteLine("No rules matched the provided filters.");
            }

            Environment.ExitCode = 0;
        }, configOption, enabledOnlyOption, categoryOption);

        return command;
    }

    private static Command CreateRulesInitCommand()
    {
        var command = new Command("init", "Initialize .reliabilityiq rule/config templates");
        var repoOption = new Option<DirectoryInfo?>("--repo", "Repository path (default: current directory).");
        command.AddOption(repoOption);

        command.SetHandler((repo) =>
        {
            var root = ResolveInitRoot(repo?.FullName);
            var created = RuleInitScaffolder.Initialize(root);
            foreach (var path in created)
            {
                Console.WriteLine($"created: {path}");
            }

            if (created.Count == 0)
            {
                Console.WriteLine("No changes made; .reliabilityiq structure already exists.");
            }

            Environment.ExitCode = 0;
        }, repoOption);

        return command;
    }

    private static Command CreateInitCommand()
    {
        var command = new Command("init", "Initialize ReliabilityIQ configuration");
        var repoOption = new Option<DirectoryInfo?>("--repo", "Repository path (default: current directory).");
        command.AddOption(repoOption);

        command.SetHandler((repo) =>
        {
            var root = ResolveInitRoot(repo?.FullName);
            var created = RuleInitScaffolder.Initialize(root);
            foreach (var path in created)
            {
                Console.WriteLine($"created: {path}");
            }

            if (created.Count == 0)
            {
                Console.WriteLine("No changes made; .reliabilityiq structure already exists.");
            }

            Environment.ExitCode = 0;
        }, repoOption);

        return command;
    }

    private static Command CreateDeployCommand()
    {
        var command = new Command("deploy", "Run EV2/ADO deployment artifact scan and persist findings to SQLite");

        var repoOption = new Option<DirectoryInfo>("--repo", "Repository path to scan")
        {
            IsRequired = true
        };

        var dbOption = new Option<FileInfo?>("--db", "SQLite database file path (default: <repo-root>/reliabilityiq-results.db)");
        var ev2PathMarkersOption = new Option<string?>("--ev2-path-markers", "Semicolon-delimited EV2 path markers override.");
        var adoPathMarkersOption = new Option<string?>("--ado-path-markers", "Semicolon-delimited ADO path markers override.");

        command.AddOption(repoOption);
        command.AddOption(dbOption);
        command.AddOption(ev2PathMarkersOption);
        command.AddOption(adoPathMarkersOption);

        command.SetHandler(async (repo, db, ev2PathMarkers, adoPathMarkers) =>
        {
            var options = new DeployScanOptions(
                RepoPath: repo.FullName,
                DatabasePath: db?.FullName,
                Ev2PathMarkers: ev2PathMarkers,
                AdoPathMarkers: adoPathMarkers);

            var exitCode = await DeployScanRunner.ExecuteAsync(options, Console.Out, CancellationToken.None).ConfigureAwait(false);
            Environment.ExitCode = exitCode;
        }, repoOption, dbOption, ev2PathMarkersOption, adoPathMarkersOption);

        return command;
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

    private static string ResolveInitRoot(string? path)
    {
        var root = string.IsNullOrWhiteSpace(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);
        if (Directory.Exists(Path.Combine(root, ".git")))
        {
            return root;
        }

        return RepoDiscovery.FindRepoRoot(root);
    }
}
