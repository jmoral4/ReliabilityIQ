using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using ReliabilityIQ.Core.Persistence.Queries;

namespace ReliabilityIQ.Web.Exports;

public static class ReportExportBuilder
{
    public static (string ContentType, string FileName, byte[] Content)? Build(
        string format,
        RunDetails run,
        IReadOnlyList<ExportFindingItem> findings,
        FindingsQueryFilters filters)
    {
        var normalized = format.Trim().ToLowerInvariant();
        return normalized switch
        {
            "csv" => BuildCsv(run, findings),
            "json" => BuildJson(run, findings, filters),
            "sarif" => BuildSarif(run, findings),
            "html" => BuildHtml(run, findings),
            _ => null
        };
    }

    private static (string ContentType, string FileName, byte[] Content) BuildCsv(
        RunDetails run,
        IReadOnlyList<ExportFindingItem> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("findingId,runId,ruleId,severity,confidence,filePath,line,column,message,isSuppressed,suppressionSource,suppressionReason,fingerprint");
        foreach (var finding in findings)
        {
            sb.Append(Csv(finding.FindingId.ToString())); sb.Append(',');
            sb.Append(Csv(finding.RunId)); sb.Append(',');
            sb.Append(Csv(finding.RuleId)); sb.Append(',');
            sb.Append(Csv(finding.Severity)); sb.Append(',');
            sb.Append(Csv(finding.Confidence)); sb.Append(',');
            sb.Append(Csv(finding.FilePath)); sb.Append(',');
            sb.Append(Csv(finding.Line.ToString())); sb.Append(',');
            sb.Append(Csv(finding.Column.ToString())); sb.Append(',');
            sb.Append(Csv(finding.Message)); sb.Append(',');
            sb.Append(Csv(finding.IsSuppressed ? "true" : "false")); sb.Append(',');
            sb.Append(Csv(finding.SuppressionSource)); sb.Append(',');
            sb.Append(Csv(finding.SuppressionReason)); sb.Append(',');
            sb.Append(Csv(finding.Fingerprint));
            sb.AppendLine();
        }

        var fileName = $"reliabilityiq-{SafeFile(run.RunId)}-findings.csv";
        return ("text/csv; charset=utf-8", fileName, Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static (string ContentType, string FileName, byte[] Content) BuildJson(
        RunDetails run,
        IReadOnlyList<ExportFindingItem> findings,
        FindingsQueryFilters filters)
    {
        var payload = new
        {
            metadata = new
            {
                runId = run.RunId,
                repoRoot = run.RepoRoot,
                commitSha = run.CommitSha,
                startedAt = run.StartedAt,
                endedAt = run.EndedAt,
                toolVersion = run.ToolVersion,
                generatedAt = DateTimeOffset.UtcNow,
                filters
            },
            findings
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });

        var fileName = $"reliabilityiq-{SafeFile(run.RunId)}-findings.json";
        return ("application/json; charset=utf-8", fileName, bytes);
    }

    private static (string ContentType, string FileName, byte[] Content) BuildSarif(
        RunDetails run,
        IReadOnlyList<ExportFindingItem> findings)
    {
        var ruleSet = findings
            .GroupBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .Select(group => new
            {
                id = group.Key,
                shortDescription = new { text = group.First().RuleTitle },
                fullDescription = new { text = group.First().RuleDescription },
                defaultConfiguration = new { level = ToSarifLevel(group.First().Severity) }
            })
            .OrderBy(rule => rule.id, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var results = findings.Select(finding => new
        {
            ruleId = finding.RuleId,
            level = ToSarifLevel(finding.Severity),
            message = new { text = finding.Message },
            locations = new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = finding.FilePath },
                        region = new
                        {
                            startLine = finding.Line <= 0 ? 1 : finding.Line,
                            startColumn = finding.Column <= 0 ? 1 : finding.Column
                        }
                    }
                }
            },
            fingerprints = string.IsNullOrWhiteSpace(finding.Fingerprint)
                ? null
                : new Dictionary<string, string> { ["primaryLocationLineHash"] = finding.Fingerprint },
            properties = new
            {
                confidence = finding.Confidence,
                fileCategory = finding.FileCategory,
                language = finding.Language,
                suppressed = finding.IsSuppressed,
                suppressionSource = finding.SuppressionSource,
                suppressionReason = finding.SuppressionReason
            }
        }).ToList();

        var payload = new Dictionary<string, object?>
        {
            ["version"] = "2.1.0",
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["runs"] = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "ReliabilityIQ",
                            version = run.ToolVersion,
                            informationUri = "https://github.com/",
                            rules = ruleSet
                        }
                    },
                    invocations = new[]
                    {
                        new
                        {
                            executionSuccessful = true,
                            startTimeUtc = run.StartedAt,
                            endTimeUtc = run.EndedAt
                        }
                    },
                    results
                }
            }
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });

        var fileName = $"reliabilityiq-{SafeFile(run.RunId)}-findings.sarif";
        return ("application/sarif+json; charset=utf-8", fileName, bytes);
    }

    private static (string ContentType, string FileName, byte[] Content) BuildHtml(
        RunDetails run,
        IReadOnlyList<ExportFindingItem> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html>");
        sb.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine("<title>ReliabilityIQ Report</title>");
        sb.AppendLine("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:20px;color:#1f2937}h1{margin:0 0 4px 0}table{border-collapse:collapse;width:100%;margin-top:16px}th,td{border:1px solid #d1d5db;padding:6px 8px;font-size:13px;text-align:left}th{background:#f3f4f6}.mono{font-family:Consolas,Monaco,monospace}.meta{color:#4b5563;font-size:13px}.sev-error{color:#991b1b;font-weight:600}.sev-warning{color:#92400e;font-weight:600}.sev-info{color:#1e3a8a;font-weight:600}</style>");
        sb.AppendLine("</head><body>");
        sb.AppendLine($"<h1>ReliabilityIQ Report</h1><div class=\"meta\">Run <span class=\"mono\">{Html(run.RunId)}</span> | Findings: {findings.Count} | Generated: {Html(DateTimeOffset.UtcNow.ToString("u"))}</div>");
        sb.AppendLine($"<div class=\"meta\">Repo: <span class=\"mono\">{Html(run.RepoRoot)}</span></div>");
        sb.AppendLine("<table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th><th>Suppressed</th></tr></thead><tbody>");

        foreach (var finding in findings)
        {
            var sevClass = finding.Severity switch
            {
                "Error" => "sev-error",
                "Warning" => "sev-warning",
                _ => "sev-info"
            };

            sb.Append("<tr>");
            sb.Append($"<td class=\"{sevClass}\">{Html(finding.Severity)}</td>");
            sb.Append($"<td class=\"mono\">{Html(finding.RuleId)}</td>");
            sb.Append($"<td class=\"mono\">{Html(finding.FilePath)}</td>");
            sb.Append($"<td>{finding.Line}</td>");
            sb.Append($"<td>{Html(finding.Message)}</td>");
            sb.Append($"<td>{(finding.IsSuppressed ? "yes" : "no")}</td>");
            sb.AppendLine("</tr>");
        }

        sb.AppendLine("</tbody></table></body></html>");
        var fileName = $"reliabilityiq-{SafeFile(run.RunId)}-findings.html";
        return ("text/html; charset=utf-8", fileName, Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static string ToSarifLevel(string severity)
    {
        return severity switch
        {
            "Error" => "error",
            "Warning" => "warning",
            _ => "note"
        };
    }

    private static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static string Html(string? value)
    {
        return System.Net.WebUtility.HtmlEncode(value ?? string.Empty);
    }

    private static string SafeFile(string value)
    {
        var chars = value.Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '-').ToArray();
        return new string(chars);
    }
}
