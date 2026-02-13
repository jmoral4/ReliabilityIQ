using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace ReliabilityIQ.Analyzers.Dependencies;

public sealed class DependencyFileParser
{
    private static readonly Regex ExactSemVerRegex = new(@"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex NuGetExactRegex = new(@"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PythonRequirementRegex = new(@"^([A-Za-z0-9_.-]+)\s*(==|~=|>=|<=|>|<|!=)?\s*([^;\s]+)?", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SetupInstallRequiresRegex = new(@"['""]([A-Za-z0-9_.-]+\s*(?:==|~=|>=|<=|>|<|!=)\s*[^'""\s]+)['""]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex FrameworkTokenRegex = new(@"\b(netcoreapp3\.1|net5\.0|python\s*2(?:\.\d+)?|python\s*3\.6)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public IReadOnlyList<DependencyRecord> ParseDependencies(string filePath, string content)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        var fileName = Path.GetFileName(filePath);

        if (fileName.Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase))
        {
            return ParseDirectoryPackagesProps(filePath, content);
        }

        if (extension == ".csproj")
        {
            return ParseCsproj(filePath, content);
        }

        if (fileName.Equals("packages.config", StringComparison.OrdinalIgnoreCase))
        {
            return ParsePackagesConfig(filePath, content);
        }

        if (fileName.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase))
        {
            return ParseRequirementsTxt(filePath, content);
        }

        if (fileName.Equals("setup.py", StringComparison.OrdinalIgnoreCase))
        {
            return ParseSetupPy(filePath, content);
        }

        if (fileName.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase))
        {
            return ParsePyProjectToml(filePath, content);
        }

        if (fileName.Equals("Cargo.toml", StringComparison.OrdinalIgnoreCase))
        {
            return ParseCargoToml(filePath, content);
        }

        if (fileName.Equals("package.json", StringComparison.OrdinalIgnoreCase))
        {
            return ParsePackageJson(filePath, content);
        }

        return [];
    }

    public IReadOnlyList<EolFrameworkMatch> ParseEolFrameworks(string filePath, string content)
    {
        var findings = new List<EolFrameworkMatch>();
        var fileName = Path.GetFileName(filePath);
        var extension = Path.GetExtension(filePath).ToLowerInvariant();

        if (extension == ".csproj")
        {
            try
            {
                var doc = XDocument.Parse(content, LoadOptions.SetLineInfo);
                foreach (var tfm in doc.Descendants().Where(e => e.Name.LocalName is "TargetFramework" or "TargetFrameworks"))
                {
                    var value = tfm.Value;
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        continue;
                    }

                    foreach (var token in value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        if (token.Equals("netcoreapp3.1", StringComparison.OrdinalIgnoreCase) ||
                            token.Equals("net5.0", StringComparison.OrdinalIgnoreCase))
                        {
                            var line = (tfm as IXmlLineInfo)?.HasLineInfo() == true ? ((IXmlLineInfo)tfm).LineNumber : 1;
                            findings.Add(new EolFrameworkMatch(filePath, line, token, "Out-of-support .NET target framework."));
                        }
                    }
                }
            }
            catch
            {
                // Best effort parsing.
            }
        }
        else if (fileName.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase) || fileName.Equals("setup.py", StringComparison.OrdinalIgnoreCase))
        {
            var lines = content.Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (line.Contains("3.6", StringComparison.OrdinalIgnoreCase) && line.Contains("python", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new EolFrameworkMatch(filePath, i + 1, "Python 3.6", "Out-of-support Python runtime."));
                }

                if (line.Contains("2.", StringComparison.OrdinalIgnoreCase) && line.Contains("python", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new EolFrameworkMatch(filePath, i + 1, "Python 2.x", "Out-of-support Python runtime."));
                }
            }
        }

        foreach (Match match in FrameworkTokenRegex.Matches(content))
        {
            if (!match.Success)
            {
                continue;
            }

            var framework = match.Groups[1].Value;
            var line = CountLine(content, match.Index);
            if (framework.Equals("netcoreapp3.1", StringComparison.OrdinalIgnoreCase) ||
                framework.Equals("net5.0", StringComparison.OrdinalIgnoreCase) ||
                framework.Contains("python 2", StringComparison.OrdinalIgnoreCase) ||
                framework.Contains("python 3.6", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new EolFrameworkMatch(filePath, line, framework, "Out-of-support framework/runtime detected."));
            }
        }

        return findings
            .DistinctBy(f => $"{f.FilePath}|{f.Line}|{f.Framework}", StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<DependencyRecord> ParseCsproj(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        try
        {
            var doc = XDocument.Parse(content, LoadOptions.SetLineInfo);
            foreach (var packageReference in doc.Descendants().Where(e => e.Name.LocalName == "PackageReference"))
            {
                var name = packageReference.Attribute("Include")?.Value ?? packageReference.Attribute("Update")?.Value;
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                var version = packageReference.Attribute("Version")?.Value ??
                              packageReference.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value ??
                              string.Empty;

                var line = (packageReference as IXmlLineInfo)?.HasLineInfo() == true ? ((IXmlLineInfo)packageReference).LineNumber : 1;
                deps.Add(BuildDependency(filePath, line, DependencyEcosystem.NuGet, name, version));
            }
        }
        catch
        {
            // Best effort parsing.
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParsePackagesConfig(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        try
        {
            var doc = XDocument.Parse(content, LoadOptions.SetLineInfo);
            foreach (var package in doc.Descendants().Where(e => e.Name.LocalName == "package"))
            {
                var id = package.Attribute("id")?.Value;
                var version = package.Attribute("version")?.Value;
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }

                var line = (package as IXmlLineInfo)?.HasLineInfo() == true ? ((IXmlLineInfo)package).LineNumber : 1;
                deps.Add(BuildDependency(filePath, line, DependencyEcosystem.NuGet, id, version ?? string.Empty));
            }
        }
        catch
        {
            // Best effort parsing.
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParseDirectoryPackagesProps(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        try
        {
            var doc = XDocument.Parse(content, LoadOptions.SetLineInfo);
            foreach (var packageVersion in doc.Descendants().Where(e => e.Name.LocalName == "PackageVersion"))
            {
                var name = packageVersion.Attribute("Include")?.Value ?? packageVersion.Attribute("Update")?.Value;
                var version = packageVersion.Attribute("Version")?.Value;
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                var line = (packageVersion as IXmlLineInfo)?.HasLineInfo() == true ? ((IXmlLineInfo)packageVersion).LineNumber : 1;
                deps.Add(BuildDependency(filePath, line, DependencyEcosystem.NuGet, name, version ?? string.Empty));
            }
        }
        catch
        {
            // Best effort parsing.
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParseRequirementsTxt(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        var lines = content.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("-"))
            {
                continue;
            }

            var match = PythonRequirementRegex.Match(line);
            if (!match.Success)
            {
                continue;
            }

            var name = match.Groups[1].Value;
            var op = match.Groups[2].Value;
            var version = match.Groups[3].Value;
            var spec = (op + version).Trim();

            deps.Add(BuildDependency(filePath, i + 1, DependencyEcosystem.PyPI, name, spec));
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParseSetupPy(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        foreach (Match match in SetupInstallRequiresRegex.Matches(content))
        {
            if (!match.Success)
            {
                continue;
            }

            var requirement = match.Groups[1].Value;
            var parsed = PythonRequirementRegex.Match(requirement);
            if (!parsed.Success)
            {
                continue;
            }

            var name = parsed.Groups[1].Value;
            var op = parsed.Groups[2].Value;
            var version = parsed.Groups[3].Value;
            var spec = (op + version).Trim();

            deps.Add(BuildDependency(filePath, CountLine(content, match.Index), DependencyEcosystem.PyPI, name, spec));
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParsePyProjectToml(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        var lines = content.Split('\n');
        var inDepsArray = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.StartsWith("[", StringComparison.Ordinal))
            {
                inDepsArray = false;
            }

            if (line.StartsWith("dependencies", StringComparison.OrdinalIgnoreCase) && line.Contains('[', StringComparison.Ordinal))
            {
                inDepsArray = true;
            }

            if (!inDepsArray)
            {
                continue;
            }

            if (line.StartsWith("]", StringComparison.Ordinal))
            {
                inDepsArray = false;
                continue;
            }

            var depToken = line.Trim().Trim(',').Trim('"', '\'');
            if (depToken.Length == 0)
            {
                continue;
            }

            var parsed = PythonRequirementRegex.Match(depToken);
            if (!parsed.Success)
            {
                continue;
            }

            var name = parsed.Groups[1].Value;
            var op = parsed.Groups[2].Value;
            var version = parsed.Groups[3].Value;
            var spec = (op + version).Trim();
            deps.Add(BuildDependency(filePath, i + 1, DependencyEcosystem.PyPI, name, spec));
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParseCargoToml(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();
        var lines = content.Split('\n');
        var inDependencySection = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.StartsWith("[", StringComparison.Ordinal))
            {
                inDependencySection = line.Equals("[dependencies]", StringComparison.OrdinalIgnoreCase) ||
                                      line.Equals("[dev-dependencies]", StringComparison.OrdinalIgnoreCase) ||
                                      line.Equals("[build-dependencies]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (!inDependencySection || line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator <= 0 || separator == line.Length - 1)
            {
                continue;
            }

            var name = line[..separator].Trim();
            var rhs = line[(separator + 1)..].Trim();
            string versionSpec;

            if (rhs.StartsWith('{'))
            {
                var versionMatch = Regex.Match(rhs, @"version\s*=\s*""([^""]+)""");
                if (!versionMatch.Success)
                {
                    continue;
                }

                versionSpec = versionMatch.Groups[1].Value;
            }
            else
            {
                versionSpec = rhs.Trim().Trim('"');
            }

            deps.Add(BuildDependency(filePath, i + 1, DependencyEcosystem.Cargo, name, versionSpec));
        }

        return deps;
    }

    private static IReadOnlyList<DependencyRecord> ParsePackageJson(string filePath, string content)
    {
        var deps = new List<DependencyRecord>();

        try
        {
            using var json = JsonDocument.Parse(content);
            var roots = new[] { "dependencies", "devDependencies" };
            foreach (var root in roots)
            {
                if (!json.RootElement.TryGetProperty(root, out var depNode) || depNode.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var property in depNode.EnumerateObject())
                {
                    deps.Add(BuildDependency(filePath, 1, DependencyEcosystem.Npm, property.Name, property.Value.GetString() ?? string.Empty));
                }
            }
        }
        catch
        {
            // Best effort parsing.
        }

        return deps;
    }

    private static DependencyRecord BuildDependency(string filePath, int line, DependencyEcosystem ecosystem, string name, string versionSpec)
    {
        var normalizedVersion = versionSpec.Trim();

        var isPinned = ecosystem switch
        {
            DependencyEcosystem.NuGet => IsPinnedNuGet(normalizedVersion),
            DependencyEcosystem.PyPI => normalizedVersion.StartsWith("==", StringComparison.Ordinal) && normalizedVersion.Length > 2,
            DependencyEcosystem.Cargo => normalizedVersion.StartsWith("=", StringComparison.Ordinal),
            DependencyEcosystem.Npm => ExactSemVerRegex.IsMatch(normalizedVersion),
            _ => false
        };

        var exactVersion = ecosystem switch
        {
            DependencyEcosystem.NuGet => ExtractNuGetExactVersion(normalizedVersion),
            DependencyEcosystem.PyPI => normalizedVersion.StartsWith("==", StringComparison.Ordinal) ? normalizedVersion[2..].Trim() : null,
            DependencyEcosystem.Cargo => normalizedVersion.StartsWith("=", StringComparison.Ordinal) ? normalizedVersion[1..].Trim() : null,
            DependencyEcosystem.Npm => ExactSemVerRegex.IsMatch(normalizedVersion) ? normalizedVersion : null,
            _ => null
        };

        return new DependencyRecord(filePath, line, ecosystem, name.Trim(), normalizedVersion, isPinned, exactVersion);
    }

    private static bool IsPinnedNuGet(string versionSpec)
    {
        if (string.IsNullOrWhiteSpace(versionSpec))
        {
            return false;
        }

        if (NuGetExactRegex.IsMatch(versionSpec))
        {
            return true;
        }

        if (versionSpec.StartsWith('[') && versionSpec.EndsWith(']'))
        {
            var inner = versionSpec[1..^1].Trim();
            return NuGetExactRegex.IsMatch(inner) && !inner.Contains(',', StringComparison.Ordinal);
        }

        return false;
    }

    private static string? ExtractNuGetExactVersion(string versionSpec)
    {
        if (NuGetExactRegex.IsMatch(versionSpec))
        {
            return versionSpec;
        }

        if (versionSpec.StartsWith('[') && versionSpec.EndsWith(']'))
        {
            var inner = versionSpec[1..^1].Trim();
            return NuGetExactRegex.IsMatch(inner) && !inner.Contains(',', StringComparison.Ordinal) ? inner : null;
        }

        return null;
    }

    private static int CountLine(string content, int index)
    {
        var line = 1;
        for (var i = 0; i < index && i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                line++;
            }
        }

        return line;
    }
}
