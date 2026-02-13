using ReliabilityIQ.Core;
using ReliabilityIQ.Core.Discovery;

namespace ReliabilityIQ.Tests;

public sealed class FileClassifierTests
{
    private readonly FileClassifier _classifier = new();

    [Theory]
    [InlineData("src/app/main.cs", FileCategory.Source)]
    [InlineData("config/appsettings.json", FileCategory.Config)]
    [InlineData("docs/readme.md", FileCategory.Docs)]
    [InlineData("deploy/ev2/serviceModel.json", FileCategory.DeploymentArtifact)]
    [InlineData("obj/Debug/net10.0/generated.g.cs", FileCategory.Generated)]
    [InlineData("node_modules/library/index.js", FileCategory.Vendor)]
    [InlineData(".vs/config/applicationhost.config", FileCategory.IDE)]
    public void Classify_MapsExpectedCategories(string path, FileCategory expected)
    {
        var actual = _classifier.Classify(path);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("src/file.cs", "csharp")]
    [InlineData("src/main.py", "python")]
    [InlineData("src/lib.rs", "rust")]
    [InlineData("config/app.yaml", "yaml")]
    [InlineData("docs/readme.md", "markdown")]
    [InlineData("assets/logo.png", null)]
    public void DetectLanguage_MapsCommonExtensions(string path, string? expected)
    {
        var actual = _classifier.DetectLanguage(path);
        Assert.Equal(expected, actual);
    }
}
