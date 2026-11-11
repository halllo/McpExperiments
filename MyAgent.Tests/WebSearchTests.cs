using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

/// <summary>
/// Calls AgentCore's managed web search (InvokeWebSearch on web-search.v1) directly, without a gateway.
/// Needs bedrock-agentcore:InvokeWebSearch on arn:aws:bedrock-agentcore:{region}:aws:tool/web-search.v1.
/// </summary>
[TestClass]
[TestCategory("Live")]   // makes real, paid AWS calls
public sealed class WebSearchTests
{
    public required TestContext TestContext { get; set; }

    [TestMethod]
    public async Task Search_ReturnsRankedResultsWithUrls()
    {
        using var host = Program.BuildHost();
        var webSearch = host.Services.GetRequiredService<WebSearch>();

        var hits = await webSearch.Search("Amazon Bedrock AgentCore web search", maxResults: 3, cancellationToken: TestContext.CancellationToken);

        foreach (var hit in hits) TestContext.WriteLine($"{hit.PublishedAt:yyyy-MM-dd} {hit.Title} {hit.Url}");
        Assert.IsNotEmpty(hits);
        Assert.IsLessThanOrEqualTo(3, hits.Count);
        Assert.IsTrue(hits.All(h => !string.IsNullOrWhiteSpace(h.Text)));
    }

    [TestMethod]
    public async Task Search_WithDomainFilter_OnlyReturnsThatDomain()
    {
        using var host = Program.BuildHost();
        var webSearch = host.Services.GetRequiredService<WebSearch>();

        var hits = await webSearch.Search("AgentCore Gateway", maxResults: 5, includeDomains: ["aws.amazon.com"], cancellationToken: TestContext.CancellationToken);

        foreach (var hit in hits) TestContext.WriteLine(hit.Url);
        Assert.IsNotEmpty(hits);
        Assert.IsTrue(hits.All(h => new Uri(h.Url!).Host.EndsWith("aws.amazon.com")));
    }
}
