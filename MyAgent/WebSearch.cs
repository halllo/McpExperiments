using System.Text.Json;
using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;

namespace MyAgent;

public record WebSearchHit(string? Title, string? Url, DateTime? PublishedAt, string Text);

/// <summary>
/// Thin wrapper over AgentCore's managed web search (<c>InvokeWebSearch</c> on the built-in
/// <c>web-search.v1</c> tool). It is a plain data-plane call, so it needs no AgentCore Gateway:
/// the caller only needs <c>bedrock-agentcore:InvokeWebSearch</c> on
/// <c>arn:aws:bedrock-agentcore:{region}:aws:tool/web-search.v1</c>.
/// </summary>
/// <remarks>
/// Web search is only offered in a few regions (us-east-1, us-east-2, us-west-2, eu-west-1, ap-southeast-2,
/// ap-northeast-1), not in eu-central-1 where the rest of MyAgent runs. So it gets its own client, in
/// <c>AWSBedrockAgentCoreWebSearchRegion</c> (default <c>eu-west-1</c>, the closest one).
/// </remarks>
public class WebSearch(IConfiguration configuration, ILogger<WebSearch> logger)
{
    private const string webSearchId = "web-search.v1";
    public const string DefaultRegion = "eu-west-1";

    private readonly Lazy<IAmazonBedrockAgentCore> client = new(() => new AmazonBedrockAgentCoreClient(
        awsAccessKeyId: configuration["AWSBedrockAccessKeyId"],
        awsSecretAccessKey: configuration["AWSBedrockSecretAccessKey"],
        region: Amazon.RegionEndpoint.GetBySystemName(configuration["AWSBedrockAgentCoreWebSearchRegion"] ?? DefaultRegion)));

    /// <param name="query">1–200 characters; longer queries are truncated rather than rejected.</param>
    /// <param name="maxResults">1–25.</param>
    public async Task<IReadOnlyList<WebSearchHit>> Search(
        string query,
        int maxResults = 5,
        IList<string>? includeDomains = null,
        IList<string>? excludeDomains = null,
        DateTime? publishedAfter = null,
        DateTime? publishedBefore = null,
        CancellationToken cancellationToken = default)
    {
        query = query.Trim();
        if (query.Length > 200) query = query[..200];

        var request = new InvokeWebSearchRequest
        {
            WebSearchId = webSearchId,
            SearchQuery = query,
            MaxResults = Math.Clamp(maxResults, 1, 25),
        };

        var domainFilter = includeDomains is { Count: > 0 } || excludeDomains is { Count: > 0 }
            ? new DomainFilter
            {
                Include = includeDomains is { Count: > 0 } ? [.. includeDomains] : null,
                Exclude = excludeDomains is { Count: > 0 } ? [.. excludeDomains] : null,
            }
            : null;
        var dateFilter = publishedAfter is not null || publishedBefore is not null
            ? new PublishedDateFilter { PublishedAfter = publishedAfter, PublishedBefore = publishedBefore }
            : null;
        if (domainFilter is not null || dateFilter is not null)
            request.Filters = new WebSearchFilters { DomainFilter = domainFilter, PublishedDateFilter = dateFilter };

        var response = await client.Value.InvokeWebSearchAsync(request, cancellationToken);
        var hits = (response.Results ?? [])
            .Select(r => new WebSearchHit(r.Title, r.Url, r.PublishedAt, r.Text ?? ""))
            .ToList();
        logger.LogInformation("Web search {Query} returned {Count} result(s)", query, hits.Count);
        return hits;
    }

    /// <summary>The <c>web_search</c> tool the agents get.</summary>
    public static Microsoft.Extensions.AI.AIFunction CreateTool() => Microsoft.Extensions.AI.AIFunctionFactory.Create(
        method: async (IServiceProvider services, string query, int maxResults = 5, string[]? includeDomains = null, string? publishedAfter = null, CancellationToken cancellationToken = default) =>
        {
            DateTime? after = DateTime.TryParse(publishedAfter, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            var hits = await services.GetRequiredService<WebSearch>().Search(query, maxResults, includeDomains, publishedAfter: after, cancellationToken: cancellationToken);
            return JsonSerializer.Serialize(hits, JsonSerializerOptions.Web);
        },
        name: "web_search",
        description: """
            Search the public web for current information (news, recent releases, facts you are unsure of or that may have changed).
            Returns ranked results with title, url, publishedAt and an extracted text passage.
            query: at most 200 characters. maxResults: 1-25 (default 5).
            includeDomains: optional list of domains to restrict results to, e.g. ["aws.amazon.com"].
            publishedAfter: optional ISO-8601 date; only results published on or after it.
            Cite the urls of the results you use in your answer.
            """);
}
