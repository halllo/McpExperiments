using Microsoft.Extensions.AI;
using Microsoft.Extensions.Caching.Memory;
using ModelContextProtocol.Client;
using System.ClientModel;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddMemoryCache();

builder.Services.AddTransient<SetAccessToken>();
builder.Services.AddHttpClient("token").AddAsKeyed();
builder.Services.AddHttpClient("mcp").AddHttpMessageHandler<SetAccessToken>().AddAsKeyed();

builder.Services.AddScoped(sp => new SseClientTransport(new()
{
	Name = "Vibe MCP Server",
	Endpoint = new Uri("https://localhost:7296/sse"),
}, sp.GetRequiredKeyedService<HttpClient>("mcp")));

builder.Services.AddScoped<IChatClient>(sp => new FunctionInvokingChatClient(new OpenAI.Chat.ChatClient("gemma-3-27b-it", new ApiKeyCredential("my_key"), new OpenAI.OpenAIClientOptions()
{
	Endpoint = new Uri("http://127.0.0.1:1234/v1"),//lm studio
}).AsIChatClient(), sp.GetRequiredService<ILoggerFactory>(), sp));

var app = builder.Build();
app.MapOpenApi();
app.UseHttpsRedirection();

app.MapGet("/tools", async (SseClientTransport sse) =>
{
	await using var mcpClient = await McpClientFactory.CreateAsync(sse);
	var tools = await mcpClient.ListToolsAsync();
	return Results.Ok(tools.Select(t => new { t.Name, t.Description, t.JsonSchema }));
});
app.MapGet("/invoke", async (SseClientTransport sse, IChatClient chatClient) =>
{
	await using var mcpClient = await McpClientFactory.CreateAsync(sse);
	var tools = await mcpClient.ListToolsAsync();

	IList<ChatMessage> messages =
	[
		new(ChatRole.System, "You are a helpful assistant delivering time and vibes in one short sentence."),
		new(ChatRole.User, "What is the current (CET) time in Karlsruhe, Germany? And what is the vibe there?")
	];

	var response = await chatClient.GetResponseAsync(messages, new ChatOptions { Tools = [.. tools] });
	return Results.Ok(response.Text);
});

app.Run();


public class SetAccessToken : DelegatingHandler
{
	private readonly HttpClient httpClient;
	private readonly IMemoryCache memoryCache;

	public SetAccessToken([FromKeyedServices("token")] HttpClient httpClient, IMemoryCache memoryCache)
	{
		this.httpClient = httpClient;
		this.memoryCache = memoryCache;
	}

	protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
	{
		const string cacheKey = "AccessToken";
		if (!memoryCache.TryGetValue(cacheKey, out string? token))
		{
			var tokenResponse = await httpClient.GetAsync("https://localhost:7296/debug_token?userId=123&userName=bob");
			token = await tokenResponse.Content.ReadFromJsonAsync<string>();

			memoryCache.Set(cacheKey, token, new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
		}

		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
		return await base.SendAsync(request, cancellationToken);
	}
}