using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;


// Local tool
// await using var mcpClient1 = await McpClient.CreateAsync(new StdioClientTransport(new()
// {
// 	Name = "Stdio MCP Server",
// 	Command = @"D:\McpExperiments\MyMCPServer.Stdio\bin\Debug\net10.0\MyMCPServer.Stdio.exe",
// }));

// Local Dejure
// await using var mcpClient3 = await McpClient.CreateAsync(new StdioClientTransport(new()
// {
// 	Name = "Dejure Stdio MCP Server",
// 	Command = @"D:\DejureMcp\DejureMcp.Stdio\bin\Debug\net9.0\DejureMcp.Stdio.exe",
// }));

// Remote tool
var http = new HttpClient();
var tokenCache = new TokenCacheFile("token_cache.json");
var httpClientTransport = new HttpClientTransport(new()
{
	Name = "Vibe MCP Server",
	Endpoint = new Uri("https://gateway-mcpexperiments.dev.localhost:8443/my-mcp-server/mcp"),
	TransportMode = HttpTransportMode.StreamableHttp,
	OAuth = new()
	{
		ClientId = "mcp_console",
		RedirectUri = new Uri("http://localhost:1179/callback"),
		AuthorizationRedirectDelegate = AuthorizationUrl.Handle,
		TokenCache = tokenCache,
	},
}, http);

await using var mcpClient2 = await McpClient.CreateAsync(httpClientTransport);

var token = await tokenCache.GetTokensAsync(CancellationToken.None);
var jwtTokenHandler = new JsonWebTokenHandler();
var jwt = jwtTokenHandler.ReadJsonWebToken(token?.AccessToken ?? string.Empty);
Console.WriteLine("Authenticated:");
Console.WriteLine(JsonSerializer.Serialize(jwt.Claims.Select(c => new { c.Type, c.Value }), new JsonSerializerOptions { WriteIndented = true }));

var mcpClients = new[] { /*mcpClient1,*/ mcpClient2,/* mcpClient3 */ };












try
{
	Console.WriteLine();
	Console.WriteLine("Available MCP tools:");
	var mcpTools = mcpClients
		.ToAsyncEnumerable()
		.SelectMany(async (client, cancel) => (await client.ListToolsAsync(cancellationToken: cancel)).AsEnumerable());
	await foreach (var tool in mcpTools)
	{
		Console.WriteLine($"- {tool}");
	}
}
catch (Exception ex)
{
	Console.WriteLine($"Error connecting to MCP server: {ex.Message}");
}

try
{
	Console.WriteLine();
	Console.WriteLine("Available MCP resources:");
	var mcpResources = mcpClients
		.ToAsyncEnumerable()
		.SelectMany(async (client, cancel) =>
		{
			var rs = await client.ListResourcesAsync(cancellationToken: cancel);
			return rs.Select(r => new { client, uri = r.Uri });
		})
		.Select(async (resource, cancel) =>
		{
			var content = await resource.client.ReadResourceAsync(resource.uri, cancellationToken: cancel);
			return new { resource.uri, content };
		});
	await foreach (var resource in mcpResources)
	{
		Console.WriteLine($"- {resource.uri}");
		Console.WriteLine($"\t{resource.content.Contents.OfType<TextResourceContents>().Single().Text}");
	}
}
catch (Exception ex)
{
	Console.WriteLine($"Error getting resources: {ex.Message}");
}

try
{
	Console.WriteLine();
	Console.WriteLine("Available MCP resource templates:");
	var mcpResourceTemplates = mcpClients
		.ToAsyncEnumerable()
		.SelectMany(async (client, cancel) => (await client.ListResourceTemplatesAsync(cancellationToken: cancel)).AsEnumerable());
	await foreach (var resourceTemplate in mcpResourceTemplates)
	{
		Console.WriteLine($"- {resourceTemplate.UriTemplate}");
	}
}
catch (Exception ex)
{
	Console.WriteLine($"Error getting resource templates: {ex.Message}");
}

Console.WriteLine("Press enter to end.");
Console.ReadLine();

foreach (var mcpClient in mcpClients)
{
	await mcpClient.DisposeAsync();
}
