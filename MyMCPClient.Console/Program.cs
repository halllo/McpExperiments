using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using System.ClientModel;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Web;
using System.Linq;
using System.Text.Json;


// Local tool
// await using var mcpClient1 = await McpClientFactory.CreateAsync(new StdioClientTransport(new()
// {
// 	Name = "Time MCP Server",
// 	Command = @"..\..\..\..\MyMCPServer.Stdio\bin\Debug\net9.0\MyMCPServer.Stdio.exe",
// }));


// Remote tool
var http = new HttpClient();
//var tokenResponse = await http.GetAsync($"https://localhost:7296/debug_token?userId={Guid.NewGuid()}&userName={"bob"}");
//var debugtoken = await tokenResponse.Content.ReadFromJsonAsync<string>();
//http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", debugtoken);
await using var mcpClient2 = await McpClient.CreateAsync(new HttpClientTransport(new()
{
	Name = "Vibe MCP Server",
	Endpoint = new Uri("http://localhost:5253/bot"),
	TransportMode = HttpTransportMode.StreamableHttp,
	OAuth = new()
	{
		ClientId = "mcp_console",
		//ClientName = $"ProtectedMcpClient_{DateTime.Now:yyyyMMddHHmmss}", //we already have a client_id and dont need dynamic client registration
		RedirectUri = new Uri("http://localhost:1179/callback"),
		AuthorizationRedirectDelegate = HandleAuthorizationUrlAsync,
		Scopes = ["openid", "profile", "verification", "notes", "admin", "offline_access"],//the client we registered supports refresh tokens
		TokenCache = new TokenCacheFile("token_cache.json"),
	},
}, http));

/// Taken from https://github.com/modelcontextprotocol/csharp-sdk/blob/c0440760ac363d817cbdca87e1ab7eff7e74a025/samples/ProtectedMCPClient/Program.cs#L72
static async Task<string?> HandleAuthorizationUrlAsync(Uri authorizationUrl, Uri redirectUri, CancellationToken cancellationToken)
{
	Console.WriteLine("Starting OAuth authorization flow...");
	Console.WriteLine($"Opening browser to: {authorizationUrl}");

	var listenerPrefix = redirectUri.GetLeftPart(UriPartial.Authority);
	if (!listenerPrefix.EndsWith("/")) listenerPrefix += "/";

	using var listener = new HttpListener();
	listener.Prefixes.Add(listenerPrefix);

	try
	{
		listener.Start();
		Console.WriteLine($"Listening for OAuth callback on: {listenerPrefix}");

		OpenBrowser(authorizationUrl);

		var context = await listener.GetContextAsync();
		var query = HttpUtility.ParseQueryString(context.Request.Url?.Query ?? string.Empty);
		var code = query["code"];
		var error = query["error"];

		string responseHtml = "<html><body><h1>Authentication complete</h1><p>You can close this window now.</p></body></html>";
		byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
		context.Response.ContentLength64 = buffer.Length;
		context.Response.ContentType = "text/html";
		context.Response.OutputStream.Write(buffer, 0, buffer.Length);
		context.Response.Close();

		if (!string.IsNullOrEmpty(error))
		{
			Console.WriteLine($"Auth error: {error}");
			return null;
		}

		if (string.IsNullOrEmpty(code))
		{
			Console.WriteLine("No authorization code received");
			return null;
		}

		Console.WriteLine("Authorization code received successfully.");
		return code;
	}
	catch (Exception ex)
	{
		Console.WriteLine($"Error getting auth code: {ex.Message}");
		return null;
	}
	finally
	{
		if (listener.IsListening) listener.Stop();
	}

	static void OpenBrowser(Uri url)
	{
		try
		{
			var psi = new ProcessStartInfo
			{
				FileName = url.ToString(),
				UseShellExecute = true
			};
			Process.Start(psi);
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error opening browser. {ex.Message}");
			Console.WriteLine($"Please manually open this URL: {url}");
		}
	}
}

var mcpClients = new[] { /*mcpClient1,*/ mcpClient2 };
var mcpTools = await mcpClients.ToAsyncEnumerable().SelectManyAwait(async c => (await c.ListToolsAsync()).ToAsyncEnumerable()).ToListAsync();
Console.WriteLine("Available MCP tools:");
foreach (var tool in mcpTools)
{
	Console.WriteLine($"- {tool}");
}

Console.WriteLine("Invoking...");
var invoked = await mcpTools.First(t => t.Name == "get_vibe").InvokeAsync(new AIFunctionArguments(new Dictionary<string, object?> { { "location", "Karlsruhe" } } ));
Console.WriteLine(JsonSerializer.Serialize(invoked, new JsonSerializerOptions { WriteIndented = true }));
//todo: how to return additional contents?


// LLM
// var openAiClient = new OpenAI.OpenAIClient(new ApiKeyCredential("my_key"), new OpenAI.OpenAIClientOptions()
// {
// 	Endpoint = new Uri("http://127.0.0.1:1234/v1"),//lm studio
// });
// var openAiChatClient = openAiClient.GetChatClient("gemma-3-27b-it");
// var iChatClient = openAiChatClient.AsIChatClient();
// using var logFactory = LoggerFactory.Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Trace));
// var client = iChatClient
// 	.AsBuilder()
// 	.UseLogging(logFactory)
// 	.UseFunctionInvocation()
// 	.Build();

// var message = "What is the current (CET) time in Karlsruhe, Germany? And what is the vibe there?";
// Console.WriteLine(message);

// IList<ChatMessage> messages =
// [
// 	new(ChatRole.System, "You are a helpful assistant delivering time and vibes in one short sentence."),
// 	new(ChatRole.User, message)
// ];

// var response = await client.GetResponseAsync(messages, new ChatOptions { Tools = [.. mcpTools] });

// Console.WriteLine(response);




Console.WriteLine("Press enter to end.");
Console.ReadLine();

foreach (var mcpClient in mcpClients)
{
	await mcpClient.DisposeAsync();
}
