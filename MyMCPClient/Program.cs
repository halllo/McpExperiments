using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol.Transport;
using System.ClientModel;




try
{
	var h = new HttpClient();
	h.BaseAddress = new Uri("https://localhost:7148");
	h.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("MyMCPClient", "1.0"));
	//h.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX25hbWUiLCJlbWFpbCI6InVzZXJfZW1haWwiLCJEYXRlT2ZKb2luaW5nIjoiMjAyMi0wOS0xMiIsImp0aSI6ImIyZmJiODVhLWIzYTctNDBlZC1hNzYwLWYyMDQ5OTlkM2U5MSIsImV4cCI6MTc0MzYzMzQ5OSwiaXNzIjoieW91cl9pc3N1ZXIiLCJhdWQiOiJ5b3VyX2F1ZGllbmNlIn0.z-tUleLMBg6fbjPLGqYYyZx_o6n98hpSCOVV7XPUPLg");
	var c = await h.GetAsync("weatherforecast");
	if (c.StatusCode == System.Net.HttpStatusCode.Unauthorized)
	{
		var locationHeader = c.Headers.Location.AbsoluteUri;
	}
	c.EnsureSuccessStatusCode();
	var s = await c.Content.ReadAsStringAsync();
	Console.WriteLine(s);
}
catch (Exception e)
{
	Environment.Exit(1);
}








await using var mcpClient1 = await McpClientFactory.CreateAsync(new StdioClientTransport(new()
{
	Name = "Time MCP Server",
	Command = @"..\..\..\..\MyMCPServer.Stdio\bin\Debug\net9.0\MyMCPServer.Stdio.exe",
}));
var mcpClient1Tools = await mcpClient1.ListToolsAsync();

await using var mcpClient2 = await McpClientFactory.CreateAsync(new SseClientTransport(new()
{
	Name = "Vibe MCP Server",
	Endpoint = new Uri("https://localhost:7296/sse"),
}));
var mcpClient2Tools = await mcpClient2.ListToolsAsync();

var mcpTools = mcpClient1Tools.Concat(mcpClient2Tools).ToList();
Console.WriteLine("Available MCP tools:");
foreach (var tool in mcpTools)
{
	Console.WriteLine($"- {tool}");
}
Console.WriteLine();






var chatClient = new OpenAIChatClient(new OpenAI.OpenAIClient(new ApiKeyCredential("my_key"), new OpenAI.OpenAIClientOptions()
{
	Endpoint = new Uri("http://127.0.0.1:1234/v1"),//lm studio
}), "gemma-3-27b-it");


using var logFactory = LoggerFactory.Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Trace));
var client = new ChatClientBuilder(chatClient)
	.UseLogging(logFactory)
	.UseFunctionInvocation()
	.Build();


var message = "What is the current (CET) time in Karlsruhe, Germany? And what is the vibe there?";
Console.WriteLine(message);

IList<ChatMessage> messages =
[
	new(ChatRole.System, "You are a helpful assistant delivering time and vibes in one short sentence."),
	new(ChatRole.User, message)
];

var response = await client.GetResponseAsync(messages, new ChatOptions { Tools = [.. mcpTools] });

Console.WriteLine(response);

Console.WriteLine("Press enter to end.");
Console.ReadLine();
