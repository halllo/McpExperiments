using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol.Transport;
using System.ClientModel;
using System.Net.Http.Headers;
using System.Net.Http.Json;

await using var mcpClient1 = await McpClientFactory.CreateAsync(new StdioClientTransport(new()
{
	Name = "Time MCP Server",
	Command = @"..\..\..\..\MyMCPServer.Stdio\bin\Debug\net9.0\MyMCPServer.Stdio.exe",
}));
var mcpClient1Tools = await mcpClient1.ListToolsAsync();


var http = new HttpClient();
var tokenResponse = await http.GetAsync($"https://localhost:7296/debug_token?userId={Guid.NewGuid()}&userName={"bob"}");
var debugtoken = await tokenResponse.Content.ReadFromJsonAsync<string>();
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", debugtoken);
await using var mcpClient2 = await McpClientFactory.CreateAsync(new SseClientTransport(new()
{
	Name = "Vibe MCP Server",
	Endpoint = new Uri("https://localhost:7296/sse"),
}, http));
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
