using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Configuration;
using ModelContextProtocol.Protocol.Transport;
using System.ClientModel;

var message = "What is the current (CET) time in Karlsruhe, Germany?";
Console.WriteLine(message);

McpClientOptions options = new()
{
	ClientInfo = new() { Name = "Time Client", Version = "1.0.0" }
};

var config = new McpServerConfig
{
	Id = "time",
	Name = "Time MCP Server",
	TransportType = TransportTypes.StdIo,
	TransportOptions = new Dictionary<string, string>
	{
		["command"] = @"..\..\..\..\MyMCPServer.Stdio\bin\Debug\net9.0\MyMCPServer.Stdio.exe"
	}
};

using var factory = LoggerFactory.Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Trace));
await using var mcpClient = await McpClientFactory.CreateAsync(config, options);

Console.WriteLine("MCP Tools available:");
var mcpTools = await mcpClient.ListToolsAsync();
foreach (var tool in mcpTools)
{
	Console.WriteLine($"  {tool}");
}
Console.WriteLine();





var chatClient = new OpenAIChatClient(new OpenAI.OpenAIClient(new ApiKeyCredential("my_key"), new OpenAI.OpenAIClientOptions()
{
	Endpoint = new Uri("http://127.0.0.1:1234/v1"),//lm studio
}), "hermes-3-llama-3.2-3b");

var client = new ChatClientBuilder(chatClient)
	.UseLogging(factory)
	.UseFunctionInvocation()
	.Build();

IList<ChatMessage> messages =
[
	new(ChatRole.System, "You are a helpful assistant delivering time in one sentence in a short format, like 'It is 10:08 in Paris, France.'"),
	new(ChatRole.User, message)
];



var response = await client.GetResponseAsync(messages, new ChatOptions { Tools = [.. mcpTools] });

Console.WriteLine(response);
