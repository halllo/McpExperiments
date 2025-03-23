using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using System.ComponentModel;
using ModelContextProtocol;

var builder = Host.CreateEmptyApplicationBuilder(settings: null);
builder.Services
	.AddMcpServer()
	.WithStdioServerTransport()
	.WithTools();

//Console.WriteLine("Running MCP Server..."); //no console writing, because it confuses the Stdio transport
await builder.Build().RunAsync();

[McpToolType]
public static class TimeTool
{
	[McpTool, Description("Get the current time for a city")]
	public static string GetCurrentTime(string city) => $"It is {DateTime.Now.Hour}:{DateTime.Now.Minute} in {city}.";
}
