using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using System.ComponentModel;

var builder = Host.CreateEmptyApplicationBuilder(settings: null);
builder.Services
	.AddMcpServer()
	.WithStdioServerTransport()
	.WithToolsFromAssembly();

Console.WriteLine("Running MCP Server..."); //confuses Claude Desktop a little (there are warning toasts on startup), but it still works.
await builder.Build().RunAsync();

[McpServerToolType]
public static class TimeTool
{
	[McpServerTool, Description("Get the current time for a city")]
	public static string GetCurrentTime(string city) => $"It is {DateTime.Now.Hour}:{DateTime.Now.Minute} in {city}.";
}
