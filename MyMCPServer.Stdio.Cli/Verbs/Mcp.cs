using CommandLine;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MyMCPServer.Cli.Stdio.Verbs
{
	[Verb("mcp")]
	public class Mcp
	{
		public async Task Do(ILogger<Mcp> logger, IHost host)
		{
			logger.LogInformation("Starting MCP server...");
			await host.RunAsync();
			logger.LogInformation("Done.");
		}
	}
}
