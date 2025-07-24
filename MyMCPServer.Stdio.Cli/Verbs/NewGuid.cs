using CommandLine;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using System.ComponentModel;

namespace MyMCPServer.Cli.Stdio.Verbs
{
	[Verb("guid")]
	public class NewGuid
	{
		public async Task<string> Do(ILogger<NewGuid> logger)
		{
			var newGuid = Guid.NewGuid();
			logger.LogInformation("Generated new GUID: {Guid}", newGuid);
			return newGuid.ToString();
		}
	}

	[McpServerToolType]
	public class NewGuidMcp(ILogger<NewGuid> logger)
	{
		[McpServerTool, Description("Get a new guid.")]
		public async Task<string> GetGuid() => await new NewGuid().Do(logger);
	}
}
