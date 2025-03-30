using ModelContextProtocol.Server;
using System.ComponentModel;

namespace MyMCPServer.Sse
{
	[McpServerToolType]
	public static class VibeTool
	{
		[McpServerTool, Description("Gets the vibe in the provided location.")]
		public static string GetVibe(string location)
		{
			return $"Curious vibes in {location}.";
		}
	}
}
