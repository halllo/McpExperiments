using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json.Nodes;

namespace MyMCPServer.Sse
{
	[McpServerToolType]
	public class VibeTool
	{
		private readonly ILogger<VibeTool> logger;
		private readonly IHttpContextAccessor httpContextAccessor;

		public VibeTool(ILogger<VibeTool> logger, IHttpContextAccessor httpContextAccessor)
		{
			this.logger = logger;
			this.httpContextAccessor = httpContextAccessor;
		}

		[McpServerTool, Description("Gets the vibe in the provided location.")]
		public IEnumerable<ContentBlock> GetVibe(string location)
		{
			var user = this.httpContextAccessor.HttpContext?.User;
			var name = user?.FindFirst("name")?.Value;
			var sub = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			if (name is null || sub is null)
			{
				//creates an "isError:true" tool result.
				throw new McpException("Forbidden. You must be logged in to use this tool.");
			}

			this.logger.LogInformation("[{user} ({sub})] Getting vibe in {location}.", name, sub, location);

			return
			[
				new TextContentBlock { Text = $"Curious vibes for {name} in {location}." },
				// new EmbeddedResourceBlock //seems to break Claude Desktop
				// {
				// 	Resource = new BlobResourceContents
				// 	{
				// 		MimeType = "image/jpeg",
				// 		Uri = "https://images.pexels.com/photos/3779448/pexels-photo-3779448.jpeg",
				// 	},
				// 	Meta = new JsonObject
				// 	{
				// 		["altText"] = $"A man listening.",
				// 	},
				// },
			];
		}
	}
}
