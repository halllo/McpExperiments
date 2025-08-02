using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Security.Claims;

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
		public string GetVibe(string location)
		{
			var user = this.httpContextAccessor.HttpContext?.User;
			var name = user?.FindFirst("name")?.Value;
			var sub = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

			this.logger.LogInformation("[{user} ({sub})] Getting vibe in {location}.", name, sub, location);
			return $"Curious vibes for {name} in {location}.";
		}
	}
}
