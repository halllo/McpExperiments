using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using ModelContextProtocol;
using ModelContextProtocol.AspNetCore.Authentication;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using MyMCPServer.Sse;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

var internalIdentityServerUrl = builder.Configuration["services:identity-server:https:0"];
var identityServerUrl = "https://gateway-mcpexperiments.dev.localhost:8443/identity";
Console.WriteLine($"Using Identity Server URL: {identityServerUrl}");

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
	options.ForwardedHeaders =
	  ForwardedHeaders.XForwardedFor |
	  ForwardedHeaders.XForwardedHost |
	  ForwardedHeaders.XForwardedProto;
	// Optionally clear KnownIPNetworks and KnownProxies to trust all (for cloud/proxy scenarios)
	options.KnownIPNetworks.Clear();
	options.KnownProxies.Clear();
});

builder.Services.AddOpenApi();
builder.Services.AddHttpContextAccessor();
builder.Services.AddMcpServer(o =>
{
	//these handlers are invoked in addition to the tools registered with `WithTools<Tool>()`
	o.Handlers = new McpServerHandlers()
	{
		ListToolsHandler = (request, cancellationToken) =>
			ValueTask.FromResult(new ListToolsResult
			{
				Tools =
				[
					new Tool
						{
							Name = "echo",
							Description = "Echoes the input back to the client.",
							InputSchema = JsonSerializer.Deserialize<JsonElement>("""
								{
									"type": "object",
									"properties": {
										"message": {
											"type": "string",
											"description": "The input to echo back"
										}
									},
									"required": ["message"]
								}
								"""),
						}
				]
			}),

		CallToolHandler = (request, cancellationToken) =>
		{
			if (request.Params?.Name == "echo")
			{
				if (request.Params.Arguments?.TryGetValue("message", out var message) is not true)
				{
					throw new McpException("Missing required argument 'message'");
				}

				return ValueTask.FromResult(new CallToolResult
				{
					Content = [new TextContentBlock { Text = $"Echo: {message}" }]
				});
			}

			throw new McpException($"Unknown tool: '{request.Params?.Name}'");
		}
	};
})
	.WithHttpTransport(o =>
	{
		o.Stateless = true;
	})
	.WithTools<VibeTool>()
	;

builder.Services.AddCors(options =>
{
	options.AddDefaultPolicy(policy =>
	{
		policy
			.AllowAnyOrigin()
			.AllowAnyMethod()
			.AllowAnyHeader();
	});
});

builder.Services.AddAuthentication(config =>
{
})
	.AddJwtBearer(options =>
	{
		options.Authority = identityServerUrl;
		options.Audience = "https://gateway-mcpexperiments.dev.localhost:8443/my-mcp-server/mcp";
		options.MapInboundClaims = false;//keep claim types as they are, do not map to Microsoft-specific claim types. this is important for MCP authentication to work, as it looks for specific claim types in the token.
		options.ForwardChallenge = McpAuthenticationDefaults.AuthenticationScheme;
		options.Events = new JwtBearerEvents
		{
			OnAuthenticationFailed = context =>
			{
				var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("JwtBearerEvents");
				logger.LogError(context.Exception, "Authentication failed with exception");
				return Task.CompletedTask;
			},
			OnForbidden = context =>
			{
				var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("JwtBearerEvents");
				logger.LogWarning("Forbidden request: {path}", context.HttpContext.Request.Path);
				return Task.CompletedTask;
			}
		};
	})
	.AddMcp(options =>
	{
		options.ResourceMetadata = new()
		{
			AuthorizationServers = { identityServerUrl! },
			ScopesSupported = ["openid", "profile", "verification", "notes", "admin"],//dont include "offline_access" here, as not all clients may support refresh tokens.
		};
	})
	;

builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("mcp", policy =>
	{
		policy.AuthenticationSchemes = [JwtBearerDefaults.AuthenticationScheme];
		policy.RequireAuthenticatedUser();
	});
});






var app = builder.Build();

app.UseForwardedHeaders();
app.UsePathBase("/my-mcp-server");

app.MapDefaultEndpoints();
app.MapOpenApi();
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/hello", () => "Hello MCP!");

app.MapMcp("/mcp").RequireAuthorization("mcp");

app.Run();
