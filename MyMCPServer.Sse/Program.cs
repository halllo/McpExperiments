using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol;
using ModelContextProtocol.AspNetCore.Authentication;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using MyMCPServer.Sse;
using OAuthServer;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOpenApi();
builder.Services.AddHttpContextAccessor();
builder.Services.AddMcpServer(o =>
{
	//these handlers are invoken in addition to the tools registered with `WithTools<Tool>()`
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
		//o.Stateless = true; //to get IHttpContextAccessor back with streamable-http transport, according to https://github.com/modelcontextprotocol/csharp-sdk/issues/365#issuecomment-2859953161, but it breaks SSE
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
	config.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	config.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	config.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
	//This is the cookie we are going to use for the OIDC authentication flow.
	.AddCookie(options =>
	{
		options.Cookie.Name = "MyMCPServer.Sse.Session";
	})
	//This is the remote OIDC authentication the MCP server should use.
	.AddOpenIdConnect(o =>
	{
		o.Authority = "https://localhost:5001";
		o.ClientId = "mcp_server";
		o.ClientSecret = "secret";
		o.ResponseType = OpenIdConnectResponseType.Code;
		o.Scope.Add("openid");
		o.Scope.Add("profile");
		o.Scope.Add("verification");
		o.Scope.Add("notes");
		o.Scope.Add("admin");
		o.SaveTokens = true;
		o.Events.OnTicketReceived = ctx =>
		{
			// Add the access token claims to the cookie
			var accesstoken = ctx.Properties?.GetTokenValue("access_token");
			var handler = new JsonWebTokenHandler();
			var token = handler.ReadJsonWebToken(accesstoken);
			ctx.Principal!.AddIdentity(new ClaimsIdentity(token.Claims, OpenIdConnectDefaults.AuthenticationScheme));

			// Remove the access token from the cookie
			ctx.Properties?.GetTokens().ToList().ForEach(token => ctx.Properties.UpdateTokenValue(token.Name, string.Empty));

			return Task.CompletedTask;
		};
	})
	//This is deprecated bearer authentication for the MCP endpoints, where the MCP server is also an IDP.
	.AddJwtBearer("mcp=idp", options =>
	{
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = false,//We dont want to provide a valid issuer URL here, which is changing based on local config. Validating the issuer signing key is enough.
			ValidateAudience = true,
			LifetimeValidator = (notBefore, expires, token, parameters) => expires > DateTime.UtcNow,
			ValidateIssuerSigningKey = true,
			ValidAudience = "mcp_server",
		};

		options.Events = new JwtBearerEvents
		{
			OnMessageReceived = context => { return Task.CompletedTask; },
			OnTokenValidated = context => { return Task.CompletedTask; },
			OnChallenge = context =>
			{
				var request = context.Request;
				var prmUrl = $"{request.Scheme}://{request.Host}/.well-known/oauth-selfprotected-resource";
				var headerValue = $"Bearer resource_metadata=\"{prmUrl}\"";
				context.Response.Headers["WWW-Authenticate"] = headerValue;
				context.Response.StatusCode = StatusCodes.Status401Unauthorized;
				return Task.CompletedTask;
			}
		};
	})
	//This is the new bearer authentication for the MCP endpoints, where MCP server is only a resource provider.
	.AddJwtBearer("mcp=rp", options =>
	{
		options.Authority = "https://localhost:5001";
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidAudiences = ["http://localhost:5253/bot", "https://localhost:7296/bot"],
			ValidateIssuer = true,
			ValidateIssuerSigningKey = true,
		};

		options.ForwardChallenge = McpAuthenticationDefaults.AuthenticationScheme;

		options.Events = new JwtBearerEvents
		{
			OnMessageReceived = context =>
			{
				var authHeader = context.Request.Headers["Authorization"];
				return Task.CompletedTask;
			},
			OnTokenValidated = context =>
			{
				return Task.CompletedTask;
			},
			OnChallenge = context =>
			{
				//var request = context.Request;
				//var prmUrl = $"{request.Scheme}://{request.Host}/.well-known/oauth-protected-resource";
				//var headerValue = $"Bearer resource_metadata=\"{prmUrl}\"";
				//context.Response.Headers["WWW-Authenticate"] = headerValue; is now set by `ForwardChallenge = McpAuthenticationDefaults.AuthenticationScheme;`
				//context.Response.StatusCode = StatusCodes.Status401Unauthorized;
				return Task.CompletedTask;
			}
		};
	})
	.AddMcp(options =>
	{
		//options.ResourceMetadataUri = new("/bot/.well-known/oauth-protected-resource", UriKind.Relative);
		options.ResourceMetadataUri = new("/.well-known/oauth-protected-resource/bot", UriKind.Relative);//required by MCP inspector, because it has it hardcoded and does not take it from www-authenticate header (https://github.com/modelcontextprotocol/inspector/issues/576).
		options.Events.OnResourceMetadataRequest = context =>
		{
			context.ResourceMetadata = new()
			{
				Resource = new Uri($"{context.Request.Scheme}://{context.Request.Host}/bot"),
				AuthorizationServers = { new Uri("https://localhost:5001") },
				ScopesSupported = ["openid", "profile", "verification", "notes", "admin"],//dont include "offline_access" here, as not all clients may support refresh tokens.
			};
			return Task.CompletedTask;
		};
	});

builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("mcp=idp", policy =>
	{
		policy.AuthenticationSchemes = ["mcp=idp"];
		policy.RequireAuthenticatedUser();
	});
	options.AddPolicy("mcp=rp", policy =>
	{
		policy.AuthenticationSchemes = ["mcp=rp"];
		policy.RequireAuthenticatedUser();
	});
});

//Lets configure MCP OAuth by providing the token signing key, a client repository for dynamic registration, and the JWT audience.
builder.Services.AddOAuth<SigningKey, ClientRespository>(options =>
{
	options.Audience = "mcp_server";
});

//We need to configure the signing key for the JWT bearer authentication.
builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerOptionsSigningKeyConfiguration>();







var app = builder.Build();

app.MapOpenApi();
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/hello", () => "Hello MCP!");

app.MapMcp("bot")
	//.RequireAuthorization("mcp=idp")
	.RequireAuthorization("mcp=rp")
	;
//app.MapOAuth(); //we no longer need this, as we are not an IDP anymore

//app.MapGet("/.well-known/oauth-selfprotected-resource", (HttpContext context) =>
//{
//	return Results.Json(new
//	{
//		resource = "http://localhost:5253",
//		authorization_servers = new[] { "http://localhost:5253" },
//		bearer_methods_supported = new[] { "header", "body" },
//		scopes_supported = new[] { "openid", "profile", "verification", "notes", "admin" }
//	});
//});

//app.MapGet("/.well-known/oauth-protected-resource", (HttpContext context) =>
//{
//	return Results.Json(new
//	{
//		resource = "http://localhost:5253",
//		authorization_servers = new[] { "https://localhost:5001" },
//		bearer_methods_supported = new[] { "header", "body" },
//		scopes_supported = new[] { "openid", "profile", "verification", "notes", "admin" }
//	});
//});

app.MapGet("/debug_token", async (HttpContext context, IOptions<OAuth.Options> options, OAuth.IKeyProvider keyProvider, ILoggerFactory loggerFactory, [FromQuery] string userId, [FromQuery] string? userName = null) =>
{
	ILogger logger = loggerFactory.CreateLogger("debug_token");
	var request = context.Request;
	var handler = new JsonWebTokenHandler();
	var iss = new Uri($"{request.Scheme}://{request.Host}").AbsoluteUri.TrimEnd('/');
	var accessToken = handler.CreateToken(new SecurityTokenDescriptor
	{
		Issuer = iss,
		Subject = new ClaimsIdentity(
		[
			new Claim("sub", userId),
			new Claim("name", userName ?? string.Empty),
			..new[]{ "openid", "profile", "verification", "notes", "admin" }.Select(s => new Claim("scope", s)),
		]),
		Audience = options.Value.Audience,
		Expires = DateTime.UtcNow.AddMinutes(5),
		TokenType = "Bearer",
		SigningCredentials = new SigningCredentials(await keyProvider.GetSigningKey(), SecurityAlgorithms.RsaSha256),
	});
	logger.LogWarning("Issued debug token for {User} {Id}", userName, userId);
	return Results.Ok(accessToken);
});

app.Run();







class ClientRespository : OAuth.IClientRepository
{
	public ClientRespository()
	{
		Register("mcp_server", new OAuth.ClientRegistration
		{
			ClientName = "MCP Server",
			RedirectUris = ["https://localhost:5001/signin-oidc"],
			ClientUri = "https://localhost:5001",
			GrantTypes = ["authorization_code"],
			ResponseTypes = ["code"],
			TokenEndpointAuthMethod = "client_secret_post",
			ClientSecret = "secret",
			Scopes = ["openid", "profile", "verification", "notes", "admin"],
		}).Wait();
	}

	public async Task<OAuth.ClientRegistration?> Get(string clientId)
	{
		if (File.Exists($"client_{clientId}.json"))
		{
			var clientRegistrationJson = await File.ReadAllTextAsync($"client_{clientId}.json");
			return JsonSerializer.Deserialize<OAuth.ClientRegistration>(clientRegistrationJson);
		}
		else
		{
			return null;
		}
	}

	public async Task Register(string clientId, OAuth.ClientRegistration clientRegistration)
	{
		await File.WriteAllTextAsync($"client_{clientId}.json", JsonSerializer.Serialize(clientRegistration, new JsonSerializerOptions { WriteIndented = true }));
	}
}

class SigningKey : OAuth.IKeyProvider
{
	public SigningKey(IWebHostEnvironment env)
	{
		var rsaKey = RSA.Create();
		var path = Path.Combine(env.ContentRootPath, "devkey.key");
		if (File.Exists(path))
		{
			rsaKey.ImportRSAPrivateKey(File.ReadAllBytes(path), out _);
		}
		else
		{
			var privateKey = rsaKey.ExportRSAPrivateKey();
			File.WriteAllBytes(path, privateKey);
		}

		this.SecurityKey = new RsaSecurityKey(rsaKey);
	}

	public SecurityKey SecurityKey { get; }

	public Task<SecurityKey> GetSigningKey()
	{
		return Task.FromResult(this.SecurityKey);
	}

	public void PostConfigure(string? name, JwtBearerOptions options)
	{
		options.TokenValidationParameters.IssuerSigningKey = SecurityKey;
	}
}

class JwtBearerOptionsSigningKeyConfiguration : IPostConfigureOptions<JwtBearerOptions>
{
	private readonly OAuth.IKeyProvider keyProvider;

	public JwtBearerOptionsSigningKeyConfiguration(OAuth.IKeyProvider keyProvider)
	{
		this.keyProvider = keyProvider;
	}

	public void PostConfigure(string? name, JwtBearerOptions options)
	{
		if (name == "mcp=idp")
		{
			options.TokenValidationParameters.IssuerSigningKey = keyProvider.GetSigningKey().Result;
		}
	}
}