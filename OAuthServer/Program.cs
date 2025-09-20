using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OAuthServer;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddAuthentication(config =>
{
	config.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	config.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	config.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
	.AddCookie(options =>
	{
		options.Cookie.Name = "OAuthServer.Session";
	})
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
	.AddJwtBearer(options =>
	{
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = false,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidAudience = "mcp_server",
		};
	});

builder.Services.AddAuthorization(options =>
{
	options.AddPolicy(JwtBearerDefaults.AuthenticationScheme, policy =>
	{
		policy.AuthenticationSchemes = [JwtBearerDefaults.AuthenticationScheme];
		policy.RequireAuthenticatedUser();
	});
});

builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerOptionsSigningKeyConfiguration>();

builder.Services.AddOAuth<SigningKey, ClientRespository>(options =>
{
	options.Audience = "mcp_server";
});






var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

//app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapOAuth("oauth");
app.MapGet("/session", (HttpContext ctx) =>
{
	return Results.Ok(new { claims = ctx.User.Claims.Select(c => new { c.Type, c.Value }) });
}).RequireAuthorization(JwtBearerDefaults.AuthenticationScheme);

app.Run();





class ClientRespository : OAuth.IClientRepository
{
	public Task<OAuth.ClientRegistration?> Get(string clientId)
	{
		if (clientId == "mcp_server")
		{
			return Task.FromResult<OAuth.ClientRegistration?>(new OAuth.ClientRegistration
			{
				ClientName = "MCP Server",
				RedirectUris = ["https://localhost:5001/signin-oidc"],
				ClientUri = "https://localhost:5001",
				GrantTypes = ["authorization_code"],
				ResponseTypes = ["code"],
				TokenEndpointAuthMethod = "client_secret_post",
				ClientSecret = "secret",
				Scopes = ["openid", "profile", "verification", "notes", "admin"],
			});
		}
		else
		{
			return Task.FromResult<OAuth.ClientRegistration?>(null);
		}
	}

	public Task Register(string clientId, OAuth.ClientRegistration clientRegistration) => throw new NotImplementedException();
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
		options.TokenValidationParameters.IssuerSigningKey = keyProvider.GetSigningKey().Result;
	}
}