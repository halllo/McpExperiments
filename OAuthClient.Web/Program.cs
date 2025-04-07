using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddAuthentication(config =>
{
	config.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	config.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	config.DefaultChallengeScheme = "oauth";
})
	.AddCookie(options =>
	{
		options.Cookie.Name = "OAuthClient.Session";
	})
	.AddOAuth("oauth", options =>
	{
		options.ClientId = "mcp_client";
		options.ClientSecret = "secret";
		options.AuthorizationEndpoint = "https://localhost:7148/oauth/authorize";
		options.TokenEndpoint = "https://localhost:7148/oauth/token";
		options.CallbackPath = "/oauth/callback";
		options.UsePkce = true;
		options.Scope.Add("openid");
		options.Scope.Add("profile");
		options.Scope.Add("notes");
		options.Scope.Add("admin");
		options.SaveTokens = true;
		options.Events.OnCreatingTicket = async ctx =>
		{
			var handler = new JsonWebTokenHandler();
			var token = handler.ReadJsonWebToken(ctx.AccessToken);
			ctx.Principal!.AddIdentity(new ClaimsIdentity(token.Claims, "oauth"));
		};
	});
builder.Services.AddAuthorization();



var app = builder.Build();
if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

app.UseHttpsRedirection();


app.MapGet("/claims", async (HttpContext ctx) =>
{

	var result = await ctx.AuthenticateAsync();
	if (result.Succeeded && result.Properties != null)
	{
		var accessToken = result.Properties.GetTokenValue("access_token");
		using HttpClient client = new();
		client.BaseAddress = new Uri("https://localhost:7148");
		client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
		using var response = await client.GetAsync("/session");
		response.EnsureSuccessStatusCode();

		return Results.Ok(new
		{
			client_claims = ctx.User.Claims.Select(c => new { c.Type, c.Value }),
			server_claims = await response.Content.ReadAsStringAsync(),
		});
	}
	else
	{
		return Results.Ok(new
		{
			client_claims = ctx.User.Claims.Select(c => new { c.Type, c.Value })
		});
	}
})
.WithName("GetClaims")
.RequireAuthorization();

app.Run();
