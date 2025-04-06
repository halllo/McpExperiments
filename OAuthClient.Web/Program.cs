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
	})
	.AddOAuth("oauth", options =>
	{
		options.ClientId = "mcp_server";
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


app.MapGet("/claims", (HttpContext ctx) =>
{
	return Results.Ok(new
	{
		claims = ctx.User.Claims.Select(c => new { c.Type, c.Value })
	});
})
.WithName("GetClaims")
.RequireAuthorization();

app.Run();
