using Microsoft.AspNetCore.Authentication.Cookies;

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
		options.AuthorizationEndpoint = "https://localhost:5001/connect/authorize";
		options.TokenEndpoint = "https://localhost:5001/connect/token";
		options.ClientId = "mcp_server";
		options.ClientSecret = "secret";
		options.CallbackPath = "/oauth/callback";
		options.UsePkce = true;
		options.Scope.Add("openid");
		options.Scope.Add("profile");
		options.Scope.Add("notes");
		options.Scope.Add("admin");
		options.SaveTokens = true;
		options.Events.OnRedirectToAuthorizationEndpoint = async ctx =>
		{
			ctx.Response.StatusCode = 401;
			ctx.Response.Headers["Location"] = ctx.RedirectUri;
			await ctx.Response.CompleteAsync();
		};
	});
builder.Services.AddAuthorization();



var app = builder.Build();
if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

app.UseHttpsRedirection();


app.MapGet("/weatherforecast", () =>
{
	var summaries = new[]
	{
		"Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
	};
	var forecast = Enumerable.Range(1, 5).Select(index =>
		new WeatherForecast
		(
			DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
			Random.Shared.Next(-20, 55),
			summaries[Random.Shared.Next(summaries.Length)]
		))
		.ToArray();
	return forecast;
})
.WithName("GetWeatherForecast")
.RequireAuthorization(); ;

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
	public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
