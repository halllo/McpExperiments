using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//todo: make this an oauth server (https://www.youtube.com/watch?v=EBVKlm0wyTE)

builder.Services.AddOpenApi();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
	.AddJwtBearer(options =>
	{
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = "your_issuer",
			ValidAudience = "your_audience",
			IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your_secret_keyyour_secret_keyyour_secret_keyyour_secret_keyyour_secret_key"))
		};
	});
builder.Services.AddAuthorization();



var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

app.UseHttpsRedirection();


app.UseAuthentication();
app.UseAuthorization();



app.MapGet("/login", () =>
{
	var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your_secret_keyyour_secret_keyyour_secret_keyyour_secret_keyyour_secret_key"));
	var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

	//If you've had the login module, you can also use the real user information here
	var claims = new[] {
		new Claim(JwtRegisteredClaimNames.Sub, "user_name"),
		new Claim(JwtRegisteredClaimNames.Email, "user_email"),
		new Claim("DateOfJoining", "2022-09-12"),
		new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
	};

	var token = new JwtSecurityToken("your_issuer",
		"your_audience",
		claims,
		expires: DateTime.Now.AddMinutes(120),
		signingCredentials: credentials);

	return new JwtSecurityTokenHandler().WriteToken(token);
});




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
.RequireAuthorization();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
	public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
