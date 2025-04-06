using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
	.AddCookie(options =>
	{
		options.Cookie.Name = "OAuthServer.Session";
		options.LoginPath = "/login";
	});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<DevKeys>();







var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", async (string returnUrl, HttpResponse response) =>
{
	//todo: replace with actual login logic
	response.Headers.ContentType = new string[] { "text/html" };
	await response.WriteAsync(
		$"""
		<!DOCTYPE html>
		<html>
			<head>
				<title>Login</title>
			</head>
			<body>
				<h1>Login</h1>
				<form method="post" action="/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}">
					<label for="username">Username:</label>
					<input type="text" id="username" name="username" required />
					<br />
					<label for="password">Password:</label>
					<input type="password" id="password" name="password" required />
					<br />
					<button type="submit">Login</button>
				</form>
			</body>
		</html>
		""");
});

app.MapPost("/login", async (HttpContext ctx, string returnUrl) =>
{
	await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(
	[
		new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
		new Claim(ClaimTypes.Name, "Manuel")
	], CookieAuthenticationDefaults.AuthenticationScheme)));

	return Results.Redirect(returnUrl);
});

app.MapGet("/oauth/authorize", (HttpRequest request, IDataProtectionProvider dataProtectionProvider) =>
{
	var iss = HttpUtility.UrlEncode("https://localhost:7148");
	request.Query.TryGetValue("state", out var state);

	if (!request.Query.TryGetValue("response_type", out var responseType) || responseType != "code")
	{
		return Results.BadRequest(new { error = "invalid_request", state, iss, });
	}

	if (!request.Query.TryGetValue("client_id", out var clientId) || clientId != "mcp_server")
	{
		return Results.BadRequest(new { error = "unauthorized_client", state, iss, });
	}

	request.Query.TryGetValue("code_challenge", out var codeChallenge);
	request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
	request.Query.TryGetValue("redirect_uri", out var redirectUri);
	request.Query.TryGetValue("scope", out var scope);

	var protector = dataProtectionProvider.CreateProtector("oauth");
	var authCode = new AuthCode
	{
		UserId = request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)!,
		UserName = request.HttpContext.User.FindFirstValue(ClaimTypes.Name)!,
		ClientId = clientId!,
		RedirectUri = redirectUri!,
		CodeChallenge = codeChallenge!,
		CodeChallengeMethod = codeChallengeMethod!,
		Expiry = DateTime.UtcNow.AddMinutes(5)
	};
	var code = protector.Protect(JsonSerializer.Serialize(authCode));
	return Results.Redirect($"{redirectUri}?code={code}&state={state}&iss={iss}");
}).RequireAuthorization();

app.MapPost("/oauth/token", async (HttpRequest request, DevKeys keys, IDataProtectionProvider dataProtectionProvider) =>
{
	var bodyBytes = await request.BodyReader.ReadAsync();
	var bodyContent = Encoding.UTF8.GetString(bodyBytes.Buffer);

	string grantType = "", code = "", redirectUri = "", codeVerifier = "", clientId = "", clientSecret = "";
	foreach (var part in bodyContent.Split('&'))
	{
		var subParts = part.Split('=');
		var key = subParts[0];
		var value = subParts[1];
		if (key == "grant_type") grantType = value;
		else if (key == "code") code = value;
		else if (key == "redirect_uri") redirectUri = value;
		else if (key == "code_verifier") codeVerifier = value;
		else if (key == "client_id") clientId = value;
		else if (key == "client_secret") clientSecret = value;
	}

	if (clientSecret != "secret")
	{
		return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client secret" });
	}

	var protector = dataProtectionProvider.CreateProtector("oauth");
	var codeString = protector.Unprotect(code);
	var authCode = JsonSerializer.Deserialize<AuthCode>(codeString);

	if (authCode == null) return Results.BadRequest("Authorization code expired");
	if (authCode.Expiry < DateTime.UtcNow) return Results.BadRequest("Authorization code expired");

	using var sha256 = SHA256.Create();
	var codeChallenge = Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));
	if (authCode == null || authCode.CodeChallenge != codeChallenge) return Results.BadRequest("Invalid code verifier");

	var handler = new JsonWebTokenHandler();
	return Results.Ok(new
	{
		access_token = handler.CreateToken(new SecurityTokenDescriptor
		{
			Claims = new Dictionary<string, object>
			{
				{ JwtRegisteredClaimNames.Sub, authCode.UserId },
				{ JwtRegisteredClaimNames.Name, authCode.UserName }
			},
			Expires = DateTime.UtcNow.AddMinutes(5),
			TokenType = "Bearer",
			SigningCredentials = new SigningCredentials(keys.RsaSecurityKey, SecurityAlgorithms.RsaSha256),
		}),
		token_type = "Bearer",
	});
});

app.Run();

class DevKeys
{
	public DevKeys(IWebHostEnvironment env)
	{
		RsaKey = RSA.Create();
		var path = Path.Combine(env.ContentRootPath, "devkey.key");
		if (File.Exists(path))
		{
			RsaKey.ImportRSAPrivateKey(File.ReadAllBytes(path), out _);
		}
		else
		{
			var privateKey = RsaKey.ExportRSAPrivateKey();
			File.WriteAllBytes(path, privateKey);
		}
	}

	public RSA RsaKey { get; }
	public RsaSecurityKey RsaSecurityKey => new RsaSecurityKey(RsaKey);
}

class AuthCode
{
	public string UserId { get; set; } = null!;
	public string UserName { get; set; } = null!;
	public string ClientId { get; set; } = null!;
	public string RedirectUri { get; set; } = null!;
	public string CodeChallenge { get; set; } = null!;
	public string CodeChallengeMethod { get; set; } = null!;
	public DateTime Expiry { get; set; }
}
