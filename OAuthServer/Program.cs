using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

const string ExternalLoginScheme = nameof(ExternalLoginScheme);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
	.AddCookie(options =>
	{
		options.Cookie.Name = "OAuthServer.Session";
		options.LoginPath = "/login";
	})
	.AddOpenIdConnect(ExternalLoginScheme, o =>
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
		o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
		o.Events.OnTicketReceived = async ctx =>
		{
			// Add the access token claims to the cookie
			var accesstoken = ctx.Properties?.GetTokenValue("access_token");
			var handler = new JsonWebTokenHandler();
			var token = handler.ReadJsonWebToken(accesstoken);
			ctx.Principal!.AddIdentity(new ClaimsIdentity(token.Claims, ExternalLoginScheme));

			// Remove the access token from the cookie
			ctx.Properties?.GetTokens().ToList().ForEach(token => ctx.Properties.UpdateTokenValue(token.Name, string.Empty));
		};
	});

builder.Services.AddAuthorization(options =>
{
	{//default
		var defaultPolicy = new AuthorizationPolicyBuilder();
		defaultPolicy.AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme);
		defaultPolicy.RequireAuthenticatedUser();
		options.DefaultPolicy = defaultPolicy.Build();
		options.AddPolicy("", defaultPolicy.Build());
	}
	options.AddPolicy(ExternalLoginScheme, policy =>
	{
		policy.AuthenticationSchemes = [ExternalLoginScheme];
		policy.RequireAuthenticatedUser();
	});
});

builder.Services.AddSingleton<SigningKey>();

var oauthClientConfig = new
{
	ClientId = "mcp_server",
	ClientSecret = "secret",
	Scope = "openid profile notes admin",
};




var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", async (string returnUrl, HttpContext ctx, HttpResponse response) =>
{
	var props = new AuthenticationProperties
	{
		RedirectUri = "login/callback",
		Items =
		{
			{ "return_url", returnUrl }
		}
	};
	return Results.Challenge(props, [ExternalLoginScheme]);
});

app.MapGet("/login/callback", async (HttpContext ctx) =>
{
	var result = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
	if (result.Succeeded && result.Properties != null)
	{
		var returnUrl = result.Properties.Items["return_url"]!;
		return Results.Redirect(returnUrl);
	}
	else
	{
		return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid login" });
	}
}).RequireAuthorization(ExternalLoginScheme);

app.MapGet("/oauth/authorize", (HttpRequest request, IDataProtectionProvider dataProtectionProvider) =>
{
	var iss = HttpUtility.UrlEncode("https://localhost:7148");
	request.Query.TryGetValue("state", out var state);

	if (!request.Query.TryGetValue("response_type", out var responseType) || responseType != "code")
	{
		return Results.BadRequest(new { error = "invalid_request", state, iss, });
	}

	if (!request.Query.TryGetValue("client_id", out var clientId) || clientId != oauthClientConfig.ClientId)
	{
		return Results.BadRequest(new { error = "unauthorized_client", state, iss, });
	}

	request.Query.TryGetValue("code_challenge", out var codeChallenge);
	request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
	request.Query.TryGetValue("redirect_uri", out var redirectUri);
	if (!request.Query.TryGetValue("scope", out var scope) || scope != oauthClientConfig.Scope)
	{
		return Results.BadRequest(new { error = "invalid_scope", state, iss, });
	}

	var protector = dataProtectionProvider.CreateProtector("oauth");
	var authCode = new AuthCode
	{
		UserId = request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)!,
		UserName = request.HttpContext.User.FindFirstValue("name"),
		ClientId = clientId!,
		RedirectUri = redirectUri!,
		CodeChallenge = codeChallenge!,
		CodeChallengeMethod = codeChallengeMethod!,
		Expiry = DateTime.UtcNow.AddMinutes(5)
	};
	var code = protector.Protect(JsonSerializer.Serialize(authCode));
	return Results.Redirect($"{redirectUri}?code={code}&state={state}&iss={iss}");
}).RequireAuthorization();

app.MapPost("/oauth/token", async (HttpRequest request, SigningKey signingKey, IDataProtectionProvider dataProtectionProvider) =>
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

	if (clientId != oauthClientConfig.ClientId)
	{
		return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client id" });
	}

	if (clientSecret != oauthClientConfig.ClientSecret)
	{
		return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client secret" });
	}

	if (string.IsNullOrEmpty(grantType) || grantType != "authorization_code")
	{
		return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid grant type" });
	}

	var protector = dataProtectionProvider.CreateProtector("oauth");
	var codeString = protector.Unprotect(code);
	var authCode = JsonSerializer.Deserialize<AuthCode>(codeString);

	if (authCode == null)
	{
		return Results.BadRequest(new { error = "invalid_grant", error_description = "Authorization code missing" });
	}

	if (authCode.Expiry < DateTime.UtcNow)
	{
		return Results.BadRequest(new { error = "invalid_grant", error_description = "Authorization code expired" });
	}

	if (authCode.RedirectUri != HttpUtility.UrlDecode(redirectUri))
	{
		return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid redirect uri" });
	}

	using var sha256 = SHA256.Create();
	var codeChallenge = Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));
	if (authCode == null || authCode.CodeChallenge != codeChallenge)
	{
		return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid code verifier" });
	}

	var handler = new JsonWebTokenHandler();
	return Results.Ok(new
	{
		access_token = handler.CreateToken(new SecurityTokenDescriptor
		{
			Claims = new Dictionary<string, object>
			{
				{ JwtRegisteredClaimNames.Sub, authCode.UserId },
				{ JwtRegisteredClaimNames.Name, authCode.UserName ?? string.Empty }
			},
			Expires = DateTime.UtcNow.AddMinutes(5),
			TokenType = "Bearer",
			SigningCredentials = new SigningCredentials(signingKey.RsaSecurityKey, SecurityAlgorithms.RsaSha256),
		}),
		token_type = "Bearer",
	});
});

app.Run();

class SigningKey
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

		this.RsaSecurityKey = new RsaSecurityKey(rsaKey);
	}

	public RsaSecurityKey RsaSecurityKey { get; }
}

class AuthCode
{
	public string UserId { get; set; } = null!;
	public string? UserName { get; set; }
	public string ClientId { get; set; } = null!;
	public string RedirectUri { get; set; } = null!;
	public string CodeChallenge { get; set; } = null!;
	public string CodeChallengeMethod { get; set; } = null!;
	public DateTime Expiry { get; set; }
}
