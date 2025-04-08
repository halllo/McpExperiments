using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

namespace OAuthServer
{
	public static class OAuth
	{
		public class Options
		{
			public string? ClientId { get; set; }
			public string? ClientSecret { get; set; }
			public string? Scope { get; set; }
			public string? Audience { get; set; }
			public SecurityKey? SecurityKey { get; set; }
		}

		class AuthCode
		{
			public string UserId { get; set; } = null!;
			public string? UserName { get; set; }
			public string ClientId { get; set; } = null!;
			public string[] Scopes { get; set; } = null!;
			public string RedirectUri { get; set; } = null!;
			public string CodeChallenge { get; set; } = null!;
			public string CodeChallengeMethod { get; set; } = null!;
			public DateTime Expiry { get; set; }
		}

		public static IEndpointConventionBuilder MapOAuth(this IEndpointRouteBuilder endpoints, [StringSyntax("Route")] string pattern = "oauth")
		{
			return endpoints.MapOAuth(RoutePatternFactory.Parse(pattern));
		}

		public static IEndpointConventionBuilder MapOAuth(this IEndpointRouteBuilder endpoints, RoutePattern pattern)
		{
			var routeGroup = endpoints.MapGroup(pattern);

			routeGroup.MapGet("/authorize", (HttpRequest request, IDataProtectionProvider dataProtectionProvider, IOptions<Options> options) =>
			{
				var iss = new Uri($"{request.Scheme}://{request.Host}").AbsoluteUri;
				request.Query.TryGetValue("state", out var state);

				if (!request.Query.TryGetValue("response_type", out var responseType) || responseType != "code")
				{
					return Results.BadRequest(new { error = "invalid_request", state, iss, });
				}

				if (!request.Query.TryGetValue("client_id", out var clientId) || clientId != options.Value.ClientId)
				{
					return Results.BadRequest(new { error = "unauthorized_client", state, iss, });
				}

				request.Query.TryGetValue("code_challenge", out var codeChallenge);
				request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
				request.Query.TryGetValue("redirect_uri", out var redirectUri);

				if (!request.Query.TryGetValue("scope", out var scope))
				{
					return Results.BadRequest(new { error = "invalid_scope", state, iss, });
				}

				var userScopes = request.HttpContext.User.Claims
					.Where(c => c.Type == "scope")
					.Select(c => c.Value)
					.ToList();
				var requestScopes = scope.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries)
					.Where(userScopes.Contains)
					.ToArray();

				var protector = dataProtectionProvider.CreateProtector("oauth");
				var authCode = new AuthCode
				{
					UserId = request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)!,
					UserName = request.HttpContext.User.FindFirstValue("name"),
					ClientId = clientId!,
					Scopes = requestScopes,
					RedirectUri = redirectUri!,
					CodeChallenge = codeChallenge!,
					CodeChallengeMethod = codeChallengeMethod!,
					Expiry = DateTime.UtcNow.AddMinutes(5)
				};
				var code = protector.Protect(JsonSerializer.Serialize(authCode));
				return Results.Redirect($"{redirectUri}?code={code}&state={state}&iss={HttpUtility.UrlEncode(iss)}");
			}).RequireAuthorization();

			routeGroup.MapPost("/token", async (HttpRequest request, IDataProtectionProvider dataProtectionProvider, IOptions<Options> options) =>
			{
				var bodyBytes = await request.BodyReader.ReadAsync();
				var bodyContent = Encoding.UTF8.GetString(bodyBytes.Buffer);
				request.BodyReader.AdvanceTo(bodyBytes.Buffer.End);

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

				if (clientId != options.Value.ClientId)
				{
					return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client id" });
				}

				if (clientSecret != options.Value.ClientSecret)
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
						Subject = new ClaimsIdentity([
							new Claim(ClaimTypes.NameIdentifier, authCode.UserId),
							new Claim(ClaimTypes.Name, authCode.UserName ?? string.Empty),
							..authCode.Scopes.Select(s => new Claim("scope", s)),
						]),
						Audience = options.Value.Audience,
						Expires = DateTime.UtcNow.AddMinutes(5),
						TokenType = "Bearer",
						SigningCredentials = new SigningCredentials(options.Value.SecurityKey, SecurityAlgorithms.RsaSha256),
					}),
					token_type = "Bearer",
				});
			});

			return routeGroup;
		}
	}
}