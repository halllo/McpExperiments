using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
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
			public string? ValidClientId { get; set; }
			public string? ValidClientSecret { get; set; }
			public string? Audience { get; set; }
			public SecurityKey? SecurityKey { get; set; }
		}

		class ClientRegistration
		{
			public string[] redirect_uris { get; set; } = null!;
			public string token_endpoint_auth_method { get; set; } = null!;
			public string[] grant_types { get; set; } = null!;
			public string[] response_types { get; set; } = null!;
			public string client_name { get; set; } = null!;
			public string client_uri { get; set; } = null!;
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
			endpoints.MapGet("/.well-known/oauth-authorization-server", (HttpRequest request) =>
			{
				var iss = new Uri($"{request.Scheme}://{request.Host}").AbsoluteUri.TrimEnd('/');
				return Results.Ok(new
				{
					issuer = iss,
					authorization_endpoint = $"{iss}/{pattern}/authorize",
					token_endpoint = $"{iss}/{pattern}/token",
					registration_endpoint = $"{iss}/{pattern}/register",
					response_types_supported = new[] { "code" },
					response_modes_supported = new[] { "query" },
					grant_types_supported = new[] { "authorization_code", "refresh_token" },
					token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "none" },
					revocation_endpoint = $"{iss}/{pattern}/token",
					code_challenge_methods_supported = new[] { "plain", "S256" },
				});
			});

			var routeGroup = endpoints.MapGroup(pattern);

			ConcurrentDictionary<string, ClientRegistration> clientRegistrations = new(StringComparer.Ordinal);
			routeGroup.MapPost("/register", ([FromBody] ClientRegistration clientRegistration) =>
			{
				var client_id = Guid.NewGuid();
				clientRegistrations.AddOrUpdate(client_id.ToString(), clientRegistration, (key, oldValue) => clientRegistration);

				return Results.Created($"/{pattern}/register/{client_id}", new
				{
					client_id,
					clientRegistration.redirect_uris,
					clientRegistration.client_name,
					clientRegistration.client_uri,
					clientRegistration.grant_types,
					clientRegistration.response_types,
					clientRegistration.token_endpoint_auth_method,
					registration_client_uri = $"/{pattern}/register/{client_id}",
					client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
				});
			});

			routeGroup.MapGet("/authorize", (HttpRequest request, IDataProtectionProvider dataProtectionProvider, IOptions<Options> options) =>
			{
				var iss = new Uri($"{request.Scheme}://{request.Host}").AbsoluteUri.TrimEnd('/');
				request.Query.TryGetValue("state", out var state);

				if (!request.Query.TryGetValue("response_type", out var responseType) || responseType != "code")
				{
					return Results.BadRequest(new { error = "invalid_request", state, iss, });
				}

				if (!request.Query.TryGetValue("client_id", out var clientId) || clientId != options.Value.ValidClientId)
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

				if (clientId != options.Value.ValidClientId)
				{
					return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client id" });
				}

				if (clientSecret != options.Value.ValidClientSecret)
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