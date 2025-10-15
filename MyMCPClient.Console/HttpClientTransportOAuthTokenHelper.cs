using ModelContextProtocol.Client;
using System.Reflection;
using System.Text.Json;

/// <summary>
/// Extract and inject the OAuth token, until we get the TokenCache (https://github.com/modelcontextprotocol/csharp-sdk/pull/834).
/// </summary>
public static class HttpClientTransportOAuthTokenHelper
{
	public static string? ExtractOAuthToken(this HttpClientTransport httpTransport)
	{
		var mcpHttpClientField = httpTransport.GetType().GetField("_mcpHttpClient", BindingFlags.NonPublic | BindingFlags.Instance);
		var mcpHttpClient = mcpHttpClientField?.GetValue(httpTransport);
		var clientOAuthProviderField = (mcpHttpClient?.GetType() as TypeInfo)?.DeclaredFields.FirstOrDefault(df => df.FieldType.FullName == "ModelContextProtocol.Authentication.ClientOAuthProvider");
		var clientOAuthProvider = clientOAuthProviderField?.GetValue(mcpHttpClient);
		var tokenField = clientOAuthProvider?.GetType().GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance);
		var token = tokenField?.GetValue(clientOAuthProvider);
		var obtainedAtProperty = token?.GetType().GetProperty("ObtainedAt");
		var obtainedAt = obtainedAtProperty?.GetValue(token);
		if (token == null || obtainedAt == null) return null;
		var tokenJson = JsonSerializer.Serialize(token, token!.GetType());
		return JsonSerializer.Serialize(new { tokenJson, obtainedAt });
	}

	public static void InjectOAuthToken(this HttpClientTransport httpTransport, string? token)
	{
		if (string.IsNullOrEmpty(token)) return;
		var tokenObj = JsonSerializer.Deserialize<JsonElement>(token);
		var tokenJson = tokenObj.GetProperty("tokenJson").GetString();
		var obtainedAt = tokenObj.GetProperty("obtainedAt").GetDateTimeOffset();
		var mcpHttpClientField = httpTransport.GetType().GetField("_mcpHttpClient", BindingFlags.NonPublic | BindingFlags.Instance);
		var mcpHttpClient = mcpHttpClientField?.GetValue(httpTransport);
		var clientOAuthProviderField = (mcpHttpClient?.GetType() as TypeInfo)?.DeclaredFields.FirstOrDefault(df => df.FieldType.FullName == "ModelContextProtocol.Authentication.ClientOAuthProvider");
		var clientOAuthProvider = clientOAuthProviderField?.GetValue(mcpHttpClient);
		var tokenField = clientOAuthProvider?.GetType().GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance);
		var tokenType = tokenField?.FieldType;
		var deserializedToken = JsonSerializer.Deserialize(tokenJson!, tokenType!);
		if (deserializedToken != null)
		{
			var obtainedAtProperty = tokenType!.GetProperty("ObtainedAt");
			obtainedAtProperty?.SetValue(deserializedToken, obtainedAt);
			tokenField?.SetValue(clientOAuthProvider, deserializedToken);
		}
	}
}