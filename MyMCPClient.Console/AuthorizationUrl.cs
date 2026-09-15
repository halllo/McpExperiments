using ModelContextProtocol.Authentication;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

public static class AuthorizationUrl
{
    /// Taken from https://github.com/modelcontextprotocol/csharp-sdk/blob/c0440760ac363d817cbdca87e1ab7eff7e74a025/samples/ProtectedMCPClient/Program.cs#L72
    public static async Task<AuthorizationResult?> Handle(AuthorizationCallbackContext context, CancellationToken cancellationToken)
    {
        static Uri changeScopes(Uri url, Func<string[], string[]> adjustScopes)
        {
            return new Uri(Regex.Replace(url.ToString(), @"(?<=&scope=)(?<scopes>[^&]+)", m =>
            {
                var scopes = m.Groups["scopes"].Value;
                return string.Join('+', adjustScopes(scopes.Split('+', StringSplitOptions.RemoveEmptyEntries)));
            }));
        }

        // Scope manipulation, because ClientOAuthProvider.Scopes no longer has priority (https://github.com/modelcontextprotocol/csharp-sdk/pull/1238)
        var newAuthUrl = changeScopes(context.AuthorizationUri, scopes => [.. scopes, "offline_access"]);
        Console.WriteLine($"Starting OAuth authorization flow at {newAuthUrl}");

        var listenerPrefix = context.RedirectUri.GetLeftPart(UriPartial.Authority);
        if (!listenerPrefix.EndsWith("/")) listenerPrefix += "/";

        using var listener = new HttpListener();
        listener.Prefixes.Add(listenerPrefix);

        try
        {
            listener.Start();
            Console.WriteLine($"Listening for OAuth callback on: {listenerPrefix}");

            OpenBrowser(newAuthUrl);

            var httpContext = await listener.GetContextAsync();
            var query = HttpUtility.ParseQueryString(httpContext.Request.Url?.Query ?? string.Empty);
            var code = query["code"];
            var state = query["state"];
            var iss = query["iss"];
            var error = query["error"];

            string responseHtml = "<html><body><h1>Authentication complete</h1><p>You can close this window now.</p></body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
            httpContext.Response.ContentLength64 = buffer.Length;
            httpContext.Response.ContentType = "text/html";
            httpContext.Response.OutputStream.Write(buffer, 0, buffer.Length);
            httpContext.Response.Close();

            if (!string.IsNullOrEmpty(error))
            {
                Console.WriteLine($"Auth error: {error}");
                return null;
            }

            if (string.IsNullOrEmpty(code))
            {
                Console.WriteLine("No authorization code received");
                return null;
            }

            // The SDK requires an exact match against the state it sent before it exchanges the code.
            if (string.IsNullOrEmpty(state))
            {
                Console.WriteLine("No state received");
                return null;
            }

            Console.WriteLine("Authorization code received successfully.");
            // Iss is passed on when present so the SDK can validate the issuer per RFC 9207.
            return new AuthorizationResult { Code = code, State = state, Iss = iss };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting auth code: {ex.Message}");
            return null;
        }
        finally
        {
            if (listener.IsListening) listener.Stop();
        }

        static void OpenBrowser(Uri url)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = url.ToString(),
                    UseShellExecute = true
                };
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error opening browser. {ex.Message}");
                Console.WriteLine($"Please manually open this URL: {url}");
            }
        }
    }
}
