using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

public static class AuthorizationUrl
{
    /// Taken from https://github.com/modelcontextprotocol/csharp-sdk/blob/c0440760ac363d817cbdca87e1ab7eff7e74a025/samples/ProtectedMCPClient/Program.cs#L72
    public static async Task<string?> Handle(Uri authUrl, Uri redirectUri, CancellationToken cancellationToken)
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
        var newAuthUrl = changeScopes(authUrl, scopes => [.. scopes, "offline_access"]);
        Console.WriteLine($"Starting OAuth authorization flow at {newAuthUrl}");

        var listenerPrefix = redirectUri.GetLeftPart(UriPartial.Authority);
        if (!listenerPrefix.EndsWith("/")) listenerPrefix += "/";

        using var listener = new HttpListener();
        listener.Prefixes.Add(listenerPrefix);

        try
        {
            listener.Start();
            Console.WriteLine($"Listening for OAuth callback on: {listenerPrefix}");

            OpenBrowser(newAuthUrl);

            var context = await listener.GetContextAsync();
            var query = HttpUtility.ParseQueryString(context.Request.Url?.Query ?? string.Empty);
            var code = query["code"];
            var error = query["error"];

            string responseHtml = "<html><body><h1>Authentication complete</h1><p>You can close this window now.</p></body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
            context.Response.ContentLength64 = buffer.Length;
            context.Response.ContentType = "text/html";
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            context.Response.Close();

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

            Console.WriteLine("Authorization code received successfully.");
            return code;
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