namespace MyMCPClient.Console.Tests;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.Json;

/// <summary>
/// An in-process MCP server that requires OAuth, together with the authorization server protecting it.
/// Runs on <see cref="TestServer"/>, so there are no sockets, no certificates and no external processes:
/// every request the SDK makes — MCP, metadata and token endpoints alike — is routed back into this app.
/// </summary>
internal sealed class MockMcpServer : IAsyncDisposable
{
    private const string Origin = "http://localhost";
    private const string AccessToken = "mock-access-token";

    private readonly WebApplication _app;
    private readonly List<string> _requests = [];

    public Uri McpEndpoint { get; } = new($"{Origin}/mcp");

    /// <summary>Every JSON-RPC request received, as "method (anonymous|authenticated)".</summary>
    public IReadOnlyList<string> Requests => _requests;

    public HttpClient CreateClient() => _app.GetTestClient();

    public static async Task<MockMcpServer> StartAsync()
    {
        var server = new MockMcpServer();
        await server._app.StartAsync();
        return server;
    }

    private MockMcpServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        _app = builder.Build();

        _app.MapGet("/.well-known/oauth-protected-resource/mcp", () => Results.Json(new
        {
            resource = $"{Origin}/mcp",
            authorization_servers = new[] { Origin },
        }));

        _app.MapGet("/.well-known/oauth-authorization-server", () => Results.Json(new
        {
            issuer = Origin,
            authorization_endpoint = $"{Origin}/authorize",
            token_endpoint = $"{Origin}/token",
            response_types_supported = new[] { "code" },
            code_challenge_methods_supported = new[] { "S256" },
        }));

        _app.MapPost("/token", () => Results.Json(new
        {
            access_token = AccessToken,
            token_type = "Bearer",
            expires_in = 3600,
        }));

        // The standalone GET stream: a method the endpoint does not serve, never an auth challenge.
        _app.MapGet("/mcp", () => Results.StatusCode(StatusCodes.Status405MethodNotAllowed));

        _app.MapPost("/mcp", (Delegate)HandleMcpAsync);
    }

    private async Task<IResult> HandleMcpAsync(HttpContext context)
    {
        var authenticated = (string?)context.Request.Headers.Authorization == $"Bearer {AccessToken}";

        string? method;
        JsonElement? id;
        using (var request = await JsonDocument.ParseAsync(context.Request.Body))
        {
            method = request.RootElement.GetProperty("method").GetString();
            // Cloned: the response is serialized after this document is disposed.
            id = request.RootElement.TryGetProperty("id", out var element) ? element.Clone() : null;
        }

        _requests.Add($"{method} ({(authenticated ? "authenticated" : "anonymous")})");

        if (!authenticated)
        {
            // The challenge that sends the client off to log in.
            context.Response.Headers.WWWAuthenticate =
                $"Bearer resource_metadata=\"{Origin}/.well-known/oauth-protected-resource/mcp\"";
            return Results.StatusCode(StatusCodes.Status401Unauthorized);
        }

        if (id is null)
        {
            return Results.Accepted();   // a notification, such as notifications/initialized
        }

        return method == "initialize"
            ? Results.Json(new
            {
                jsonrpc = "2.0",
                id,
                result = new
                {
                    protocolVersion = "2025-11-25",
                    capabilities = new { },
                    serverInfo = new { name = "mock-mcp-server", version = "1.0.0" },
                },
            })
            : Results.Json(new
            {
                jsonrpc = "2.0",
                id,
                error = new { code = -32601, message = $"This server does not support '{method}'." },
            });
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
