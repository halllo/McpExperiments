namespace MyMCPClient.Console.Tests;

using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;
using System.Web;

/// <summary>
/// One connect must cost the user exactly one login.
///
/// This test FAILS today, which is the point: the client prefers protocol 2026-07-28, so it opens the
/// connection with a server/discover probe bounded by <see cref="McpClientOptions.DiscoverProbeTimeout"/> —
/// 5 seconds by default. An interactive login takes longer than that, so the probe, and with it the login
/// its 401 kicked off, is abandoned. The SDK falls back to the initialize handshake, which carries no
/// token, earns its own 401, and opens a second browser tab.
///
/// It goes green once the connect holds a token for the whole handshake, by any of:
///   - DiscoverProbeTimeout = Timeout.InfiniteTimeSpan, with InitializationTimeout raised past a real login
///   - ProtocolVersion pinned to an initialize-capable revision, so no probe is issued
///   - obtaining the token before connecting, so nothing 401s mid-handshake
///
/// See https://dev.azure.com/stp-pde/Legal%20Twin/_workitems/edit/128584.
/// </summary>
[TestClass]
public sealed class DoubleLoginTests
{
    /// <summary>Longer than the 5 second DiscoverProbeTimeout default — as any real login is.</summary>
    private static readonly TimeSpan HumanLogin = TimeSpan.FromSeconds(6);

    [TestMethod, Timeout(60_000)]
    public async Task Connecting_AsksTheUserToLogInExactlyOnce()
    {
        await using var server = await MockMcpServer.StartAsync();
        var logins = 0;

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = server.McpEndpoint,
            TransportMode = HttpTransportMode.StreamableHttp,
            OAuth = new ClientOAuthOptions
            {
                ClientId = "mcp_console",
                RedirectUri = new Uri("http://localhost:1179/callback"),
                AuthorizationCallbackHandler = async (context, _) =>
                {
                    // Each call is a browser tab the user has to deal with. The first one is a human typing
                    // their password; a second tab is instant, because the IdP already has a session by then.
                    // Like a real HttpListener-based handler this ignores the SDK's cancellation token —
                    // a person does not stop typing because a timeout elapsed somewhere inside the client.
                    if (Interlocked.Increment(ref logins) == 1)
                    {
                        await Task.Delay(HumanLogin, CancellationToken.None);
                    }

                    var state = HttpUtility.ParseQueryString(context.AuthorizationUri.Query)["state"];
                    return new AuthorizationResult { Code = $"authorization-code-{logins}", State = state };
                },
            },
        }, server.CreateClient());

        await using var client = await McpClient.CreateAsync(transport);

        Assert.AreEqual(1, logins,
            $"The user should be prompted to log in exactly once per connect, but was prompted {logins} times. " +
            $"The server the client talked to saw: {string.Join(" → ", server.Requests)}.");

        // Only the very first request may be unauthenticated: that 401 is what discovers the challenge and
        // starts the login. Anything anonymous after that is a login the client threw away.
        Assert.AreEqual(1, server.Requests.Count(request => request.EndsWith("(anonymous)")),
            "Only the first request should go out unauthenticated; every request after the login should carry the token.");

        Assert.IsNotNull(client.ServerInfo, "The connect should still succeed.");
    }
}
