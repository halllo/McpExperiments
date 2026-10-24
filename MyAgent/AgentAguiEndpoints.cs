using Microsoft.Agents.AI.Hosting.AGUI.AspNetCore;

namespace MyAgent;

/// <summary>
/// Serves the chat agents over <see href="https://docs.ag-ui.com">AG-UI</see>: a page at
/// <c>/agents</c> and the framework's own AG-UI endpoint per agent at <c>/agents/{name}/agui</c>.
/// This is the transport that carries a tool's activity — the planner–executor's live plan among
/// it — which DevUI and the OpenAI Responses endpoints have no event for.
/// </summary>
/// <remarks>
/// Unlike the council's endpoint, the agent routes are <c>MapAGUIServer</c>'s, so they forward the
/// tools a client advertises and carry each event's <c>rawEvent</c>; they apply no limits beyond
/// Kestrel's. Requires <c>AddAGUIServer()</c>.
/// </remarks>
public static class AgentAguiEndpoints
{
    /// <summary>The agents served here, by DI key. Mapped by name, so each resolves on its first request rather than at startup.</summary>
    public static readonly string[] AgentNames = ["amazonbedrock", "openai"];

    /// <summary>The same policy as the council page's; see <c>ArchitectureCouncilEndpoints</c> for why it is a header.</summary>
    const string PageContentSecurityPolicy =
        "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; " +
        "connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'";

    static readonly Lazy<string> Page = new(() =>
    {
        var assembly = typeof(AgentAguiEndpoints).Assembly;
        var name = $"{assembly.GetName().Name}.PlannerExecutor.html";
        using var stream = assembly.GetManifestResourceStream(name) ?? throw new InvalidOperationException($"Embedded resource '{name}' not found.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    });

    public static IEndpointRouteBuilder MapAgentAgui(this IEndpointRouteBuilder app)
    {
        // Read the page now, for the same reason the council endpoint does: a missing embedded
        // resource is a build mistake, and Lazy would cache the failure forever.
        _ = Page.Value;

        app.MapGet("/agents", (HttpContext http) =>
            {
                http.Response.Headers.CacheControl = "no-cache";
                http.Response.Headers.XContentTypeOptions = "nosniff";
                http.Response.Headers.XFrameOptions = "DENY";
                http.Response.Headers.ContentSecurityPolicy = PageContentSecurityPolicy;
                return Results.Content(Page.Value, "text/html; charset=utf-8");
            })
           .ExcludeFromDescription();

        app.MapGet("/agents/info", () => Results.Ok(new
                {
                    agents = AgentNames,
                    activityType = PlannerExecutor.ActivityType,
                }))
           .ExcludeFromDescription();

        foreach (var name in AgentNames)
        {
            app.MapAGUIServer(name, $"/agents/{name}/agui")
               .ExcludeFromDescription();
        }

        return app;
    }
}
