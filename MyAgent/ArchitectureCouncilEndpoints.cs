using System.Runtime.CompilerServices;
using System.Text.Json;
using AGUI.Abstractions;
using AGUI.Server;
using Microsoft.Agents.AI.Workflows;
using Microsoft.AspNetCore.Http.Features;

namespace MyAgent;

/// <summary>
/// Serves a web view of a workflow run: a page at <c>/architecturecouncil</c> and an
/// <see href="https://docs.ag-ui.com">AG-UI</see> event stream at <c>/architecturecouncil/agui</c>.
/// The stream speaks the protocol rather than a private format, so the page is one client of it
/// among any others. <see cref="WorkflowAguiStream"/> does the streaming; this file is only HTTP.
/// </summary>
public static class ArchitectureCouncilEndpoints
{
    /// <summary>
    /// The longest topic accepted, in characters, counted across every message in the request — so it
    /// is the bound on how much text one request can put in front of the model, and therefore on what
    /// one request can cost. Served to the page as well, which uses it as its input's maxlength.
    /// </summary>
    public const int MaxTopicLength = 500;

    /// <summary>
    /// The largest request body accepted. Enforced before the body is buffered, because
    /// <see cref="MaxTopicLength"/> cannot be: validation runs on a materialized request, and a large
    /// body costs memory long before it costs tokens.
    /// </summary>
    public const int MaxRequestBytes = 64 * 1024;

    const string LogCategory = "MyAgent.ArchitectureCouncil.View";

    /// <summary>
    /// The page's own policy, as a response header rather than the <c>&lt;meta&gt;</c> equivalent it
    /// also carries: <c>frame-ancestors</c> is ignored in meta form, and neither <c>form-action</c>
    /// nor <c>base-uri</c> falls back to <c>default-src</c>.
    /// </summary>
    const string PageContentSecurityPolicy =
        "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; " +
        "connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'";

    static readonly Lazy<string> Page = new(() =>
    {
        var assembly = typeof(ArchitectureCouncilEndpoints).Assembly;
        var name = $"{assembly.GetName().Name}.ArchitectureCouncil.html";
        using var stream = assembly.GetManifestResourceStream(name) ?? throw new InvalidOperationException($"Embedded resource '{name}' not found.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    });

    public static IEndpointRouteBuilder MapArchitectureCouncil(this IEndpointRouteBuilder app)
    {
        // Read the page now. A missing embedded resource is a build mistake, and Lazy caches its
        // failure forever, so the choice is between failing at startup and 500ing until restarted.
        _ = Page.Value;

        app.MapGet("/architecturecouncil", (HttpContext http) =>
            {
                http.Response.Headers.CacheControl = "no-cache";
                http.Response.Headers.XContentTypeOptions = "nosniff";
                http.Response.Headers.XFrameOptions = "DENY";
                http.Response.Headers.ContentSecurityPolicy = PageContentSecurityPolicy;
                return Results.Content(Page.Value, "text/html; charset=utf-8");
            })
           .ExcludeFromDescription();

        // Lets the page describe itself before any run has started. Served from constants: the
        // workflow is registered transient, so resolving one here would build it per page load.
        app.MapGet("/architecturecouncil/info", () => Results.Ok(new
                {
                    name = ArchitectureCouncil.DisplayName,
                    ArchitectureCouncil.Description,
                    maxTopicLength = MaxTopicLength,
                    ArchitectureCouncil.Prompt,
                    ArchitectureCouncil.Samples,
                }))
           .ExcludeFromDescription();

        // POST, per the AG-UI transport: a run's input is a JSON body, not a query string. That also
        // rules out EventSource on the client, and with it the automatic reconnect that would
        // silently start a second paid run every time a stream ended abnormally.
        app.MapPost("/architecturecouncil/agui", RunAsync)
           .ExcludeFromDescription();

        return app;
    }

    static async Task<IResult> RunAsync(
        HttpContext http,
        [FromKeyedServices(ArchitectureCouncil.WorkflowName)] Workflow workflow,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var logger = loggerFactory.CreateLogger(LogCategory);

        // Any content type used to start a paid run, and `text/plain` needs no CORS preflight — so
        // any page in any browser could spend this account's budget without being able to read the
        // answer. Requiring JSON makes the request non-simple, so the browser asks first.
        if (!http.Request.HasJsonContentType())
        {
            return Results.Json(new { error = "This endpoint takes an AG-UI RunAgentInput as application/json." },
                statusCode: StatusCodes.Status415UnsupportedMediaType);
        }

        // Bound the body before it is buffered. The topic limit cannot do this job: it is measured
        // on a materialized request, and a large body costs memory long before it costs tokens.
        if (http.Request.ContentLength > MaxRequestBytes)
        {
            return TooLarge(MaxRequestBytes);
        }

        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size)
        {
            size.MaxRequestBodySize = MaxRequestBytes;
        }

        ChatRequestContext context;
        try
        {
            var input = await JsonSerializer.DeserializeAsync<RunAgentInput>(http.Request.Body, WorkflowAguiStream.Json, cancellationToken);

            if (Reject(input) is { } rejection)
            {
                return Results.BadRequest(new { error = rejection });
            }

            // Inside the try on purpose: adapting the input parses tool arguments, data URIs and
            // base64 blobs, so a body that deserializes can still be hostile enough to throw.
            context = input!.ToChatRequestContext(WorkflowAguiStream.Json, new AGUIStreamOptions());
        }
        catch (BadHttpRequestException ex)
        {
            // Kestrel's own verdict, most often a body over the limit set above.
            logger.LogInformation("Rejected AG-UI run input: {Reason}", ex.Message);
            return ex.StatusCode == StatusCodes.Status413PayloadTooLarge
                ? TooLarge(MaxRequestBytes)
                : Results.BadRequest(new { error = "The request body could not be read." });
        }
        catch (OperationCanceledException)
        {
            // The caller vanished mid-upload. There is nothing to answer.
            return Results.Empty;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or UriFormatException or ArgumentException or NotSupportedException)
        {
            // Not a run at all, so there is no stream to report into: answer as a bad request, and
            // keep the reason in the log rather than the response, which would otherwise hand back
            // exception text (and, in Development, a stack trace with source paths).
            logger.LogDebug(ex, "Malformed AG-UI run input.");
            return Results.BadRequest(new { error = "The request body is not a valid AG-UI RunAgentInput." });
        }

        http.Response.Headers["X-Accel-Buffering"] = "no"; // don't let a proxy buffer the run

        return TypedResults.ServerSentEvents(Frames(
            WorkflowAguiStream.RunAsync(workflow, context, MaxTopicLength, logger, http.TraceIdentifier, cancellationToken)));
    }

    /// <summary>
    /// What must hold before the SDK is handed the input. These are structural: a run with no id
    /// cannot be addressed, and a null message list is a null dereference inside the adapter.
    /// Anything about the <em>topic</em> is <see cref="WorkflowAguiStream.Validate"/>'s business and
    /// is reported through the event stream instead.
    /// </summary>
    static string? Reject(RunAgentInput? input) => input switch
    {
        null => "The request body is empty.",
        { Messages: null } => "The request body must carry a messages array.",
        _ when string.IsNullOrWhiteSpace(input.ThreadId) => "The request body must carry a threadId.",
        _ when string.IsNullOrWhiteSpace(input.RunId) => "The request body must carry a runId.",
        _ => null,
    };

    static IResult TooLarge(int limit) =>
        Results.Json(new { error = $"The request body is larger than the {limit} byte limit." },
            statusCode: StatusCodes.Status413PayloadTooLarge);

    /// <summary>
    /// Serializes each event as one SSE frame. Nothing is stripped here:
    /// <see cref="WorkflowAguiStream"/> owns the wire contract, <c>rawEvent</c> included, so every
    /// transport gets the same guarantees.
    /// </summary>
    static async IAsyncEnumerable<string> Frames(
        IAsyncEnumerable<BaseEvent> events,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Forwarded so the token the SSE writer enumerates with reaches the run. The endpoint's own
        // bound token already stops it, but leaving this one on the floor would make that single
        // argument the only thing between a disconnected client and a run that keeps spending.
        await foreach (BaseEvent evt in events.WithCancellation(cancellationToken))
        {
            yield return JsonSerializer.Serialize(evt, evt.GetType(), WorkflowAguiStream.Json);
        }
    }
}
