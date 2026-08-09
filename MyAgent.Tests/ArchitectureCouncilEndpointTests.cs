using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MyAgent.Tests;

/// <summary>
/// Covers the HTTP layer in front of <see cref="WorkflowAguiStream"/> — the part a browser or any
/// other AG-UI client actually talks to. The app is the real one: the real
/// <see cref="ArchitectureCouncil.AddArchitectureCouncil"/> registration, the real endpoints, the
/// real council workflow. Only the chat client is a stub, so none of this costs a model call.
/// </summary>
[TestClass]
[TestCategory("Offline")]
public sealed class ArchitectureCouncilEndpointTests
{
    const string RunPath = "/architecturecouncil/agui";

    // --- the page and what it reads --------------------------------------------------------------

    [TestMethod]
    [Timeout(60_000)]
    public async Task Page_IsServedWithTheHeadersThatKeepItFromBeingFramedOrSniffed()
    {
        await using var app = await StartAsync();

        var response = await app.Client.GetAsync("/architecturecouncil");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("text/html; charset=utf-8", response.Content.Headers.ContentType?.ToString());
        Assert.AreEqual("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.AreEqual("DENY", Single(response, "X-Frame-Options"));
        Assert.AreEqual("no-cache", response.Headers.CacheControl?.ToString());

        var csp = Single(response, "Content-Security-Policy");
        // frame-ancestors is ignored in the page's own <meta> policy, which is why it is sent here.
        StringAssert.Contains(csp, "frame-ancestors 'none'");
        StringAssert.Contains(csp, "default-src 'none'");

        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "<title>Workflow</title>");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task Info_CarriesExactlyTheFieldsThePageReads()
    {
        await using var app = await StartAsync();

        using var document = JsonDocument.Parse(await app.Client.GetStringAsync("/architecturecouncil/info"));
        var info = document.RootElement;

        CollectionAssert.AreEquivalent(
            new[] { "name", "description", "maxTopicLength", "prompt", "samples" },
            info.EnumerateObject().Select(property => property.Name).ToArray(),
            "The page reads exactly these; a rename would silently empty its title, placeholder or chips.");

        Assert.AreEqual(ArchitectureCouncil.DisplayName, info.GetProperty("name").GetString());
        Assert.AreEqual(ArchitectureCouncil.Description, info.GetProperty("description").GetString());
        Assert.AreEqual(ArchitectureCouncil.Prompt, info.GetProperty("prompt").GetString());
        Assert.AreEqual(ArchitectureCouncil.Samples.Length, info.GetProperty("samples").GetArrayLength());

        // The page uses this as its input's maxlength, so a run must not reject what it lets a
        // reader type. Both numbers come from the same option.
        Assert.AreEqual(ArchitectureCouncilEndpoints.MaxTopicLength, info.GetProperty("maxTopicLength").GetInt32(),
            "The advertised limit must be the limit the run enforces — the page uses it as its input's maxlength.");
    }

    // --- bodies that are not runs ---------------------------------------------------------------

    [TestMethod]
    [Timeout(60_000)]
    public async Task MalformedJson_IsABadRequestAndCostsNothing()
    {
        var chat = new StubChatClient();
        await using var app = await StartAsync(chat);

        var response = await app.Client.PostAsync(RunPath, Json("{ this is not json"));

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "not a valid AG-UI RunAgentInput");
        Assert.AreEqual(0, chat.Calls, "A body that is not a run must not reach the model.");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task NullMessages_IsABadRequestRatherThanAnUnhandledCrash()
    {
        await using var app = await StartAsync();

        // This used to dereference null inside the AG-UI adapter and answer 500 with a stack trace,
        // because the adapt step sat outside the try that guarded deserialization.
        var response = await app.Client.PostAsync(RunPath, Json("""{"threadId":"t","runId":"r","messages":null}"""));

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "messages array");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task MissingRunIds_AreRejectedSoNoRunOpensUnaddressable()
    {
        await using var app = await StartAsync();

        var response = await app.Client.PostAsync(RunPath, Json("{}"));

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "threadId");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task ParseableButHostileContent_IsRejectedWithoutLeakingHowItFailed()
    {
        await using var app = await StartAsync();

        // Each of these deserializes fine and then throws inside the adapter — base64, URI and
        // tool-argument parsing respectively. All three used to be unhandled 500s.
        string[] bodies = [
            """{"threadId":"t","runId":"r","messages":[{"id":"1","role":"user","content":[{"type":"binary","mimeType":"image/png","data":"!!!not base64!!!"}]}]}""",
            """{"threadId":"t","runId":"r","messages":[{"id":"1","role":"user","content":[{"type":"binary","mimeType":"image/png","url":"not a uri"}]}]}""",
            """{"threadId":"t","runId":"r","messages":[{"id":"1","role":"assistant","toolCalls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{oops"}}]}]}""",
        ];

        foreach (var body in bodies)
        {
            var response = await app.Client.PostAsync(RunPath, Json(body));
            var payload = await response.Content.ReadAsStringAsync();

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, $"Expected a bad request for: {body}");
            Assert.IsFalse(payload.Contains("Exception", StringComparison.OrdinalIgnoreCase),
                $"The response named the exception: {payload}");
            Assert.IsFalse(payload.Contains("MyAgent", StringComparison.Ordinal),
                $"The response leaked internals: {payload}");
        }
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task NonJsonContentType_IsRefused()
    {
        var chat = new StubChatClient();
        await using var app = await StartAsync(chat);

        // text/plain needs no CORS preflight, so accepting it let any page in any browser spend this
        // account's Bedrock budget without ever reading the answer.
        var content = new StringContent(JsonSerializer.Serialize(CouncilStubs.Input("a topic"), WorkflowAguiStream.Json),
            Encoding.UTF8, "text/plain");

        var response = await app.Client.PostAsync(RunPath, content);

        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.AreEqual(0, chat.Calls, "A cross-origin simple request must not start a run.");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task OversizedBody_IsRefusedBeforeItIsBuffered()
    {
        var chat = new StubChatClient();
        await using var app = await StartAsync(chat);

        // Well-formed, and far too big. The topic limit cannot catch this: it is measured on an
        // already-materialized request, and eight of these concurrently was an 18x memory blow-up.
        var padded = new RunAgentInputPadding(new string('x', ArchitectureCouncilEndpoints.MaxRequestBytes + 4096));
        var response = await app.Client.PostAsync(RunPath, Json(JsonSerializer.Serialize(padded)));

        Assert.AreEqual(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.AreEqual(0, chat.Calls);
    }

    sealed record RunAgentInputPadding(string Padding)
    {
        public string ThreadId => "t";

        public string RunId => "r";

        public object[] Messages => [new { id = "1", role = "user", content = Padding }];
    }

    // --- the stream a client actually reads -----------------------------------------------------

    [TestMethod]
    [Timeout(60_000)]
    public async Task Run_StreamsWellFormedAguiFramesAndNeverTheInternalRawEvent()
    {
        await using var app = await StartAsync();

        var response = await app.Client.PostAsync(RunPath, Json(JsonSerializer.Serialize(
            CouncilStubs.Input("a topic"), WorkflowAguiStream.Json)));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.AreEqual("no", Single(response, "X-Accel-Buffering"), "A buffering proxy would hold the whole run back.");

        var body = await response.Content.ReadAsStringAsync();
        var frames = body.Split("\n\n", StringSplitOptions.RemoveEmptyEntries);

        Assert.IsTrue(frames.Length > 3, $"Expected a stream of frames, got: {body}");

        List<string> types = [];
        foreach (var frame in frames)
        {
            Assert.IsTrue(frame.StartsWith("data: ", StringComparison.Ordinal), $"Not an SSE data frame: {frame}");

            using var document = JsonDocument.Parse(frame["data: ".Length..]);
            Assert.IsTrue(document.RootElement.TryGetProperty("type", out var type),
                $"Every AG-UI event carries a type discriminator: {frame}");

            // rawEvent is the whole internal update. Most events carry one, so this is load-bearing
            // rather than theoretical: it doubles every frame and can carry a failure's detail.
            Assert.IsFalse(document.RootElement.TryGetProperty("rawEvent", out _),
                $"An internal rawEvent reached the wire: {frame}");

            types.Add(type.GetString()!);
        }

        Assert.AreEqual("RUN_STARTED", types[0]);
        Assert.AreEqual("RUN_FINISHED", types[^1]);
        Assert.AreEqual(1, types.Count(t => t is "RUN_FINISHED" or "RUN_ERROR"), "A run ends exactly once.");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task Run_ThatFails_ReportsAReferenceInsteadOfTheReason()
    {
        const string secret = "Password=hunter2";
        await using var app = await StartAsync(new StubChatClient { ThrowWith = secret });

        var response = await app.Client.PostAsync(RunPath, Json(JsonSerializer.Serialize(
            CouncilStubs.Input("a topic"), WorkflowAguiStream.Json)));

        var body = await response.Content.ReadAsStringAsync();

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, "A run that starts and then fails still streams its verdict.");
        StringAssert.Contains(body, WorkflowAguiStream.RunFailedCode);
        Assert.IsFalse(body.Contains(secret, StringComparison.OrdinalIgnoreCase), $"The exception detail reached the wire: {body}");

        // The reference is the request's trace identifier, which the log carries too.
        var reference = System.Text.RegularExpressions.Regex.Match(body, @"reference ([^\s""\.\\]+)");
        Assert.IsTrue(reference.Success, $"The failure message should name a reference: {body}");
        Assert.IsTrue(reference.Groups[1].Value.Length > 0, "The reference must not be empty, or it points at nothing.");
    }

    // --- harness ---------------------------------------------------------------------------------

    static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    static string? Single(HttpResponseMessage response, string header) =>
        response.Headers.TryGetValues(header, out var values) ? values.FirstOrDefault()
        : response.Content.Headers.TryGetValues(header, out var contentValues) ? contentValues.FirstOrDefault()
        : null;

    /// <summary>
    /// The real app, minus the model. <see cref="ArchitectureCouncil.AddArchitectureCouncil"/> runs
    /// exactly as it does in production, and the keyed chat client is then replaced, so the genuine
    /// council workflow runs against a stub.
    /// </summary>
    static async Task<TestApp> StartAsync(StubChatClient? chat = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        builder.AddArchitectureCouncil();
        builder.Services.AddKeyedSingleton<IChatClient>(ArchitectureCouncil.WorkflowName, (_, _) => chat ?? new StubChatClient());

        var app = builder.Build();
        app.MapArchitectureCouncil();

        try
        {
            await app.StartAsync();
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }

        return new TestApp(app);
    }

    sealed class TestApp(WebApplication app) : IAsyncDisposable
    {
        public HttpClient Client { get; } = app.GetTestClient();

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.DisposeAsync();
        }
    }
}
