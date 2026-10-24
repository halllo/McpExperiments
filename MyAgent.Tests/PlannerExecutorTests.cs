using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AGUI.Abstractions;
using AGUI.Server;
using Microsoft.Agents.AI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using static MyAgent.Tests.CouncilStubs;

namespace MyAgent.Tests;

/// <summary>
/// Covers <see cref="PlannerExecutor"/> and the activity stream that carries its progress, against a
/// scripted chat client, so the plan a front end follows is checked without spending a model call:
/// the snapshots arrive while the tool is still running, they describe the plan truthfully, and a
/// failing step is reported as one without its detail reaching the wire.
/// </summary>
[TestClass]
[TestCategory("Offline")]
public sealed class PlannerExecutorTests
{
    const string Goal = "Find the time, then summarize it.";

    // --- the workflow on its own ------------------------------------------------------------------

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_PlansExecutesEachStepAndAnswersFromTheResults()
    {
        var chat = new ScriptedChatClient { StepCount = 3 };
        var log = new CapturingLogger();

        var answer = await PlannerExecutor.RunAsync(Goal, chat, [], Services(log), CancellationToken.None);

        Assert.AreEqual(ScriptedChatClient.FinalAnswer, answer, log.All);
        CollectionAssert.AreEqual(new[] { "Step 1", "Step 2", "Step 3" }, chat.ExecutedSteps.ToArray());
        StringAssert.Contains(chat.SynthesisPrompt, "result of Step 3", "The synthesizer must see every step's result.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_LogsTheTokensOfEveryCallItMade()
    {
        var chat = new ScriptedChatClient { StepCount = 2 };
        var log = new CapturingLogger();

        await PlannerExecutor.RunAsync(Goal, chat, [], Services(log), CancellationToken.None);

        // Planner, two steps, synthesizer.
        StringAssert.Contains(log.All, $"({4 * ScriptedChatClient.WorkflowCallTokens} total) for 2 steps");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_CutsAPlanThatIsLongerThanMaxSteps()
    {
        var chat = new ScriptedChatClient { StepCount = PlannerExecutor.MaxSteps + 3 };

        await PlannerExecutor.RunAsync(Goal, chat, [], Services(), CancellationToken.None);

        Assert.AreEqual(PlannerExecutor.MaxSteps, chat.ExecutedSteps.Count);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_ThatFailsReturnsTheFixedResultAndLogsTheDetail()
    {
        var chat = new ScriptedChatClient { StepCount = 3, FailOnStep = 2 };
        var log = new CapturingLogger();

        var answer = await PlannerExecutor.RunAsync(Goal, chat, [], Services(log), CancellationToken.None);

        Assert.AreEqual(PlannerExecutor.FailedResult, answer);
        CollectionAssert.AreEqual(new[] { "Step 1", "Step 2" }, chat.ExecutedSteps.ToArray(), "No step runs after one fails.");
        StringAssert.Contains(log.All, ScriptedChatClient.Secret, "The log is where the failure's detail belongs.");
    }

    // --- streamed through an agent, as AG-UI ------------------------------------------------------

    [TestMethod]
    [Timeout(30_000)]
    public async Task Stream_CarriesSnapshotsWhileTheToolRuns()
    {
        var chat = new ScriptedChatClient { StepCount = 2 };

        var events = await Collect(Agent(chat), Context(Goal));

        AguiConformance.Assert(events);
        Assert.IsInstanceOfType<RunFinishedEvent>(events[^1]);

        var callStart = events.FindIndex(evt => evt is ToolCallStartEvent { ToolCallName: PlannerExecutor.ToolName });
        var callResult = events.FindIndex(evt => evt is ToolCallResultEvent);
        var snapshots = events.Select((evt, index) => (evt, index)).Where(x => x.evt is ActivitySnapshotEvent).ToList();

        Assert.IsTrue(callStart >= 0 && callResult > callStart, "The tool call must start and report a result.");
        Assert.IsTrue(snapshots.Count >= 2 + 2 * 2, $"Expected a snapshot per change of state, got {snapshots.Count}.");
        Assert.IsTrue(snapshots.All(x => x.index > callStart && x.index < callResult),
            "Every snapshot must arrive while the tool runs — after its call, before its result.");

        var activities = snapshots.Select(x => (ActivitySnapshotEvent)x.evt).ToList();
        Assert.IsTrue(activities.All(a => a.ActivityType == PlannerExecutor.ActivityType && a.Replace == true));
        Assert.AreEqual(1, activities.Select(a => a.MessageId).Distinct().Count(), "One plan, one card.");
        Assert.AreEqual($"activity-{ScriptedChatClient.CallId}", activities[0].MessageId, "The card is keyed by its tool call.");

        Assert.AreEqual(PlannerExecutor.Status.Planning, Status(activities[0]));
        Assert.IsTrue(activities.Any(a => StepStatuses(a).Contains(PlannerExecutor.Status.Running)), "A step must be seen running.");

        var last = activities[^1];
        Assert.AreEqual(PlannerExecutor.Status.Completed, Status(last));
        CollectionAssert.AreEqual(new[] { PlannerExecutor.Status.Completed, PlannerExecutor.Status.Completed }, StepStatuses(last));
        Assert.AreEqual(ScriptedChatClient.FinalAnswer, last.Content.GetProperty("result").GetString());
        Assert.AreEqual(Goal, last.Content.GetProperty("goal").GetString());
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Stream_RecordsTheTokensOfEveryStepAndTheirTotal()
    {
        var chat = new ScriptedChatClient { StepCount = 2 };

        var events = await Collect(Agent(chat), Context(Goal));

        var last = events.OfType<ActivitySnapshotEvent>().Last();
        foreach (var step in last.Content.GetProperty("steps").EnumerateArray())
        {
            Assert.AreEqual(ScriptedChatClient.WorkflowCallTokens, step.GetProperty("usage").GetProperty("totalTokens").GetInt64());
        }

        // Planner, two steps and synthesizer: the card counts the whole plan, not only its steps.
        var workflowTokens = 4 * ScriptedChatClient.WorkflowCallTokens;
        Assert.AreEqual(workflowTokens, last.Content.GetProperty("usage").GetProperty("totalTokens").GetInt64());
        Assert.AreEqual(4 * 10, last.Content.GetProperty("usage").GetProperty("inputTokens").GetInt64());

        // The run's own tally: the agent's two calls, plus everything the plan spent inside its tool.
        var finished = (RunFinishedEvent)events[^1];
        Assert.IsNotNull(finished.Usage, "RUN_FINISHED must carry usage.");
        Assert.AreEqual(2 * ScriptedChatClient.AgentCallTokens + workflowTokens, finished.Usage.Sum(u => u.TotalTokens ?? 0));
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Stream_ReportsAFailedStepWithoutItsDetail()
    {
        var chat = new ScriptedChatClient { StepCount = 3, FailOnStep = 2 };

        var events = await Collect(Agent(chat), Context(Goal));

        AguiConformance.Assert(events);
        Assert.IsInstanceOfType<RunFinishedEvent>(events[^1], "A failed plan is a tool result, not a failed run.");

        var last = events.OfType<ActivitySnapshotEvent>().Last();
        Assert.AreEqual(PlannerExecutor.Status.Failed, Status(last));
        CollectionAssert.AreEqual(
            new[] { PlannerExecutor.Status.Completed, PlannerExecutor.Status.Failed, PlannerExecutor.Status.Pending },
            StepStatuses(last));

        // The planner and the step that finished; the failed step reported nothing.
        Assert.AreEqual(2 * ScriptedChatClient.WorkflowCallTokens, last.Content.GetProperty("usage").GetProperty("totalTokens").GetInt64());

        Assert.IsFalse(Wire(events).Contains(ScriptedChatClient.Secret), "The step's exception text must not reach the wire.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Stream_OfAnAgentThatThrowsEndsInRunError()
    {
        var chat = new ScriptedChatClient { ThrowOnAgentCall = true };

        var events = await Collect(Agent(chat), Context(Goal));

        AguiConformance.Assert(events);
        Assert.IsInstanceOfType<RunErrorEvent>(events[^1]);
        Assert.IsFalse(Wire(events).Contains(ScriptedChatClient.Secret), "The exception text must not reach the wire.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Stream_StopsTheRunWhenTheCallerLeaves()
    {
        var chat = new ScriptedChatClient { StepCount = 3, StallOnStep = 2 };
        using var cts = new CancellationTokenSource();

        // The framework's stream ends a cancelled run by throwing, which is what the SSE writer expects.
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
        {
            await foreach (BaseEvent evt in Stream(Agent(chat), Context(Goal), cts.Token))
            {
                if (evt is ActivitySnapshotEvent snapshot && StepStatuses(snapshot).ElementAtOrDefault(1) == PlannerExecutor.Status.Running)
                {
                    await cts.CancelAsync();
                }
            }
        });

        await Task.Delay(200);
        Assert.IsTrue(chat.StallCancelled, "Leaving must cancel the step that was running.");
        Assert.AreEqual(2, chat.ExecutedSteps.Count, "No step may start after the caller left.");
    }

    // --- over HTTP ---------------------------------------------------------------------------------

    [TestMethod]
    [Timeout(60_000)]
    public async Task Endpoint_StreamsTheSnapshotsAsServerSentEvents()
    {
        await using var app = await StartAsync(new ScriptedChatClient { StepCount = 2 });

        var response = await app.Client.PostAsync("/agents/amazonbedrock/agui", Json(Input(Goal)));
        var body = await response.Content.ReadAsStringAsync();

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        StringAssert.Contains(body, "\"type\":\"ACTIVITY_SNAPSHOT\"");
        StringAssert.Contains(body, $"\"activityType\":\"{PlannerExecutor.ActivityType}\"");
        StringAssert.Contains(body, "\"type\":\"RUN_FINISHED\"");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task Endpoint_ServesOnlyTheListedAgents()
    {
        await using var app = await StartAsync(new ScriptedChatClient());

        var response = await app.Client.PostAsync("/agents/architecture_council/agui", Json(Input(Goal)));

        Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task Endpoint_RefusesANonJsonBody()
    {
        await using var app = await StartAsync(new ScriptedChatClient());

        // A text/plain POST needs no CORS preflight; refusing it keeps other origins from starting paid runs.
        var plain = await app.Client.PostAsync("/agents/amazonbedrock/agui", new StringContent("hi", Encoding.UTF8, "text/plain"));

        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, plain.StatusCode);
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task Page_IsServedWithItsContentSecurityPolicy()
    {
        await using var app = await StartAsync(new ScriptedChatClient());

        var response = await app.Client.GetAsync("/agents");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.IsTrue(response.Headers.TryGetValues("Content-Security-Policy", out var csp));
        StringAssert.Contains(csp.Single(), "frame-ancestors 'none'");
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "<title>Agents</title>");
    }

    // --- helpers -----------------------------------------------------------------------------------

    static string? Status(ActivitySnapshotEvent snapshot) => snapshot.Content.GetProperty("status").GetString();

    static string?[] StepStatuses(ActivitySnapshotEvent snapshot) =>
        [.. snapshot.Content.GetProperty("steps").EnumerateArray().Select(step => step.GetProperty("status").GetString())];

    static IServiceProvider Services(ILogger? logger = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging =>
        {
            logging.ClearProviders();
            if (logger is not null)
            {
                logging.AddProvider(new SingleLoggerProvider(logger));
            }
        });
        return services.BuildServiceProvider();
    }

    /// <summary>An agent shaped like the real ones where it matters: the tool, and the activity stream.</summary>
    static AIAgent Agent(ScriptedChatClient chat, IServiceProvider? services = null)
    {
        services ??= Services();
        return chat
            .AsAIAgent(new ChatClientAgentOptions
            {
                Name = "amazonbedrock",
                ChatOptions = new ChatOptions { Tools = [PlannerExecutor.CreateTool(chat, [])] },
            }, services: services)
            .AsBuilder()
            .UseActivityStream()
            .Build(services);
    }

    /// <summary>The composition <c>MapAGUIServer</c> streams, minus the HTTP around it.</summary>
    static IAsyncEnumerable<BaseEvent> Stream(AIAgent agent, ChatRequestContext context, CancellationToken cancellationToken) =>
        agent.RunStreamingAsync(context.Messages, options: new ChatClientAgentRunOptions { ChatOptions = context.ChatOptions }, cancellationToken: cancellationToken)
            .AsChatResponseUpdatesAsync()
            .AsAGUIEventStreamAsync(context, cancellationToken);

    static async Task<List<BaseEvent>> Collect(AIAgent agent, ChatRequestContext context)
    {
        List<BaseEvent> events = [];
        await foreach (BaseEvent evt in Stream(agent, context, CancellationToken.None))
        {
            events.Add(evt);
        }
        return events;
    }

    static string Wire(IEnumerable<BaseEvent> events) =>
        string.Join("\n", events.Select(evt => JsonSerializer.Serialize(evt, evt.GetType(), WorkflowAguiStream.Json)));

    static StringContent Json(RunAgentInput input) =>
        new(JsonSerializer.Serialize(input, WorkflowAguiStream.Json), Encoding.UTF8, "application/json");

    static async Task<TestApp> StartAsync(ScriptedChatClient chat)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddAGUIServer();
        foreach (var name in AgentAguiEndpoints.AgentNames)
        {
            builder.Services.AddKeyedSingleton<AIAgent>(name, (sp, _) => Agent(chat, sp));
        }

        var app = builder.Build();
        app.MapAgentAgui();
        await app.StartAsync();
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

    sealed class SingleLoggerProvider(ILogger logger) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => logger;
        public void Dispose() { }
    }
}

/// <summary>
/// Answers as whichever role is asking — the calling agent, the planner, the step executor or the
/// synthesizer — told apart by the instructions each one carries.
/// </summary>
sealed class ScriptedChatClient : IChatClient
{
    public const string CallId = "call-plan";
    public const string FinalAnswer = "final answer";

    /// <summary>What every workflow call (planner, step, synthesizer) reports spending.</summary>
    public const int WorkflowCallTokens = 15;

    /// <summary>What every call of the calling agent itself reports, so the two can be told apart.</summary>
    public const int AgentCallTokens = 101;

    /// <summary>Text a failing step throws with. It must show up in the log and nowhere on the wire.</summary>
    public const string Secret = "secret-host.internal:5432";

    readonly List<string> _executed = [];

    public int StepCount { get; init; } = 2;

    /// <summary>The 1-based step whose execution throws.</summary>
    public int? FailOnStep { get; init; }

    /// <summary>The 1-based step whose execution waits until it is cancelled.</summary>
    public int? StallOnStep { get; init; }

    public bool ThrowOnAgentCall { get; init; }

    public bool StallCancelled { get; private set; }

    public string SynthesisPrompt { get; private set; } = "";

    public IReadOnlyList<string> ExecutedSteps
    {
        get { lock (_executed) { return [.. _executed]; } }
    }

    public async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        var instructions = options?.Instructions + string.Join("\n", list.Where(m => m.Role == ChatRole.System).Select(m => m.Text));
        var prompt = list.LastOrDefault(m => m.Role == ChatRole.User)?.Text ?? "";

        if (instructions.Contains("You plan work"))
        {
            var steps = Enumerable.Range(1, StepCount).Select(i => new { title = $"Step {i}", instructions = $"Do part {i}." });
            return Text(JsonSerializer.Serialize(new { steps }));
        }

        if (instructions.Contains("You carry out exactly one step"))
        {
            var match = Regex.Match(prompt, @"Your step \((\d+) of \d+\): (.+)");
            var number = int.Parse(match.Groups[1].Value);
            var title = match.Groups[2].Value.Trim();
            lock (_executed) { _executed.Add(title); }

            if (number == FailOnStep)
            {
                throw new InvalidOperationException($"Could not reach {Secret}.");
            }

            if (number == StallOnStep)
            {
                try
                {
                    await Task.Delay(Timeout.Infinite, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    StallCancelled = true;
                    throw;
                }
            }

            return Text($"result of {title}");
        }

        if (instructions.Contains("You are given a goal"))
        {
            SynthesisPrompt = prompt;
            return Text(FinalAnswer);
        }

        // The calling agent: call the tool once, then answer from its result.
        if (ThrowOnAgentCall)
        {
            throw new InvalidOperationException($"Could not reach {Secret}.");
        }

        if (list.SelectMany(m => m.Contents).OfType<FunctionResultContent>().FirstOrDefault() is { } result)
        {
            return Text($"Here is what I found: {result.Result}", agentCall: true);
        }

        return new ChatResponse(new ChatMessage(ChatRole.Assistant,
            [new FunctionCallContent(CallId, PlannerExecutor.ToolName, new Dictionary<string, object?> { ["goal"] = prompt })]))
        {
            Usage = Usage(100, 1),
        };
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var response = await GetResponseAsync(messages, options, cancellationToken);
        foreach (var update in response.ToChatResponseUpdates())
        {
            yield return update;
        }
    }

    static ChatResponse Text(string text, bool agentCall = false) => new(new ChatMessage(ChatRole.Assistant, text))
    {
        Usage = agentCall ? Usage(100, 1) : Usage(10, 5),
    };

    static UsageDetails Usage(long input, long output) =>
        new() { InputTokenCount = input, OutputTokenCount = output, TotalTokenCount = input + output };

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose() { }
}
