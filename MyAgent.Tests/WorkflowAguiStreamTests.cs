using System.Text.Json;
using AGUI.Abstractions;
using AGUI.Server;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using static MyAgent.Tests.CouncilStubs;

namespace MyAgent.Tests;

/// <summary>
/// Covers <see cref="WorkflowAguiStream"/> against a stubbed chat client, so the guarantees the
/// browser depends on — one terminal event, always, and never a truncated run reported as a
/// finished one — are checked without spending a model call.
/// </summary>
[TestClass]
[TestCategory("Offline")]
public sealed class WorkflowAguiStreamTests
{
    const int TopicLimit = 500;

    // --- the happy path ---------------------------------------------------------------------

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_OpensWithRunStartedEchoingTheCallersIds()
    {
        var events = await Collect(Council(), Context("a topic", threadId: "thread-7", runId: "run-9"));

        var started = events[0] as RunStartedEvent;
        Assert.IsNotNull(started, $"Expected RUN_STARTED first, got {events[0].Type}.");
        Assert.AreEqual("thread-7", started.ThreadId);
        Assert.AreEqual("run-9", started.RunId);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_EndsWithExactlyOneTerminalEvent()
    {
        var events = await Collect(Council(), Context("a topic"));

        Assert.IsInstanceOfType<RunFinishedEvent>(events[^1], $"Expected RUN_FINISHED last, got {events[^1].Type}.");
        AguiConformance.Assert(events);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_CarriesEachSpeakersNameOnTheMessageThatOpens()
    {
        var events = await Collect(Council(), Context("a topic"));

        CollectionAssert.AreEqual(
            new[] { "first_agent", "second_agent", "third_agent" },
            events.OfType<TextMessageStartEvent>().Select(s => s.Name).ToArray(),
            "AG-UI attributes speech through TEXT_MESSAGE_START.name; the page keys its cards on it.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Run_WithToolCalls_PlacesEachCallInExactlyOneTurn()
    {
        var events = await Collect(Council(withToolCall: true), Context("a topic"));

        AguiConformance.Assert(events);

        var calls = events.OfType<ToolCallStartEvent>().ToList();
        Assert.AreEqual(3, calls.Count, "Each participant called its tool once.");

        // The page attaches a tool chip to the turn owning parentMessageId, so a call that names a
        // message nobody opened would be drawn against whoever happened to speak last.
        var messageNames = events.OfType<TextMessageStartEvent>().ToDictionary(s => s.MessageId, s => s.Name);
        foreach (ToolCallStartEvent call in calls)
        {
            Assert.IsNotNull(call.ParentMessageId, $"Tool call '{call.ToolCallName}' named no parent message.");
            Assert.IsTrue(messageNames.ContainsKey(call.ParentMessageId!),
                $"Tool call '{call.ToolCallName}' names parent '{call.ParentMessageId}', which never opened.");
        }

        Assert.AreEqual(3, events.OfType<ToolCallResultEvent>().Count(), "Every call reported a result.");
    }

    // --- rejected input ---------------------------------------------------------------------

    [TestMethod]
    [Timeout(30_000)]
    public async Task BlankTopic_IsRejectedAsAnInvalidInputRun()
    {
        var events = await Collect(Council(), Context("   "));

        Assert.IsInstanceOfType<RunStartedEvent>(events[0], "Even a rejected run reports as a run.");
        var error = events[^1] as RunErrorEvent;
        Assert.IsNotNull(error, $"Expected RUN_ERROR last, got {events[^1].Type}.");
        Assert.AreEqual(WorkflowAguiStream.InvalidInputCode, error.Code);
        StringAssert.Contains(error.Message, "provide a topic");
        Assert.AreEqual(0, events.OfType<TextMessageStartEvent>().Count(), "No agent should have spoken.");
        AguiConformance.Assert(events);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task OverlongTopic_IsRejectedAndSaysTheLimit()
    {
        var events = await Collect(Council(), Context(new string('x', 11)), maxTopicLength: 10);

        var error = events[^1] as RunErrorEvent;
        Assert.IsNotNull(error);
        Assert.AreEqual(WorkflowAguiStream.InvalidInputCode, error.Code);
        StringAssert.Contains(error.Message, "11 characters");
        StringAssert.Contains(error.Message, "limit is 10");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task TopicOfExactlyTheLimit_IsAccepted()
    {
        // The page sets its input's maxlength to this number, so an off-by-one here would refuse
        // exactly what the reader was allowed to type.
        var events = await Collect(Council(), Context(new string('x', 10)), maxTopicLength: 10);

        Assert.IsInstanceOfType<RunFinishedEvent>(events[^1], $"A topic at the limit must run; got {events[^1].Type}.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task NoUserMessage_IsRejectedRatherThanRunningOnNothing()
    {
        var input = new RunAgentInput { ThreadId = "t", RunId = "r", Messages = [], Tools = [] };
        var events = await Collect(Council(), input.ToChatRequestContext(WorkflowAguiStream.Json, new AGUIStreamOptions()));

        var error = events[^1] as RunErrorEvent;
        Assert.IsNotNull(error, $"Expected RUN_ERROR last, got {events[^1].Type}.");
        Assert.AreEqual(WorkflowAguiStream.InvalidInputCode, error.Code);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task TheTopicIsTheNewestUserMessage()
    {
        var chat = new StubChatClient();
        var events = await Collect(Council(chat), MultiMessageContext("stale question", "the real topic"));

        Assert.IsInstanceOfType<RunFinishedEvent>(events[^1]);
        Assert.IsTrue(chat.Calls > 0, "The run should have gone ahead on the newest topic.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task LengthIsMeasuredAcrossEveryMessage_NotJustTheNewest()
    {
        // Measuring only the newest message left every other one unbounded, and the group chat
        // replays the whole transcript to each participant — so an unbounded request is an
        // unbounded bill.
        var chat = new StubChatClient();
        var events = await Collect(Council(chat), MultiMessageContext(new string('x', 80), new string('y', 80)), maxTopicLength: 100);

        var error = events[^1] as RunErrorEvent;
        Assert.IsNotNull(error, $"Expected the pair to be refused as too long, got {events[^1].Type}.");
        Assert.AreEqual(WorkflowAguiStream.InvalidInputCode, error.Code);
        StringAssert.Contains(error.Message, "160 characters");
        Assert.AreEqual(0, chat.Calls, "Nothing should have reached the model.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task TooManyMessages_AreRefusedBeforeTheModelSeesThem()
    {
        var chat = new StubChatClient();
        var events = await Collect(Council(chat), MultiMessageContext([.. Enumerable.Repeat("hi", 20)]));

        var error = events[^1] as RunErrorEvent;
        Assert.IsNotNull(error, $"Expected a rejection, got {events[^1].Type}.");
        Assert.AreEqual(WorkflowAguiStream.InvalidInputCode, error.Code);
        StringAssert.Contains(error.Message, "not a conversation");
        Assert.AreEqual(0, chat.Calls);
    }

    // --- runs that do not finish ------------------------------------------------------------

    [TestMethod]
    [Timeout(30_000)]
    public async Task CallerHangsUp_ReportsNothingAtAll()
    {
        using var caller = new CancellationTokenSource();
        var chat = new StubChatClient { Stall = TimeSpan.FromSeconds(30) };
        List<BaseEvent> events = [];

        await foreach (var evt in WorkflowAguiStream.RunAsync(
            Council(chat), Context("a topic"), TopicLimit, NullLogger.Instance, "test-reference", caller.Token))
        {
            events.Add(evt);
            if (evt is RunStartedEvent) await caller.CancelAsync();
        }

        // Nobody is listening once the caller has gone, and the protocol requires no terminal event.
        // Reporting RUN_FINISHED here — which is what happened before — would have the page render a
        // truncated run as the council's verdict.
        CollectionAssert.AreEqual(
            new[] { "RUN_STARTED" },
            events.Select(evt => evt.Type.ToString()).ToArray(),
            $"Expected the stream to simply stop; got: {string.Join(", ", events.Select(e => e.Type))}");

        var spent = chat.Calls;
        await Task.Delay(500);
        Assert.AreEqual(spent, chat.Calls, "The run kept calling the model after the caller hung up.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task AgentThrows_ReportsAReferenceAndNotTheException()
    {
        const string secret = "Password=hunter2";
        var log = new CapturingLogger();
        var events = await Collect(Council(throwWith: secret), Context("a topic"), logger: log);

        var error = events[^1] as RunErrorEvent;
        Assert.IsNotNull(error, $"Expected RUN_ERROR last, got {events[^1].Type}. A failed run must not report as finished.");
        Assert.AreEqual(WorkflowAguiStream.RunFailedCode, error.Code);
        StringAssert.Contains(error.Message, "test-reference");
        AguiConformance.Assert(events);

        AssertNothingLeaked(events, secret);

        // The other half of the contract: the reference must lead somewhere.
        StringAssert.Contains(log.All, secret,
            "The detail has to reach the log, or the client is handed a reference that points at nothing.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task ErrorReportedAsContent_FailsTheRunWithoutPuttingTheDetailOnTheWire()
    {
        // An update carrying text *and* an error is how a run failure actually arrives. AG-UI drops
        // the error (it has no event for it) but copies the whole update into the text event's
        // rawEvent — so the detail rides along on a perfectly ordinary content frame.
        const string secret = "Server=db;Password=hunter2";
        var log = new CapturingLogger();
        var events = await Collect(Council(errorWith: secret), Context("a topic"), logger: log);

        Assert.AreEqual(0, events.OfType<RunFinishedEvent>().Count(),
            "A run that reported an error must not be presented as a finished one.");
        Assert.AreEqual(WorkflowAguiStream.RunFailedCode, (events[^1] as RunErrorEvent)?.Code);

        AssertNothingLeaked(events, secret);
        StringAssert.Contains(log.All, secret, "The detail belongs in the log.");
    }

    // --- helpers -----------------------------------------------------------------------------

    /// <summary>
    /// Serializes every event exactly as the transport does and asserts the secret is nowhere in the
    /// bytes — including <c>rawEvent</c>, which is scrubbed by the stream rather than the transport
    /// so that a second transport cannot reintroduce the leak.
    /// </summary>
    static void AssertNothingLeaked(List<BaseEvent> events, string secret)
    {
        foreach (var evt in events)
        {
            var json = JsonSerializer.Serialize(evt, evt.GetType(), WorkflowAguiStream.Json);
            Assert.IsFalse(json.Contains(secret, StringComparison.OrdinalIgnoreCase),
                $"The failure's detail reached the wire: {json}");
        }
    }

    static async Task<List<BaseEvent>> Collect(
        Workflow workflow,
        ChatRequestContext context,
        int maxTopicLength = TopicLimit,
        ILogger? logger = null)
    {
        List<BaseEvent> events = [];
        await foreach (var evt in WorkflowAguiStream.RunAsync(
            workflow, context, maxTopicLength, logger ?? NullLogger.Instance, "test-reference", CancellationToken.None))
        {
            events.Add(evt);
        }

        Assert.IsTrue(events.Count > 0, "The stream produced nothing at all.");
        return events;
    }
}
