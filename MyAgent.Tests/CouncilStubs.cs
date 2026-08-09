using System.Runtime.CompilerServices;
using AGUI.Abstractions;
using AGUI.Server;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using MSAssert = Microsoft.VisualStudio.TestTools.UnitTesting.Assert;

namespace MyAgent.Tests;

/// <summary>
/// A council with no model behind it, so the guarantees the browser depends on can be checked
/// without spending a model call. Shared by the stream tests and the endpoint tests.
/// </summary>
static class CouncilStubs
{
    /// <summary>A three-participant round robin, the same shape as the real council.</summary>
    internal static Workflow Council(StubChatClient chat)
    {
        AIAgent Participant(string name) => chat.AsAIAgent(name: name, description: name, instructions: "debate");

        return AgentWorkflowBuilder
            .CreateGroupChatBuilderWith(agents => new RoundRobinGroupChatManager(agents) { MaximumIterationCount = 3 })
            .AddParticipants(Participant("first_agent"), Participant("second_agent"), Participant("third_agent"))
            .WithName("test_council")
            .WithDescription("A council with no model behind it.")
            .Build();
    }

    internal static Workflow Council(
        TimeSpan? stall = null,
        string? throwWith = null,
        string? errorWith = null,
        bool withToolCall = false) =>
        Council(new StubChatClient
        {
            Stall = stall,
            ThrowWith = throwWith,
            ErrorWith = errorWith,
            WithToolCall = withToolCall,
        });

    /// <summary>A request carrying several messages, for the bounds that apply to a whole request.</summary>
    internal static ChatRequestContext MultiMessageContext(params string[] topics)
    {
        var input = new RunAgentInput
        {
            ThreadId = "t",
            RunId = "r",
            Messages = [.. topics.Select((topic, index) => (AGUIMessage)new AGUIUserMessage { Id = $"u{index}", Content = topic })],
            Tools = [],
        };

        return input.ToChatRequestContext(WorkflowAguiStream.Json, new AGUIStreamOptions());
    }

    internal static ChatRequestContext Context(string topic, string threadId = "t", string runId = "r") =>
        Input(topic, threadId, runId).ToChatRequestContext(WorkflowAguiStream.Json, new AGUIStreamOptions());

    internal static RunAgentInput Input(string topic, string threadId = "t", string runId = "r") => new()
    {
        ThreadId = threadId,
        RunId = runId,
        Messages = [new AGUIUserMessage { Id = "u1", Content = topic }],
        Tools = [],
    };
}

/// <summary>
/// Stands in for the chat client the council's participants talk to. Every knob exists because some
/// guarantee depends on it: a stall keeps a run open long enough to cancel it, a throw exercises
/// the failure path, an
/// <see cref="ErrorContent"/> the "reported as content" path AG-UI's mapper silently drops.
/// </summary>
/// <summary>
/// One call to the model: what it was shown, and how many tools it was allowed to call. Both
/// halves matter — Bedrock rejects a request that carries tool calls or results while declaring no
/// tools, which is how a caucus of tool-free drafters can be handed a history it cannot be asked
/// about.
/// </summary>
sealed record StubRequest(IReadOnlyList<ChatMessage> Messages, int ToolCount);

sealed class StubChatClient : IChatClient
{
    readonly List<StubRequest> _requests = [];
    int _calls;

    public TimeSpan? Stall { get; init; }

    public string? ThrowWith { get; init; }

    /// <summary>Reported alongside text in one update, which is how a run failure actually arrives.</summary>
    public string? ErrorWith { get; init; }

    /// <summary>
    /// Which call reports <see cref="ErrorWith"/>, or every call when null. A caucus needs one team
    /// member to fail while the others answer: that is the case where the aggregate still looks like
    /// a successful run, one draft short.
    /// </summary>
    public int? ErrorOnCall { get; init; }

    public bool WithToolCall { get; init; }

    /// <summary>How many calls have been made — i.e. what the run has cost.</summary>
    public int Calls => Volatile.Read(ref _calls);

    /// <summary>
    /// Every request put in front of the model, in the order the calls were made. What a caucus
    /// keeps out of the shared history can only be checked by looking at what a later participant
    /// was actually asked.
    /// </summary>
    public IReadOnlyList<StubRequest> Requests
    {
        get { lock (_requests) { return [.. _requests]; } }
    }

    /// <summary>
    /// The council streams, but a participant's caucus runs its team through the non-streaming path.
    /// Both reach the model, so both have to count and cost the same here.
    /// </summary>
    public async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default) =>
        await GetStreamingResponseAsync(messages, options, cancellationToken).ToChatResponseAsync(cancellationToken);

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        int call = Interlocked.Increment(ref _calls);
        lock (_requests) { _requests.Add(new StubRequest([.. messages], options?.Tools?.Count ?? 0)); }

        if (Stall is { } delay)
        {
            await Task.Delay(delay, cancellationToken);
        }

        if (ThrowWith is not null)
        {
            throw new InvalidOperationException(ThrowWith);
        }

        if (WithToolCall && call <= 3)
        {
            // A tool-calling agent speaks twice: a preamble carrying the call, then its answer.
            yield return new ChatResponseUpdate(ChatRole.Assistant, "Let me check. ");
            yield return new ChatResponseUpdate(ChatRole.Assistant,
                [new FunctionCallContent($"call-{call}", "get_role", new Dictionary<string, object?>())]);
            yield return new ChatResponseUpdate(ChatRole.Tool,
                [new FunctionResultContent($"call-{call}", $"role {call}")]);
        }

        foreach (var chunk in new[] { "position ", call.ToString() })
        {
            yield return new ChatResponseUpdate(ChatRole.Assistant, chunk);
            await Task.Yield();
        }

        if (ErrorWith is not null && (ErrorOnCall is null || ErrorOnCall == call))
        {
            // Text and an error in the same update: the mapper has no event for ErrorContent, so it
            // drops it — but it still copies the whole update into the text event's rawEvent.
            yield return new ChatResponseUpdate(ChatRole.Assistant, [new TextContent("tail"), new ErrorContent(ErrorWith)]);
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose() { }
}

/// <summary>
/// The invariants any AG-UI client may rely on, checked the way the protocol's own reference
/// verifier checks them. Applied to every path — finished, rejected, cancelled, thrown — so a client
/// that is not this page still gets a stream it can drive a state machine from.
/// </summary>
static class AguiConformance
{
    internal static void Assert(IReadOnlyList<BaseEvent> events)
    {
        MSAssert.IsTrue(events.Count > 0, "The stream produced nothing at all.");
        MSAssert.IsTrue(events[0] is RunStartedEvent or RunErrorEvent,
            $"A run opens with RUN_STARTED (or RUN_ERROR); got {events[0].Type}.");

        var terminals = events.Where(evt => evt is RunFinishedEvent or RunErrorEvent).ToList();
        MSAssert.AreEqual(1, terminals.Count,
            $"A run ends exactly once; got: {string.Join(", ", terminals.Select(t => t.Type))}");
        MSAssert.AreSame(events[^1], terminals[0], "The terminal event must be the last one.");

        var openMessages = new HashSet<string>();
        var everOpened = new HashSet<string>();
        var openCalls = new HashSet<string>();
        var everCalled = new HashSet<string>();

        foreach (BaseEvent evt in events)
        {
            switch (evt)
            {
                case TextMessageStartEvent start:
                    // Never cleared: an id that opens twice means the transcript is being replayed,
                    // which draws every card a second time.
                    MSAssert.IsTrue(everOpened.Add(start.MessageId), $"Message '{start.MessageId}' opened twice in one run.");
                    openMessages.Add(start.MessageId);
                    break;

                case TextMessageContentEvent content:
                    MSAssert.IsTrue(openMessages.Contains(content.MessageId),
                        $"Content arrived for message '{content.MessageId}', which is not open.");
                    break;

                case TextMessageEndEvent end:
                    MSAssert.IsTrue(openMessages.Remove(end.MessageId), $"Message '{end.MessageId}' closed without being open.");
                    break;

                // A call may legally reopen when its arguments arrive in pieces, so only the
                // ordering within a call is asserted, not that it opens once.
                case ToolCallStartEvent call:
                    openCalls.Add(call.ToolCallId);
                    everCalled.Add(call.ToolCallId);
                    break;

                case ToolCallArgsEvent args:
                    MSAssert.IsTrue(openCalls.Contains(args.ToolCallId),
                        $"Arguments arrived for tool call '{args.ToolCallId}', which is not open.");
                    break;

                case ToolCallEndEvent callEnd:
                    MSAssert.IsTrue(openCalls.Remove(callEnd.ToolCallId),
                        $"Tool call '{callEnd.ToolCallId}' closed without being open.");
                    break;

                case ToolCallResultEvent result:
                    MSAssert.IsTrue(everCalled.Contains(result.ToolCallId),
                        $"A result arrived for tool call '{result.ToolCallId}', which was never started.");
                    break;
            }
        }

        MSAssert.AreEqual(0, openMessages.Count,
            $"These messages were still open when the run ended, so a client's last bubble spins forever: {string.Join(", ", openMessages)}");
        MSAssert.AreEqual(0, openCalls.Count,
            $"These tool calls were never closed: {string.Join(", ", openCalls)}");
    }
}

/// <summary>Keeps what was logged, so "the client gets a reference, the log gets the detail" is testable.</summary>
sealed class CapturingLogger : ILogger
{
    readonly List<string> _entries = [];

    public IReadOnlyList<string> Entries
    {
        get { lock (_entries) { return [.. _entries]; } }
    }

    public string All => string.Join("\n", Entries);

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (_entries)
        {
            _entries.Add($"{logLevel} {eventId.Name}: {formatter(state, exception)} {exception}");
        }
    }
}
