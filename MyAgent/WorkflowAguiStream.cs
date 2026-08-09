using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using AGUI.Abstractions;
using AGUI.Server;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;

namespace MyAgent;

/// <summary>
/// Streams a <see cref="Workflow"/> as <see href="https://docs.ag-ui.com">AG-UI</see> events.
/// Nothing here knows the council's topology: the workflow is hosted as an agent, and AG-UI's own
/// mapper turns its updates into protocol events, so any workflow shape streams the same way.
/// </summary>
/// <remarks>
/// <para>
/// The mapping itself is AG-UI's (<see cref="ChatResponseUpdateAGUIExtensions.AsAGUIEventStreamAsync"/>);
/// what this class adds is the protocol's terminal contract. AG-UI's ASP.NET bridge never emits
/// <see cref="RunErrorEvent"/> — a run that fails simply stops mid-message, which on the wire looks
/// exactly like a run that ended normally. Every failure path here ends in RUN_ERROR instead, and
/// exactly one terminal event is ever emitted.
/// </para>
/// <para>
/// This class owns the whole wire contract, secrecy included: it nulls <see cref="BaseEvent.RawEvent"/>
/// on every event it yields (see <see cref="Scrub"/>), so a second transport cannot accidentally
/// publish what the HTTP one is careful to strip.
/// </para>
/// <para>
/// What bounds a run is the caller hanging up: disconnecting disposes this enumerator, which cancels
/// the run and stops it buying tokens within milliseconds. There is deliberately no server-side
/// deadline — a client that stays connected while the run hangs is bounded only by the provider's own
/// timeouts, and holds one of the endpoint's concurrency permits until it returns.
/// </para>
/// <para>
/// Tools a client advertises in <c>RunAgentInput.Tools</c> are deliberately not forwarded, so this
/// endpoint is not drop-in for AG-UI front ends that rely on frontend actions, generative UI, or
/// human-in-the-loop approval — those would silently never fire. If <c>ChatOptions</c> is ever
/// forwarded to enable them, the terminal decision below must also start treating a
/// <c>RunFinishedEvent</c> whose outcome is an interrupt as a non-success.
/// </para>
/// </remarks>
public static class WorkflowAguiStream
{
    /// <summary>The caller's input was rejected before the workflow started.</summary>
    public const string InvalidInputCode = "invalid_input";

    /// <summary>The run failed. The message carries a reference; the log carries the detail.</summary>
    public const string RunFailedCode = "run_failed";

    /// <summary>
    /// How many messages one run may carry. A run takes a topic, not a conversation; a couple of
    /// spare slots keep an AG-UI client that pads the thread from being rejected outright.
    /// </summary>
    const int MaxMessagesPerRun = 8;

    /// <summary>
    /// The wire contract, both directions. AG-UI ships a source-generated contract for its own
    /// types; combining it with the reflection resolver keeps the shape exactly as the protocol
    /// defines it while still handling the arbitrary payloads (tool arguments, state) riding inside.
    /// </summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        TypeInfoResolver = JsonTypeInfoResolver.Combine(
            AGUIJsonSerializerContext.Default,
            new DefaultJsonTypeInfoResolver()),
    };

    /// <param name="maxTopicLength">
    /// The longest topic accepted, in characters, counted across every message in the request — so it
    /// is the bound on how much text one request can put in front of the model.
    /// </param>
    /// <param name="failureReference">
    /// Identifies this run in the log. It is the only thing a failure tells the client, because the
    /// run's own error text can name hosts, keys or connection strings.
    /// </param>
    public static async IAsyncEnumerable<BaseEvent> RunAsync(
        Workflow workflow,
        ChatRequestContext context,
        int maxTopicLength,
        ILogger logger,
        string failureReference,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string threadId = context.Input.ThreadId;
        string runId = context.Input.RunId;

        if (Validate(context.Messages, maxTopicLength) is { } problem)
        {
            // A run that never starts still reports as a run: an AG-UI client learns of a problem
            // only through the event stream.
            logger.LogInformation(Events.RunRejected, "AG-UI run {RunId} rejected: {Problem}", runId, problem);
            yield return Scrub(new RunStartedEvent { ThreadId = threadId, RunId = runId });
            yield return Scrub(new RunErrorEvent { Message = problem, Code = InvalidInputCode });
            yield break;
        }

        // includeExceptionDetails: the detail is wanted for the log. It never reaches the wire —
        // every RUN_ERROR this class emits carries a message of its own.
        // includeWorkflowOutputsInResponse: leaving this on replays the entire transcript a second
        // time after the live turns, reusing their message ids — every card would be drawn twice.
        AIAgent agent = workflow.AsAIAgent(
            name: workflow.Name,
            description: workflow.Description,
            executionEnvironment: InProcessExecution.OffThread,
            includeExceptionDetails: true,
            includeWorkflowOutputsInResponse: false);

        var outcome = new RunOutcome();

        long startedAt = Stopwatch.GetTimestamp();
        logger.LogInformation(Events.RunStarted, "AG-UI run {RunId} started on workflow {Workflow} (thread {ThreadId}).",
            runId, workflow.Name, threadId);

        // The message currently streaming, if any. A terminal RUN_ERROR is legal while a message is
        // open, but it leaves a generic client's last bubble spinning forever, so close it first.
        string? openMessageId = null;
        var terminated = false;
        var count = 0;

        IAsyncEnumerable<BaseEvent> events = Guarded(
            Updates(agent, context.Messages, outcome, cancellationToken).AsAGUIEventStreamAsync(context, cancellationToken),
            outcome,
            cancellationToken);

        await foreach (BaseEvent evt in events)
        {
            // Nobody is listening once the caller has gone, and the protocol requires no terminal
            // event — so stop, rather than describe a run to a closed connection.
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            openMessageId = evt switch
            {
                TextMessageStartEvent start => start.MessageId,
                TextMessageEndEvent => null,
                _ => openMessageId,
            };

            // A failed run does not throw out here — it arrives as content the mapper has no event
            // for and drops, so the mapper still signs the run off as finished. Reporting that would
            // present half a transcript as a result.
            if (evt is RunFinishedEvent && outcome.Incomplete)
            {
                break;
            }

            terminated = evt is RunFinishedEvent or RunErrorEvent;
            count++;
            yield return Scrub(evt);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            logger.LogInformation(Events.RunAbandoned, "AG-UI run {RunId} abandoned by its caller after {Elapsed}.",
                runId, Stopwatch.GetElapsedTime(startedAt));
            yield break;
        }

        if (terminated)
        {
            logger.LogInformation(Events.RunFinished, "AG-UI run {RunId} finished in {Elapsed} after {EventCount} events.",
                runId, Stopwatch.GetElapsedTime(startedAt), count);
            yield break;
        }

        // The run failed, or the stream ran dry without a terminal event. Either way the protocol
        // still owes the client an outcome — and this is the only place one is invented.
        if (openMessageId is { } unfinished)
        {
            yield return Scrub(new TextMessageEndEvent { MessageId = unfinished });
        }

        yield return Scrub(Terminal(outcome, runId, failureReference, logger, startedAt));
    }

    /// <summary>
    /// Enumerates <paramref name="events"/>, recording a thrown exception on <paramref name="outcome"/>
    /// instead of propagating it, and ending the stream.
    /// </summary>
    /// <remarks>
    /// This helper exists only because a C# iterator cannot yield from inside a try/catch. Confining
    /// the manual enumerator loop here lets the caller read as one linear pass with a single place
    /// where a terminal event is decided.
    /// </remarks>
    static async IAsyncEnumerable<BaseEvent> Guarded(
        IAsyncEnumerable<BaseEvent> events,
        RunOutcome outcome,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using var enumerator = events.GetAsyncEnumerator(cancellationToken);

        while (true)
        {
            BaseEvent? current = null;

            try
            {
                if (await enumerator.MoveNextAsync())
                {
                    current = enumerator.Current;
                }
            }
            catch (Exception ex)
            {
                // Not rethrown: the caller owes the client a RUN_ERROR, and it cannot emit one from
                // a catch block.
                outcome.Fault = ex;
            }

            // Null means the stream ended, either normally or because it threw. Every event the
            // mapper yields is a constructed one, so null is never a real event.
            if (current is null)
            {
                yield break;
            }

            yield return current;
        }
    }

    /// <summary>
    /// Drops <see cref="BaseEvent.RawEvent"/>, which AG-UI fills with the whole underlying update.
    /// It roughly doubles every frame, tells a client of the protocol nothing it can rely on, and —
    /// the reason this lives here rather than in the transport — carries whatever the run reported,
    /// including the exception detail this class is careful to keep off the wire. An update that
    /// carries text and an error together puts that detail in a TEXT_MESSAGE_CONTENT's raw event.
    /// </summary>
    static BaseEvent Scrub(BaseEvent evt)
    {
        evt.RawEvent = null;
        return evt;
    }

    /// <summary>
    /// The error to end on. The run's own message is logged rather than sent: it can name hosts, keys
    /// or connection strings, and the client only needs to know the run did not finish.
    /// </summary>
    static RunErrorEvent Terminal(RunOutcome outcome, string runId, string failureReference, ILogger logger, long startedAt)
    {
        if (outcome.Fault is { } fault)
        {
            logger.LogError(Events.RunFailed, fault,
                "AG-UI run {RunId} threw after {Elapsed} (reference {FailureReference}).",
                runId, Stopwatch.GetElapsedTime(startedAt), failureReference);

            return Failed(failureReference);
        }

        if (outcome.Failed)
        {
            logger.LogError(Events.RunFailed, "AG-UI run {RunId} failed (reference {FailureReference}): {Detail}",
                runId, failureReference, outcome.Detail ?? "no detail reported");

            return Failed(failureReference);
        }

        // AG-UI's mapper always appends a RunFinishedEvent, so reaching here means it stopped
        // behaving that way. Keep the honest answer rather than inventing a result.
        logger.LogError(Events.RunFailed, "AG-UI run {RunId} ended without a terminal event (reference {FailureReference}).",
            runId, failureReference);

        return new RunErrorEvent
        {
            Message = $"The run ended before it produced a result (reference {failureReference}).",
            Code = RunFailedCode,
        };
    }

    static RunErrorEvent Failed(string failureReference) =>
        new() { Message = $"The run failed (reference {failureReference}).", Code = RunFailedCode };

    /// <summary>Carries a failure out of the run, which cannot throw it where the caller can yield.</summary>
    sealed class RunOutcome
    {
        /// <summary>An executor reported an error as content, which AG-UI's mapper drops.</summary>
        public bool Failed { get; set; }

        /// <summary>Enumerating the run threw.</summary>
        public Exception? Fault { get; set; }

        /// <summary>What went wrong, for the log. Never for the wire.</summary>
        public string? Detail { get; set; }

        /// <summary>True when the run cannot honestly be reported as finished.</summary>
        public bool Incomplete => Failed || Fault is not null;
    }

    /// <summary>
    /// Runs the hosted workflow, adapts its updates to the chat shape AG-UI maps from, and notes any
    /// error the run reports as content on its way past.
    /// </summary>
    static async IAsyncEnumerable<ChatResponseUpdate> Updates(
        AIAgent agent,
        IEnumerable<ChatMessage> messages,
        RunOutcome outcome,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // No ChatOptions are forwarded: the tools an AG-UI client advertises are its own to run,
        // and this workflow's participants bring the tools they need.
        await foreach (AgentResponseUpdate update in agent.RunStreamingAsync(messages, cancellationToken: cancellationToken))
        {
            if (update.Contents.OfType<ErrorContent>().FirstOrDefault() is { } error)
            {
                // Latched, and deliberately not cleared by a later successful turn: a run that
                // reported an error somewhere produced at best a partial transcript, and calling
                // that a verdict is the one mistake this class exists to prevent.
                outcome.Failed = true;
                outcome.Detail ??= error.Message;
            }

            yield return update.AsChatResponseUpdate();
        }
    }

    /// <summary>
    /// Bounds the whole request, not one field of it. Measuring only the newest user message left
    /// every other message unbounded — and the group chat replays the transcript to each
    /// participant, so an unbounded request is an unbounded bill.
    /// </summary>
    internal static string? Validate(IReadOnlyList<ChatMessage> messages, int maxTopicLength)
    {
        if (messages.Count > MaxMessagesPerRun)
        {
            return $"A run takes a topic, not a conversation ({messages.Count} messages; the limit is {MaxMessagesPerRun}).";
        }

        // ChatMessage.Text concatenates only the text parts, so an attachment is invisible to a
        // length check. This workflow has nothing to do with one either way.
        if (messages.SelectMany(message => message.Contents).Any(content => content is not TextContent))
        {
            return "A run takes a text topic; attachments and other content are not accepted.";
        }

        var total = messages.Sum(message => message.Text.Length);
        if (total > maxTopicLength)
        {
            return $"That topic is too long ({total} characters; the limit is {maxTopicLength}).";
        }

        var topic = messages.LastOrDefault(message => message.Role == ChatRole.User)?.Text;

        return string.IsNullOrWhiteSpace(topic) ? "Please provide a topic to run." : null;
    }

    /// <summary>Run lifecycle, so a bill that spikes can be explained.</summary>
    static class Events
    {
        public static readonly EventId RunStarted = new(1000, nameof(RunStarted));
        public static readonly EventId RunFinished = new(1001, nameof(RunFinished));
        public static readonly EventId RunRejected = new(1002, nameof(RunRejected));
        public static readonly EventId RunAbandoned = new(1003, nameof(RunAbandoned));
        public static readonly EventId RunFailed = new(1005, nameof(RunFailed));
    }
}
