using System.Runtime.CompilerServices;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;

namespace MyAgent;

/// <summary>
/// A council participant that caucuses with a private team before it speaks: the team drafts
/// positions concurrently, the participant is briefed with them, and only the participant's own
/// answer is said out loud. The group chat hears one voice per participant, not one per draft.
/// </summary>
/// <remarks>
/// <para>
/// The deliberation is hidden from the debate, not from the reader. Each draft is emitted as
/// <see cref="TextReasoningContent"/>, which AG-UI maps to REASONING_* events — so a client sees
/// every draft — while the group chat host strips reasoning from the messages it broadcasts to the
/// other participants, so none of it reaches another panelist's context. That asymmetry is the
/// whole design; it is what <c>ArchitectureCouncilCaucusTests</c> exists to hold in place.
/// </para>
/// <para>
/// Nesting the team as a workflow participant instead would do the opposite of what is wanted: the
/// members' turns become the participant's response, so every draft lands in the shared history
/// under the member's own name and the participant is never heard from at all.
/// </para>
/// <para>
/// Both run paths caucus. Overriding only the streaming one is a silent failure — the group chat
/// streams, so a run through the council looks perfect while every non-streaming caller (DevUI
/// among them) quietly skips the team and gets an unbriefed answer.
/// </para>
/// <para>
/// The briefing is an input to the spokesperson, so it settles in that participant's own session
/// rather than in the shared history. Harmless while each participant speaks once
/// (<see cref="ArchitectureCouncil.MaximumIterationCount"/>); a longer debate would accumulate one
/// briefing per turn there.
/// </para>
/// </remarks>
public sealed class CaucusAgent : DelegatingAIAgent
{
    /// <summary>Appended to the participant's name to name its caucus workflow.</summary>
    public const string CaucusSuffix = "_caucus";

    /// <summary>
    /// Opens the briefing. Public because it is the line that separates a participant being handed
    /// its own team's drafts from one being handed somebody else's — which is the difference a test
    /// has to be able to see.
    /// </summary>
    public const string BriefingIntro = "Your team drafted these in private:";

    readonly AIAgent _spokesperson;
    readonly AIAgent[] _team;
    readonly string _caucusName;

    /// <param name="spokesperson">The participant the council knows. It alone is heard in the debate.</param>
    /// <param name="team">Its private team. Every member drafts on the same input, concurrently.</param>
    public CaucusAgent(AIAgent spokesperson, params AIAgent[] team) : base(spokesperson)
    {
        ArgumentNullException.ThrowIfNull(spokesperson);
        ArgumentNullException.ThrowIfNull(team);

        if (team.Length == 0)
        {
            throw new ArgumentException("A caucus needs at least one team member.", nameof(team));
        }

        _spokesperson = spokesperson;
        _team = team;
        _caucusName = $"{spokesperson.Name}{CaucusSuffix}";
    }

    // The wrapper has to answer for its spokesperson wherever the framework asks who a participant
    // is: a group chat deduplicates participants by agent id, and a workflow node's id is
    // "<agent name>_<agent id>". Left to the base defaults this would report no name and a fresh
    // GUID per resolution — exactly the graph instability ArchitectureCouncil pins its ids to avoid.
    protected override string? IdCore => _spokesperson.Id;

    /// <inheritdoc />
    public override string? Name => _spokesperson.Name;

    /// <inheritdoc />
    public override string? Description => _spokesperson.Description;

    /// <inheritdoc />
    protected override async Task<AgentResponse> RunCoreAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        CancellationToken cancellationToken)
    {
        // Materialized once: the caucus reads the conversation twice — once for the team, once to
        // brief the spokesperson — and the caller is free to hand over a sequence that is lazy.
        ChatMessage[] input = [.. messages];

        IReadOnlyList<ChatMessage> drafts = await DeliberateAsync(input, cancellationToken);

        AgentResponse response = await base.RunCoreAsync(Brief(input, drafts), session, options, cancellationToken);

        // The same shape the streaming path produces: the deliberation leads, as reasoning, and the
        // position follows. A caller that renders one and not the other then behaves the same way
        // whichever path it took.
        response.Messages.Insert(0, new ChatMessage(ChatRole.Assistant, [.. Deliberation(drafts)])
        {
            AuthorName = Name,
        });

        return response;
    }

    /// <inheritdoc />
    protected override async IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ChatMessage[] input = [.. messages];

        IReadOnlyList<ChatMessage> drafts = await DeliberateAsync(input, cancellationToken);

        // One update per draft rather than one for the lot: they arrive as separate deltas of a
        // single reasoning message, which is what lets a view reveal them as they land.
        foreach (TextReasoningContent draft in Deliberation(drafts))
        {
            yield return new AgentResponseUpdate(ChatRole.Assistant, [draft])
            {
                AuthorName = Name,
            };
        }

        await foreach (AgentResponseUpdate update in
                       base.RunCoreStreamingAsync(Brief(input, drafts), session, options, cancellationToken))
        {
            yield return update;
        }
    }

    /// <summary>Runs the team and returns what each member drafted, in the order they replied.</summary>
    async Task<IReadOnlyList<ChatMessage>> DeliberateAsync(
        IReadOnlyList<ChatMessage> messages,
        CancellationToken cancellationToken)
    {
        // Built per run: a Workflow is taken into exclusive ownership by whoever runs it, and one
        // CaucusAgent is shared by every run of the council it belongs to.
        Workflow caucus = AgentWorkflowBuilder.BuildConcurrent(_caucusName, _team, aggregator: null);

        AgentResponse drafted = await caucus
            .AsAIAgent(
                id: _caucusName,
                name: _caucusName,
                description: $"The private team behind {Name}.",
                executionEnvironment: InProcessExecution.OffThread,
                includeExceptionDetails: true,
                includeWorkflowOutputsInResponse: false)
            .RunAsync(WithoutToolTraffic(messages), cancellationToken: cancellationToken);

        // A member that fails reports it as content instead of throwing, and the aggregate reads as
        // a successful run one draft short. Briefing the spokesperson with that produces a confident
        // position built on half a team — the one outcome a caucus must never quietly produce.
        if (drafted.Messages.SelectMany(message => message.Contents).OfType<ErrorContent>().FirstOrDefault() is { } error)
        {
            throw new InvalidOperationException($"The {Name} caucus failed: {error.Message}");
        }

        ChatMessage[] drafts = [.. drafted.Messages.Where(message => !string.IsNullOrWhiteSpace(message.Text))];

        return drafts.Length > 0
            ? drafts
            : throw new InvalidOperationException($"The {Name} caucus produced no drafts.");
    }

    /// <summary>
    /// The conversation as the team is shown it, with the tool traffic taken out.
    /// </summary>
    /// <remarks>
    /// A participant's tools are its own — its team drafts prose and is given none — but the group
    /// chat broadcasts a speaker's whole response, tool calls and results included. Bedrock refuses
    /// a request that carries tool blocks with no tool configuration to match them, so from the
    /// first participant that calls a tool, every caucus downstream of it fails outright. This is
    /// the fix for that, and it is what the framework's own handoffs do for the same reason
    /// (<see cref="HandoffToolCallFilteringBehavior"/>). It also spares a drafter the transcript of
    /// somebody else fetching a role charter, which was never going to change what it drafted.
    /// </remarks>
    static IEnumerable<ChatMessage> WithoutToolTraffic(IEnumerable<ChatMessage> messages)
    {
        foreach (ChatMessage message in messages)
        {
            AIContent[] kept = [.. message.Contents.Where(content => content is not (FunctionCallContent or FunctionResultContent))];

            // A tool result carries nothing else, and an empty message is itself rejected. Rebuilt
            // rather than edited in place: these belong to the caller's session, not to the caucus.
            if (kept.Length == 0)
            {
                continue;
            }

            yield return new ChatMessage(message.Role, kept)
            {
                AuthorName = message.AuthorName,
                MessageId = message.MessageId,
                AdditionalProperties = message.AdditionalProperties,
            };
        }
    }

    /// <summary>
    /// The drafts as the spokesperson is asked to use them. A user message rather than an
    /// instruction: the participant's own instructions are what make it that participant, and
    /// replacing them to deliver a briefing would replace its stance along with them.
    /// </summary>
    static IEnumerable<ChatMessage> Brief(IEnumerable<ChatMessage> messages, IReadOnlyList<ChatMessage> drafts) =>
    [
        .. messages,
        new ChatMessage(ChatRole.User, $"""
            {BriefingIntro}

            {string.Join("\n\n", drafts.Select(draft => $"{draft.AuthorName ?? "team"}: {draft.Text}"))}

            Take the strongest of them, merging where they agree, and answer as yourself.
            Do not mention the team or this briefing.
            """),
    ];

    /// <summary>
    /// The drafts as reasoning, each carrying its author. The name matters: a reader looking at a
    /// deliberation is looking at several drafts at once, and reasoning events carry no author of
    /// their own for a view to label them with. So does the blank line between them — these are
    /// deltas of one reasoning message, so whatever separates them here is all that separates them
    /// on screen.
    /// </summary>
    static IEnumerable<TextReasoningContent> Deliberation(IReadOnlyList<ChatMessage> drafts) =>
        drafts.Select((draft, index) =>
            new TextReasoningContent($"{(index == 0 ? "" : "\n\n")}{draft.AuthorName ?? "team"}: {draft.Text}"));
}
