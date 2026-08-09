using AGUI.Abstractions;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using static MyAgent.Tests.CouncilStubs;

namespace MyAgent.Tests;

/// <summary>
/// Covers the one asymmetry <see cref="CaucusAgent"/> exists for: a participant's private team is
/// visible to whoever is watching the run, and invisible to everyone else at the table. Both halves
/// are load-bearing — a caucus nobody can see is a black box, and a caucus the other participants
/// can see is just a louder debate.
/// </summary>
[TestClass]
[TestCategory("Offline")]
public sealed class ArchitectureCouncilCaucusTests
{
    const int TopicLimit = 500;

    /// <summary>Three participants, each with two team members, each speaking once.</summary>
    const int CallsPerRun = 9;

    /// <summary>The private team behind each participant, by the name the council knows it under.</summary>
    static readonly Dictionary<string, string[]> Teams = new()
    {
        [ArchitectureCouncil.CloudAdvocateName] =
            [ArchitectureCouncil.CloudOperationsAnalystName, ArchitectureCouncil.CloudDeliveryAnalystName],
        [ArchitectureCouncil.OpenSourcePuristName] =
            [ArchitectureCouncil.PortabilityAnalystName, ArchitectureCouncil.CostOfOwnershipAnalystName],
        [ArchitectureCouncil.PrincipalArchitectName] =
            [ArchitectureCouncil.TradeoffAnalystName, ArchitectureCouncil.RiskAnalystName],
    };

    // --- what the client sees ---------------------------------------------------------------

    [TestMethod]
    [Timeout(60_000)]
    public async Task EveryDraft_ReachesTheClient_AsReasoning()
    {
        var chat = new StubChatClient();

        var events = await Collect(chat);

        var deliberation = string.Concat(events.OfType<ReasoningMessageContentEvent>().Select(evt => evt.Delta));

        foreach (var member in ArchitectureCouncil.TeamMemberNames)
        {
            StringAssert.Contains(deliberation, member,
                $"'{member}' drafted a position that never reached the client: {deliberation}");
        }
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task NoDraft_ReachesTheClient_AsSpeech()
    {
        var chat = new StubChatClient();

        var events = await Collect(chat);

        // Reasoning is what the group chat strips on its way to the other participants. A draft that
        // arrived as TEXT_MESSAGE_CONTENT instead would be rendered as a position and broadcast as
        // one — the same leak, arriving through the door nobody is watching.
        var spoken = string.Concat(events.OfType<TextMessageContentEvent>().Select(evt => evt.Delta));

        foreach (var member in ArchitectureCouncil.TeamMemberNames)
        {
            Assert.IsFalse(spoken.Contains(member, StringComparison.Ordinal),
                $"'{member}' was quoted in the debate itself: {spoken}");
        }
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task EveryVoiceOnTheWire_IsAParticipant()
    {
        var chat = new StubChatClient();

        var events = await Collect(chat);

        string[] spoke = [.. events.OfType<TextMessageStartEvent>()
            .Select(evt => evt.Name ?? "")
            .Where(name => name.Length > 0)
            .Distinct()];

        CollectionAssert.AreEquivalent(
            new[]
            {
                ArchitectureCouncil.CloudAdvocateName,
                ArchitectureCouncil.OpenSourcePuristName,
                ArchitectureCouncil.PrincipalArchitectName,
            },
            spoke,
            $"The council heard: [{string.Join(", ", spoke)}]");
    }

    // --- what the other participants see ------------------------------------------------------

    [TestMethod]
    [Timeout(60_000)]
    public async Task NoParticipant_IsBriefedWithAnotherParticipantsCaucus()
    {
        var chat = new StubChatClient();

        await Collect(chat);

        // Drafts are attributed to the member who wrote them, so a member's name in a request is the
        // tell that its caucus was shown to whoever was asked. Exactly one place may show it: the
        // briefing a participant gets from its own team. Anywhere else — an instruction, a broadcast
        // position, another participant's briefing — and the caucus has leaked into the debate.
        foreach (var request in chat.Requests)
        {
            foreach (var message in request.Messages)
            {
                var briefing = message.Role == ChatRole.User
                    && message.Text.Contains(CaucusAgent.BriefingIntro, StringComparison.Ordinal);

                string[] named = [.. ArchitectureCouncil.TeamMemberNames.Where(member => message.Text.Contains(member, StringComparison.Ordinal))];

                if (named.Length == 0)
                {
                    continue;
                }

                Assert.IsTrue(briefing,
                    $"[{string.Join(", ", named)}] turned up in a {message.Role} message that is not a briefing: {message.Text}");

                string[] teams = [.. Teams.Where(team => team.Value.Intersect(named).Any()).Select(team => team.Key)];

                Assert.AreEqual(1, teams.Length,
                    $"One briefing carried the drafts of [{string.Join(", ", teams)}]: {message.Text}");
            }
        }
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task ThePrincipalArchitect_HearsThePositions_AndOnlyItsOwnCaucus()
    {
        var chat = new StubChatClient();

        await Collect(chat);

        // The last call of a run is the architect stating its ruling: the participant furthest
        // downstream, and so the one with the most chances to have been handed something private.
        var ruling = string.Join("\n", chat.Requests[^1].Messages.Select(message => message.Text));

        foreach (var member in Teams[ArchitectureCouncil.PrincipalArchitectName])
        {
            StringAssert.Contains(ruling, member,
                $"The architect ruled without its own team's drafts, so no caucus happened: {ruling}");
        }

        foreach (var member in Teams[ArchitectureCouncil.CloudAdvocateName].Concat(Teams[ArchitectureCouncil.OpenSourcePuristName]))
        {
            Assert.IsFalse(ruling.Contains(member, StringComparison.Ordinal),
                $"The architect was shown '{member}', who caucused for someone else: {ruling}");
        }
    }

    // --- the caucus itself ----------------------------------------------------------------------

    [TestMethod]
    [Timeout(30_000)]
    public async Task TheNonStreamingPath_CaucusesToo()
    {
        var chat = new StubChatClient();
        var caucus = new CaucusAgent(
            Agent(chat, "spokesperson"),
            Agent(chat, "first_member"),
            Agent(chat, "second_member"));

        // The group chat streams, so this path has no cover in a council run: overriding only the
        // streaming one leaves every other caller — DevUI included — with an unbriefed answer and
        // no sign that anything was skipped.
        AgentResponse response = await caucus.RunAsync([new ChatMessage(ChatRole.User, "a topic")]);

        Assert.AreEqual(3, chat.Calls, "Two members and their spokesperson is three calls.");

        var deliberation = string.Concat(response.Messages
            .SelectMany(message => message.Contents)
            .OfType<TextReasoningContent>()
            .Select(content => content.Text));

        StringAssert.Contains(deliberation, "first_member");
        StringAssert.Contains(deliberation, "second_member");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task NoDrafterIsShownToolTraffic_ItHasNoToolsToBeAskedAbout()
    {
        // The group chat broadcasts a speaker's whole response, tool calls and results included, and
        // a drafter is given no tools of its own. Bedrock refuses that combination outright, so this
        // is not a matter of taste: before it was fixed, the first participant to call a tool failed
        // every caucus after it, and the council returned a ruling from a debate of one.
        var chat = new StubChatClient { WithToolCall = true };

        await Collect(chat);

        foreach (var (request, index) in chat.Requests.Select((request, index) => (request, index)))
        {
            var traffic = request.Messages
                .SelectMany(message => message.Contents)
                .Any(content => content is FunctionCallContent or FunctionResultContent);

            Assert.IsFalse(traffic && request.ToolCount == 0,
                $"Call #{index + 1} carried tool calls or results while declaring no tools.");
        }
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task ADrafterSeesThePositions_WithoutTheToolCallsBehindThem()
    {
        var chat = new StubChatClient();
        var caucus = new CaucusAgent(Agent(chat, "spokesperson"), Agent(chat, "member"));

        await caucus.RunAsync([
            new ChatMessage(ChatRole.User, "a topic"),
            new ChatMessage(ChatRole.Assistant, [
                new TextContent("Let me check."),
                new FunctionCallContent("c1", "get_role", new Dictionary<string, object?>()),
            ]),
            new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", "the charter")]),
            new ChatMessage(ChatRole.Assistant, [new TextContent("Managed queues, then.")]),
        ]);

        // The team runs first, the spokesperson last.
        var drafter = chat.Requests[0].Messages;
        var spokesperson = chat.Requests[^1].Messages;

        Assert.IsFalse(drafter.SelectMany(message => message.Contents).Any(content => content is FunctionCallContent or FunctionResultContent),
            "A drafter was shown tool traffic it has no tools to account for.");

        // What was said is still there — only the plumbing behind it was dropped.
        StringAssert.Contains(string.Join("\n", drafter.Select(message => message.Text)), "Managed queues, then.");

        Assert.IsTrue(spokesperson.SelectMany(message => message.Contents).Any(content => content is FunctionCallContent),
            "The participant kept its tools, so the debate it sees is unchanged.");
    }

    [TestMethod]
    [Timeout(30_000)]
    public void ACaucusWithNoTeam_IsRefusedAtConstruction()
    {
        var chat = new StubChatClient();

        // Otherwise it is a participant that reports a caucus it never held.
        Assert.ThrowsExactly<ArgumentException>(() => new CaucusAgent(Agent(chat, "spokesperson")));
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task AMemberThatFails_FailsTheRun_RatherThanBriefingHalfATeam()
    {
        const string secret = "Password=hunter2";

        // The first call of a run is a team member, and it reports its failure as content rather
        // than throwing — so the caucus reads as a successful run one draft short. Left unchecked,
        // the council rules confidently on the strength of half a team.
        var chat = new StubChatClient { ErrorWith = secret, ErrorOnCall = 1 };
        var log = new CapturingLogger();

        var events = await Collect(chat, log);

        Assert.IsInstanceOfType<RunErrorEvent>(events[^1],
            $"A caucus that lost a member still produced a verdict: {string.Join(", ", events.Select(evt => evt.Type))}");
        Assert.AreEqual(WorkflowAguiStream.RunFailedCode, (events[^1] as RunErrorEvent)?.Code);

        foreach (var evt in events)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(evt, evt.GetType(), WorkflowAguiStream.Json);
            Assert.IsFalse(json.Contains(secret, StringComparison.OrdinalIgnoreCase),
                $"The failure's detail reached the wire: {json}");
        }

        StringAssert.Contains(log.All, "reference", "A failed run is only traceable through its reference.");
    }

    [TestMethod]
    [Timeout(60_000)]
    public async Task ARunCosts_OneCallPerTeamMember_PlusOnePerParticipant()
    {
        var chat = new StubChatClient();

        await Collect(chat);

        // Not an implementation detail: the same debate without caucuses costs three calls, and a
        // team is the one change here that multiplies the bill rather than adding to it.
        Assert.AreEqual(CallsPerRun, chat.Calls,
            "A caucusing council costs participants × (team + 1) model calls; that number changed.");
    }

    // --- helpers -----------------------------------------------------------------------------

    static AIAgent Agent(StubChatClient chat, string name) =>
        chat.AsAIAgent(name: name, description: name, instructions: "draft");

    /// <summary>The real council, run against a stub, as a client of the AG-UI stream sees it.</summary>
    static async Task<List<BaseEvent>> Collect(StubChatClient chat, ILogger? logger = null)
    {
        List<BaseEvent> events = [];

        await foreach (var evt in WorkflowAguiStream.RunAsync(
            ArchitectureCouncil.Create(chat),
            Context("a topic"),
            TopicLimit,
            logger ?? NullLogger.Instance,
            "test-reference",
            CancellationToken.None))
        {
            events.Add(evt);
        }

        AguiConformance.Assert(events);
        return events;
    }
}
