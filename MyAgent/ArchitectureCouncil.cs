using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;

namespace MyAgent;

/// <summary>
/// A multi-agent workflow: two opinionated advocates debate an architecture decision and a
/// principal architect rules on it, wired together as a round-robin group chat. Each of the three
/// caucuses with a private team before it speaks — see <see cref="CaucusAgent"/>.
/// </summary>
public static class ArchitectureCouncil
{
    /// <summary>Name of the workflow, and the DI key it is registered under.</summary>
    public const string WorkflowName = "architecture_council";

    public const string CloudAdvocateName = "cloud_native_advocate";
    public const string OpenSourcePuristName = "open_source_purist";
    public const string PrincipalArchitectName = "principal_architect";

    // A participant's private team. These names are never a speaker on the wire — the whole point
    // of a caucus is that the council hears the participant, not its team — but they do label the
    // drafts inside the deliberation, so they are written to be read.
    public const string CloudOperationsAnalystName = "cloud_operations_analyst";
    public const string CloudDeliveryAnalystName = "cloud_delivery_analyst";
    public const string PortabilityAnalystName = "portability_analyst";
    public const string CostOfOwnershipAnalystName = "cost_of_ownership_analyst";
    public const string TradeoffAnalystName = "tradeoff_analyst";
    public const string RiskAnalystName = "risk_analyst";

    /// <summary>Every private team member. Nothing they draft is ever attributed on the wire.</summary>
    public static readonly string[] TeamMemberNames = [
        CloudOperationsAnalystName,
        CloudDeliveryAnalystName,
        PortabilityAnalystName,
        CostOfOwnershipAnalystName,
        TradeoffAnalystName,
        RiskAnalystName,
    ];

    // A participant's executor id in the workflow graph is "<agent name>_<agent id>", and an
    // AIAgent's id defaults to a fresh GUID. Left to default, every resolution of this (transient)
    // registration would produce different node ids, and DevUI — which draws the graph from one
    // instance and runs another — could no longer tell which node an event belongs to, leaving the
    // highlight stuck on GroupChatHost, whose id is a constant. Pinning the ids keeps the graph
    // identical across resolutions. They must stay distinct from one another: the group chat
    // deduplicates its participants by agent id.
    const string CloudAdvocateId = "advocate";
    const string OpenSourcePuristId = "purist";
    const string PrincipalArchitectId = "architect";

    /// <summary>Emitted by the <c>format_adr</c> tool, so its output is traceable in the transcript.</summary>
    public const string AdrMarker = "ADR-0042";

    /// <summary>
    /// One turn per participant: advocate, purist, architect. A turn is a caucus rather than a
    /// single call, so a run costs <c>participants × (team members + 1)</c> model calls — nine here,
    /// where the same debate without teams costs three.
    /// </summary>
    public const int MaximumIterationCount = 3;

    /// <summary>The council's name as a reader sees it, shown by the web view.</summary>
    public const string DisplayName = "Architecture Council";

    /// <summary>What the council is, shown by the web view and by DevUI.</summary>
    public const string Description = "Two advocates debate an architecture decision, each briefed in private by its own team; the principal architect rules.";

    /// <summary>What to ask for — the web view shows this rather than inventing its own copy.</summary>
    public const string Prompt = "Which architecture decision should the council rule on?";

    /// <summary>Example topics offered by the web view.</summary>
    public static readonly string[] Samples = [
        "Should our new event-processing service run on a managed cloud queue or on self-hosted Kafka?",
        "Postgres on RDS or a self-managed cluster?",
        "Buy an observability SaaS or run OpenTelemetry ourselves?",
    ];

    /// <summary>
    /// Registers the council workflow under <see cref="WorkflowName"/>. DevUI discovers keyed
    /// <see cref="Workflow"/> registrations and wraps them as agents on demand, so this single
    /// call is enough for the workflow to show up and be runnable there.
    /// </summary>
    /// <remarks>
    /// The workflow is transient — building it is cheap and I/O-free — so a run never shares an
    /// instance with another caller. A <see cref="Workflow"/> is taken into exclusive ownership by
    /// whoever runs it, and DevUI's agent wrapper holds one for its own runs.
    /// The chat client behind it is a singleton, so the connection pool is still shared.
    /// </remarks>
    public static IHostedWorkflowBuilder AddArchitectureCouncil(this IHostApplicationBuilder builder)
    {
        builder.Services.AddKeyedSingleton<IChatClient>(WorkflowName, (sp, _) =>
            Factory.AmazonBedrock(sp.GetRequiredService<IConfiguration>(), sp));

        return builder.AddWorkflow(
            WorkflowName,
            (sp, key) => Create(sp.GetRequiredKeyedService<IChatClient>(WorkflowName), name: key),
            ServiceLifetime.Transient);
    }

    /// <summary>
    /// Builds the council workflow. Each participant gets its own tool, so tool calling happens
    /// inside the workflow's executors rather than in the caller, and its own team, so the position
    /// it argues is the best of several rather than its first thought.
    /// </summary>
    public static Workflow Create(IChatClient chatClient, string name = WorkflowName)
    {
        AIAgent cloudAdvocate = chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Id = CloudAdvocateId,
            Name = CloudAdvocateName,
            Description = "Argues for cloud-managed PaaS services.",
            ChatOptions = new ChatOptions
            {
                Instructions = """
                    You are a cloud-native advocate on an architecture review council.
                    You strongly prefer managed PaaS services to reduce operational overhead.
                    Always call the get_cloud_architect_role tool first, then state your position.
                    Keep your position under 80 words.
                    """,
                Tools = [
                    AIFunctionFactory.Create(
                        method: () => "Cloud architect: optimise for managed services, elastic scale and low ops burden.",
                        name: "get_cloud_architect_role",
                        description: "Get the charter of the cloud architect role.")
                ],
            },
        });

        AIAgent openSourcePurist = chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Id = OpenSourcePuristId,
            Name = OpenSourcePuristName,
            Description = "Argues for self-hosted, vendor-agnostic tooling.",
            ChatOptions = new ChatOptions
            {
                Instructions = """
                    You are an open-source purist on an architecture review council.
                    You strongly prefer self-hosted, cloud-agnostic tools for cost control and portability.
                    Always call the get_software_architect_role tool first, then rebut the previous speaker.
                    Keep your rebuttal under 80 words.
                    """,
                Tools = [
                    AIFunctionFactory.Create(
                        method: () => "Software architect: optimise for portability, total cost of ownership and no vendor lock-in.",
                        name: "get_software_architect_role",
                        description: "Get the charter of the software architect role.")
                ],
            },
        });

        AIAgent principalArchitect = chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Id = PrincipalArchitectId,
            Name = PrincipalArchitectName,
            Description = "Observes the debate and issues the final ruling.",
            ChatOptions = new ChatOptions
            {
                Instructions = """
                    You are the principal architect on an architecture review council.
                    You observed the debate between the cloud-native advocate and the open-source purist.
                    Synthesize their tradeoffs and make a final ruling.
                    You MUST call the format_adr tool exactly once with your ruling, and then reply with the
                    text it returns verbatim and nothing else.
                    """,
                Tools = [
                    AIFunctionFactory.Create(
                        method: (string decision, string rationale) => $"""
                            {AdrMarker}: {decision}
                            Status: Accepted
                            Rationale: {rationale}
                            """,
                        name: "format_adr",
                        description: "Format the final ruling as an architecture decision record.")
                ],
            },
        });

        // Round-robin: advocate -> purist -> architect. MaximumIterationCount caps the debate at
        // one turn per participant, so the architect's ruling terminates the chat. Each participant
        // enters the chat wrapped in its team: the group chat only ever sees the three of them.
        return AgentWorkflowBuilder
            .CreateGroupChatBuilderWith(agents => new RoundRobinGroupChatManager(agents)
            {
                MaximumIterationCount = MaximumIterationCount
            })
            .AddParticipants(
                new CaucusAgent(cloudAdvocate,
                    TeamMember(chatClient, CloudOperationsAnalystName, """
                        You draft for a cloud-native advocate on an architecture review council.
                        Make the case for managed PaaS from one angle only: the operational burden of
                        running it yourself — on-call, patching, upgrades, capacity.
                        Draft one position, under 60 words. Do not hedge and do not cover other angles.
                        """),
                    TeamMember(chatClient, CloudDeliveryAnalystName, """
                        You draft for a cloud-native advocate on an architecture review council.
                        Make the case for managed PaaS from one angle only: delivery speed — how much
                        sooner the team ships, and what it stops spending its attention on.
                        Draft one position, under 60 words. Do not hedge and do not cover other angles.
                        """)),
                new CaucusAgent(openSourcePurist,
                    TeamMember(chatClient, PortabilityAnalystName, """
                        You draft for an open-source purist on an architecture review council.
                        Make the case for self-hosted, cloud-agnostic tools from one angle only:
                        lock-in — what leaving the vendor would later cost.
                        Draft one position, under 60 words. Do not hedge and do not cover other angles.
                        """),
                    TeamMember(chatClient, CostOfOwnershipAnalystName, """
                        You draft for an open-source purist on an architecture review council.
                        Make the case for self-hosted, cloud-agnostic tools from one angle only: total
                        cost of ownership as usage grows.
                        Draft one position, under 60 words. Do not hedge and do not cover other angles.
                        """)),
                new CaucusAgent(principalArchitect,
                    TeamMember(chatClient, TradeoffAnalystName, """
                        You draft for the principal architect of an architecture review council, who
                        has heard a cloud-native advocate and an open-source purist argue.
                        Draft a ruling that turns on the single decisive tradeoff between them, and
                        name that tradeoff. Under 60 words. Decide; do not summarize.
                        """),
                    TeamMember(chatClient, RiskAnalystName, """
                        You draft for the principal architect of an architecture review council, who
                        has heard a cloud-native advocate and an open-source purist argue.
                        Draft a ruling that turns on the biggest risk either position carries, and say
                        how the ruling contains it. Under 60 words. Decide; do not summarize.
                        """)))
            .WithName(name)
            .WithDescription(Description)
            .Build();
    }

    /// <summary>
    /// One member of a participant's private team. Deliberately tool-free: the role tools are what
    /// a reader watches a participant reach for, and giving one to every drafter would report six
    /// tool calls for a turn in which the participant made one.
    /// </summary>
    static AIAgent TeamMember(IChatClient chatClient, string name, string instructions) =>
        chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            // Pinned for the same reason the participants' ids are, one level down: a member is a
            // node in its caucus workflow, whose id is "<agent name>_<agent id>".
            Id = name,
            Name = name,
            Description = $"Drafts positions for {name.Replace('_', ' ')}.",
            ChatOptions = new ChatOptions { Instructions = instructions },
        });
}
