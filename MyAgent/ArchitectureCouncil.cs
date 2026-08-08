using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Hosting;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;

namespace MyAgent;

/// <summary>
/// A multi-agent workflow: two opinionated advocates debate an architecture decision and a
/// principal architect rules on it, wired together as a round-robin group chat.
/// </summary>
public static class ArchitectureCouncil
{
    /// <summary>Name of the workflow, and the DI key it is registered under.</summary>
    public const string WorkflowName = "architecture_council";

    public const string CloudAdvocateName = "cloud_native_advocate";
    public const string OpenSourcePuristName = "open_source_purist";
    public const string PrincipalArchitectName = "principal_architect";

    /// <summary>Emitted by the <c>format_adr</c> tool, so its output is traceable in the transcript.</summary>
    public const string AdrMarker = "ADR-0042";

    /// <summary>One turn per participant: advocate, purist, architect.</summary>
    public const int MaximumIterationCount = 3;

    /// <summary>
    /// Registers the council workflow under <see cref="WorkflowName"/>. DevUI discovers keyed
    /// <see cref="Workflow"/> registrations and wraps them as agents on demand, so this single
    /// call is enough for the workflow to show up and be runnable there.
    /// </summary>
    public static IHostedWorkflowBuilder AddArchitectureCouncil(this IHostApplicationBuilder builder) =>
        builder.AddWorkflow(WorkflowName, (sp, key) =>
            Create(Factory.OpenAI(sp.GetRequiredService<IConfiguration>(), sp), name: key));

    /// <summary>
    /// Builds the council workflow. Each participant gets its own tool, so tool calling happens
    /// inside the workflow's executors rather than in the caller.
    /// </summary>
    public static Workflow Create(IChatClient chatClient, string name = WorkflowName)
    {
        AIAgent cloudAdvocate = chatClient.AsAIAgent(
            name: CloudAdvocateName,
            description: "Argues for cloud-managed PaaS services.",
            instructions: """
                You are a cloud-native advocate on an architecture review council.
                You strongly prefer managed PaaS services to reduce operational overhead.
                Always call the get_cloud_architect_role tool first, then state your position.
                Keep your position under 80 words.
                """,
            tools: [
                AIFunctionFactory.Create(
                    method: () => "Cloud architect: optimise for managed services, elastic scale and low ops burden.",
                    name: "get_cloud_architect_role",
                    description: "Get the charter of the cloud architect role.")
            ]);

        AIAgent openSourcePurist = chatClient.AsAIAgent(
            name: OpenSourcePuristName,
            description: "Argues for self-hosted, vendor-agnostic tooling.",
            instructions: """
                You are an open-source purist on an architecture review council.
                You strongly prefer self-hosted, cloud-agnostic tools for cost control and portability.
                Always call the get_software_architect_role tool first, then rebut the previous speaker.
                Keep your rebuttal under 80 words.
                """,
            tools: [
                AIFunctionFactory.Create(
                    method: () => "Software architect: optimise for portability, total cost of ownership and no vendor lock-in.",
                    name: "get_software_architect_role",
                    description: "Get the charter of the software architect role.")
            ]);

        AIAgent principalArchitect = chatClient.AsAIAgent(
            name: PrincipalArchitectName,
            description: "Observes the debate and issues the final ruling.",
            instructions: """
                You are the principal architect on an architecture review council.
                You observed the debate between the cloud-native advocate and the open-source purist.
                Synthesize their tradeoffs and make a final ruling.
                You MUST call the format_adr tool exactly once with your ruling, and then reply with the
                text it returns verbatim and nothing else.
                """,
            tools: [
                AIFunctionFactory.Create(
                    method: (string decision, string rationale) => $"""
                        {AdrMarker}: {decision}
                        Status: Accepted
                        Rationale: {rationale}
                        """,
                    name: "format_adr",
                    description: "Format the final ruling as an architecture decision record.")
            ]);

        // Round-robin: advocate -> purist -> architect. MaximumIterationCount caps the debate at
        // one turn per participant, so the architect's ruling terminates the chat.
        return AgentWorkflowBuilder
            .CreateGroupChatBuilderWith(agents => new RoundRobinGroupChatManager(agents)
            {
                MaximumIterationCount = MaximumIterationCount
            })
            .AddParticipants(cloudAdvocate, openSourcePurist, principalArchitect)
            .WithName(name)
            .WithDescription("Two advocates debate an architecture decision, the principal architect rules.")
            .Build();
    }
}
