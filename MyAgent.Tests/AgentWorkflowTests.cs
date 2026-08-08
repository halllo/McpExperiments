using System.Text;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

/// <summary>
/// Exercises <see cref="ArchitectureCouncil"/> — the multi-agent workflow hosted by the MyAgent
/// project — resolved from DI exactly as DevUI resolves it.
/// </summary>
[TestClass]
public sealed class AgentWorkflowTests
{
    [TestMethod]
    [Timeout(300_000)]
    public async Task ArchitectureCouncil_RoundRobinGroupChat_DebatesAndRulesWithFormattedAdr()
    {
        var host = Program.BuildWorkflowHost();

        // Resolved by DI key, the way DevUI picks up a registered workflow.
        Workflow workflow = host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName);
        Assert.AreEqual(ArchitectureCouncil.WorkflowName, workflow.Name, "The registered workflow should carry its DI key as its name.");

        List<ChatMessage> input = [
            new(ChatRole.User,
                "Should our new event-processing service run on a managed cloud queue or on self-hosted Kafka?")
        ];

        // --- Run ----------------------------------------------------------------------------

        List<string> speakingOrder = [];
        List<ChatMessage> transcript = [];
        StringBuilder streamed = new();

        await using StreamingRun run = await InProcessExecution.RunStreamingAsync(workflow, input);
        await run.TrySendMessageAsync(new TurnToken(emitEvents: true));

        await foreach (WorkflowEvent evt in run.WatchStreamAsync())
        {
            // NOTE: AgentResponseUpdateEvent derives from WorkflowOutputEvent — the per-token agent
            // updates and the workflow's final output arrive on the same stream, so the specific
            // event types have to be matched before the general one.
            if (evt is AgentResponseUpdateEvent update)
            {
                if (speakingOrder.Count == 0 || speakingOrder[^1] != update.ExecutorId)
                {
                    speakingOrder.Add(update.ExecutorId);
                }
                streamed.Append(update.Update.Text);
                continue;
            }

            if (evt is ExecutorFailedEvent failed)
            {
                Assert.Fail($"Executor '{failed.ExecutorId}' failed: {failed.Data}");
            }

            if (evt is WorkflowErrorEvent error)
            {
                Assert.Fail($"Workflow failed: {error.Exception}");
            }

            // The group chat yields its canonical conversation when the manager terminates the debate.
            if (evt is WorkflowOutputEvent output && output.As<List<ChatMessage>>() is { } messages)
            {
                transcript = messages;
                break;
            }
        }

        foreach (var message in transcript)
        {
            Console.WriteLine($"[{message.Role}] {message.AuthorName}: {message.Text}");
        }

        // --- Assertions ---------------------------------------------------------------------

        string[] expectedOrder = [
            ArchitectureCouncil.CloudAdvocateName,
            ArchitectureCouncil.OpenSourcePuristName,
            ArchitectureCouncil.PrincipalArchitectName
        ];

        // The workflow completed and yielded its canonical conversation, starting with the question.
        Assert.AreEqual(1, transcript.Count(m => m.Role == ChatRole.User), "Expected the original user question in the transcript.");

        // Round-robin: each participant holds the floor for exactly one contiguous turn, in
        // participant order. A turn spans several messages (the function call, the tool result
        // and the spoken text), so collapse consecutive messages by the same author.
        List<string> turnOrder = [];
        foreach (var message in transcript.Where(m => m.Role != ChatRole.User && m.AuthorName is not null))
        {
            if (turnOrder.Count == 0 || turnOrder[^1] != message.AuthorName)
            {
                turnOrder.Add(message.AuthorName!);
            }
        }

        CollectionAssert.AreEqual(expectedOrder, turnOrder,
            $"Expected one round-robin turn per participant (MaximumIterationCount = {ArchitectureCouncil.MaximumIterationCount}), got: {string.Join(" -> ", turnOrder)}");

        // Every participant actually said something.
        foreach (var participant in expectedOrder)
        {
            Assert.IsTrue(
                transcript.Any(m => m.Role == ChatRole.Assistant && m.AuthorName == participant && !string.IsNullOrWhiteSpace(m.Text)),
                $"Expected '{participant}' to contribute a non-empty message.");
        }

        // The same order is observable on the live event stream (executor ids are "<name>_<agentId>").
        Assert.AreEqual(3, speakingOrder.Count, $"Expected three streamed turns, got: {string.Join(" -> ", speakingOrder)}");
        for (int i = 0; i < expectedOrder.Length; i++)
        {
            Assert.IsTrue(speakingOrder[i].StartsWith(expectedOrder[i], StringComparison.Ordinal),
                $"Expected streamed turn {i} to come from '{expectedOrder[i]}', got '{speakingOrder[i]}'.");
        }
        Assert.IsTrue(streamed.Length > 0, "Expected streaming updates to carry text.");

        // Each participant reached its own tools through the workflow's executors.
        var calledFunctions = transcript
            .SelectMany(m => m.Contents.OfType<FunctionCallContent>())
            .Select(c => c.Name)
            .ToList();
        CollectionAssert.AreEquivalent(
            new[] { "get_cloud_architect_role", "get_software_architect_role", "format_adr" },
            calledFunctions,
            $"Unexpected tool calls in the transcript: {string.Join(", ", calledFunctions)}");

        // The ruling is the architect's last word and carries the ADR produced by its tool.
        var ruling = transcript.Last(m => m.Role == ChatRole.Assistant && !string.IsNullOrWhiteSpace(m.Text));
        Assert.AreEqual(ArchitectureCouncil.PrincipalArchitectName, ruling.AuthorName, "Expected the principal architect to have the last word.");
        Assert.IsTrue(ruling.Text.Contains(ArchitectureCouncil.AdrMarker, StringComparison.Ordinal),
            $"Expected the final ruling to contain the formatted ADR ({ArchitectureCouncil.AdrMarker}), got: {ruling.Text}");
    }
}
