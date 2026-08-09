using AGUI.Abstractions;
using AGUI.Server;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

/// <summary>
/// Exercises <see cref="ArchitectureCouncil"/> — the multi-agent workflow hosted by the MyAgent
/// project — resolved from DI exactly as DevUI resolves it, and streamed through the same
/// <see cref="WorkflowAguiStream"/> the web view consumes. One paid run therefore proves both that
/// the workflow debates and rules, and that the AG-UI event stream the browser reads is well formed.
/// </summary>
/// <remarks>
/// Only assertions that genuinely need a model live here. Everything about registration, graph
/// shape, protocol conformance and error handling is covered offline by
/// <see cref="ArchitectureCouncilWorkflowTests"/>, <see cref="WorkflowAguiStreamTests"/> and
/// <see cref="ArchitectureCouncilEndpointTests"/>.
/// </remarks>
[TestClass]
[TestCategory("Live")]   // makes real, paid model calls
public sealed class AgentWorkflowTests
{
    const string Topic = "Should our new event-processing service run on a managed cloud queue or on self-hosted Kafka?";

    [TestMethod]
    [Timeout(600_000)]
    public async Task ArchitectureCouncil_StreamedAsAgui_DebatesAndRulesWithFormattedAdr()
    {
        using var host = Program.BuildWorkflowHost();

        // Tracks whichever chat client AddArchitectureCouncil registers — Amazon Bedrock today.
        // All three keys, because a missing secret used to sail past this guard and then surface as
        // "the run failed", which reads like a product bug rather than a missing credential.
        var configuration = host.Services.GetRequiredService<IConfiguration>();
        foreach (var key in new[] { "AWSBedrockAccessKeyId", "AWSBedrockSecretAccessKey", "AWSBedrockRegion" })
        {
            if (string.IsNullOrWhiteSpace(configuration[key]))
            {
                Assert.Inconclusive($"{key} is not configured; skipping the live council run.");
            }
        }

        // Resolved by DI key, the way DevUI picks up a registered workflow.
        Workflow workflow = host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName);

        var input = new RunAgentInput
        {
            ThreadId = "test-thread",
            RunId = "test-run",
            Messages = [new AGUIUserMessage { Id = "u1", Content = Topic }],
            Tools = [],
        };

        var context = input.ToChatRequestContext(WorkflowAguiStream.Json, new AGUIStreamOptions());

        // --- Run, exactly as the endpoint runs it ------------------------------------------

        // A capturing logger, not a null one: when the provider rejects the call, its reason is the
        // one thing that makes a failure diagnosable, and the stream deliberately keeps it off the
        // wire. Every assertion below quotes it.
        var log = new CapturingLogger();

        List<BaseEvent> events = [];
        await foreach (BaseEvent evt in WorkflowAguiStream.RunAsync(
            workflow,
            context,
            maxTopicLength: 500,
            log,
            failureReference: "live-test",
            CancellationToken.None))
        {
            events.Add(evt);
        }

        Dump(events);

        // --- The protocol's own contract -----------------------------------------------------

        var started = events.FirstOrDefault() as RunStartedEvent;
        Assert.IsNotNull(started, $"An AG-UI run opens with RUN_STARTED; got {events.FirstOrDefault()?.Type}. {log.All}");
        Assert.AreEqual(input.ThreadId, started.ThreadId, "RUN_STARTED should echo the caller's thread id.");
        Assert.AreEqual(input.RunId, started.RunId, "RUN_STARTED should echo the caller's run id.");

        Assert.IsInstanceOfType<RunFinishedEvent>(events[^1],
            $"The run should have finished, not errored: {(events[^1] as RunErrorEvent)?.Message}\n{log.All}");

        AguiConformance.Assert(events);

        // --- What the browser renders --------------------------------------------------------

        // A tool-calling agent speaks twice per turn: a preamble that carries the tool call, then
        // its answer once the tool has returned. AG-UI reports both, because both are real
        // assistant messages; the page merges a run of them into one card, and so does this test.
        List<Turn> turns = TurnsOf(events);

        string[] expectedOrder = [
            ArchitectureCouncil.CloudAdvocateName,
            ArchitectureCouncil.OpenSourcePuristName,
            ArchitectureCouncil.PrincipalArchitectName,
        ];

        CollectionAssert.AreEqual(expectedOrder, turns.Select(t => t.Speaker).ToArray(),
            $"Expected one round-robin turn per participant, in order, got: {string.Join(" -> ", turns.Select(t => t.Speaker))}");

        foreach (Turn turn in turns)
        {
            Assert.IsTrue(turn.Text.Trim().Length > 0, $"Expected '{turn.Speaker}' to stream some text.");
        }

        // Each participant reached its own tools, and only its own — the tool call names a parent
        // message, which places it in exactly one turn.
        var expectedTools = new Dictionary<string, string>
        {
            [ArchitectureCouncil.CloudAdvocateName] = "get_cloud_architect_role",
            [ArchitectureCouncil.OpenSourcePuristName] = "get_software_architect_role",
            [ArchitectureCouncil.PrincipalArchitectName] = "format_adr",
        };

        foreach (ToolCallStartEvent call in events.OfType<ToolCallStartEvent>())
        {
            Turn? owner = turns.FirstOrDefault(t => t.MessageIds.Contains(call.ParentMessageId!));
            Assert.IsNotNull(owner,
                $"Tool call '{call.ToolCallName}' names parent message '{call.ParentMessageId}', which belongs to no turn, so the page cannot place it.");

            // TryGetValue, not an indexer: an unexpected speaker used to throw KeyNotFoundException
            // here, replacing a diagnosable assertion with a bare exception.
            Assert.IsTrue(expectedTools.TryGetValue(owner.Speaker, out var expected),
                $"'{owner.Speaker}' is not one of the council's participants, but it called '{call.ToolCallName}'.");
            Assert.AreEqual(expected, call.ToolCallName, $"'{owner.Speaker}' called a tool belonging to someone else.");
        }

        foreach (var (speaker, tool) in expectedTools)
        {
            Assert.IsTrue(events.OfType<ToolCallStartEvent>().Any(c => c.ToolCallName == tool),
                $"Expected {speaker} to call {tool}. Models do skip instructed tool calls, so a failure here may be the model rather than the code.");
        }

        // The ADR itself is the tool's output, which is deterministic — unlike whether the model
        // then echoes it verbatim, which it is instructed to do but does not reliably do.
        var adr = events.OfType<ToolCallResultEvent>()
            .Select(r => r.Content)
            .FirstOrDefault(content => content?.Contains(ArchitectureCouncil.AdrMarker) == true);

        Assert.IsNotNull(adr, $"Expected format_adr to have produced an ADR containing {ArchitectureCouncil.AdrMarker}.");
        StringAssert.Contains(adr, "Status: Accepted", "The formatted ADR should carry its status.");

        // Whatever the architect ended on is what the page shows as the result.
        Assert.IsTrue(turns[^1].Text.Trim().Length > 0, "The final turn is the result the page shows; it must not be empty.");
    }

    /// <summary>One rendered card: a maximal run of consecutive messages by the same speaker.</summary>
    sealed record Turn(string Speaker, List<string> MessageIds, string Text);

    /// <summary>
    /// Collapses the message stream into turns the way the page does: a TEXT_MESSAGE_START whose
    /// name matches the turn in progress continues it rather than starting a new one.
    /// </summary>
    static List<Turn> TurnsOf(List<BaseEvent> events)
    {
        List<Turn> turns = [];
        var text = new Dictionary<string, string>();

        foreach (BaseEvent evt in events)
        {
            switch (evt)
            {
                case TextMessageStartEvent start:
                    if (turns.Count > 0 && turns[^1].Speaker == (start.Name ?? ""))
                    {
                        turns[^1].MessageIds.Add(start.MessageId);
                    }
                    else
                    {
                        turns.Add(new Turn(start.Name ?? "", [start.MessageId], string.Empty));
                    }

                    break;

                case TextMessageContentEvent content:
                    text[content.MessageId] = text.GetValueOrDefault(content.MessageId, "") + content.Delta;
                    break;
            }
        }

        return [.. turns.Select(turn => turn with
        {
            Text = string.Join("\n\n", turn.MessageIds.Select(id => text.GetValueOrDefault(id, "")).Where(part => part.Trim().Length > 0)),
        })];
    }

    /// <summary>Prints the run as the browser sees it, so a failure is readable.</summary>
    static void Dump(List<BaseEvent> events)
    {
        foreach (BaseEvent evt in events)
        {
            string detail = evt switch
            {
                TextMessageStartEvent s => $"{s.Name} ({Short(s.MessageId)})",
                TextMessageContentEvent c => $"{Short(c.MessageId)} {c.Delta.Replace("\n", "\\n")}",
                TextMessageEndEvent e => Short(e.MessageId),
                ToolCallStartEvent t => $"{t.ToolCallName} parent={Short(t.ParentMessageId)} call={Short(t.ToolCallId)}",
                ToolCallArgsEvent a => $"call={Short(a.ToolCallId)} {a.Delta}",
                ToolCallEndEvent x => $"call={Short(x.ToolCallId)}",
                ToolCallResultEvent r => $"call={Short(r.ToolCallId)} msg={Short(r.MessageId)} {r.Content}",
                RunErrorEvent r => $"{r.Code}: {r.Message}",
                _ => "",
            };

            Console.WriteLine($"{evt.Type,-22} {detail}");
        }
    }

    static string Short(string? id) => id is null ? "<null>" : id.Length <= 8 ? id : id[^8..];
}
