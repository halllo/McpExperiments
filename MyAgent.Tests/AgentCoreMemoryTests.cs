using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MyAgent.Tests;

[TestClass]
[TestCategory("Live")]   // makes real, paid model and AgentCore Memory calls
public sealed class AgentCoreMemoryTests
{
    static (AIAgent agent, AgentCoreMemory memory) CreateAgent(IHost host, string actorId)
    {
        var config = host.Services.GetRequiredService<IConfiguration>();
        var openai = Factory.OpenAI(config, host.Services);
        var agent = Factory.CreateAgent("", openai, host.Services, autoApproveSkillTools: true, memoryActorId: actorId);
        return (agent, host.Services.GetRequiredService<AgentCoreMemory>());
    }

    [TestMethod]
    [Timeout(15 * 60 * 1000, CooperativeCancellation = true)]   // first run creates the memory resource, which takes a few minutes
    public async Task FactFromOneSession_IsRecalledInANewSession()
    {
        using var host = Program.BuildHost();
        var actorId = $"test-{Guid.NewGuid():N}";   // fresh actor, so no memories leak in from earlier runs
        var (agent, memory) = CreateAgent(host, actorId);

        var firstSession = await agent.CreateSessionAsync();
        _ = await agent.RunAsync("Please remember this: my cat is called Pixel and she is a Maine Coon.", firstSession);

        // Long-term extraction runs asynchronously in AgentCore, typically within a minute or two.
        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        while ((await memory.Recall(actorId, "cat name")).Count == 0)
        {
            Assert.IsTrue(DateTimeOffset.UtcNow < deadline, "No long-term memory record was extracted within 5 minutes.");
            await Task.Delay(TimeSpan.FromSeconds(15));
        }

        var secondSession = await agent.CreateSessionAsync();
        var response = await agent.RunAsync("What is my cat called?", secondSession);

        Assert.IsTrue(response.Text.Contains("Pixel"), $"Expected the recalled cat name in: {response.Text}");

        await memory.ForgetActor(actorId);
    }

    [TestMethod]
    public async Task EachTurn_StoresOnlyItsOwnMessages_NotTheChatHistory()
    {
        using var host = Program.BuildHost();
        var actorId = $"test-{Guid.NewGuid():N}";
        var (agent, memory) = CreateAgent(host, actorId);
        var agentCore = host.Services.GetRequiredService<IAmazonBedrockAgentCore>();

        string[] prompts = ["My favourite colour is teal.", "I live in Hamburg.", "What is my favourite colour?"];
        var session = await agent.CreateSessionAsync();
        foreach (var prompt in prompts)
            _ = await agent.RunAsync(prompt, session);

        var memoryId = await memory.GetMemoryId();
        var memorySession = (await agentCore.ListSessionsAsync(new ListSessionsRequest { MemoryId = memoryId, ActorId = actorId })).SessionSummaries.Single();
        var events = (await agentCore.ListEventsAsync(new ListEventsRequest { MemoryId = memoryId, ActorId = actorId, SessionId = memorySession.SessionId, IncludePayloads = true })).Events
            .OrderBy(e => e.EventTimestamp)
            .ToList();

        foreach (var e in events)
            Console.WriteLine($"{e.EventTimestamp:O}: " + string.Join(" | ", e.Payload.Select(p => $"{p.Conversational.Role}: {p.Conversational.Content.Text}")));

        Assert.HasCount(prompts.Length, events, "Expected one event per turn.");
        for (var i = 0; i < prompts.Length; i++)
        {
            var messages = events[i].Payload.Select(p => p.Conversational).ToList();
            Assert.HasCount(2, messages, $"Turn {i + 1} should hold exactly its user message and the answer.");
            Assert.AreEqual(Role.USER, messages[0].Role);
            Assert.AreEqual(prompts[i], messages[0].Content.Text, $"Turn {i + 1} stored a different user message.");
            Assert.AreEqual(Role.ASSISTANT, messages[1].Role);
        }

        await memory.ForgetActor(actorId);
    }

    [TestMethod]
    [Timeout(15 * 60 * 1000, CooperativeCancellation = true)]
    public async Task ForgetActor_DeletesOnlyThatActorsEventsAndRecords()
    {
        using var host = Program.BuildHost();
        var memory = host.Services.GetRequiredService<AgentCoreMemory>();
        var agentCore = host.Services.GetRequiredService<IAmazonBedrockAgentCore>();
        var forgotten = $"test-{Guid.NewGuid():N}";
        var kept = $"test-{Guid.NewGuid():N}";

        // No model needed: store the turns directly and let AgentCore extract from them.
        foreach (var (actorId, pet) in new[] { (forgotten, "a dog called Rex"), (kept, "a parrot called Kiwi") })
            await memory.AddTurn(actorId, Guid.NewGuid().ToString(), [
                new ChatMessage(ChatRole.User, $"Please remember that I have {pet}."),
                new ChatMessage(ChatRole.Assistant, "Got it, I'll remember that."),
            ]);

        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        while ((await memory.Recall(forgotten, "pet")).Count == 0 || (await memory.Recall(kept, "pet")).Count == 0)
        {
            Assert.IsTrue(DateTimeOffset.UtcNow < deadline, "No long-term memory records were extracted within 5 minutes.");
            await Task.Delay(TimeSpan.FromSeconds(15));
        }

        var (eventsDeleted, recordsDeleted) = await memory.ForgetActor(forgotten);

        Assert.AreEqual(1, eventsDeleted);
        Assert.IsGreaterThan(0, recordsDeleted);
        Assert.AreEqual(0, await CountEvents(forgotten), "Forgotten actor still has events.");

        // Listing records is eventually consistent: deleted records can still show up for a little while.
        deadline = DateTimeOffset.UtcNow.AddMinutes(1);
        while (await CountRecords(AgentCoreMemory.UserNamespace(forgotten)) + await CountRecords(AgentCoreMemory.SummaryNamespace(forgotten)) > 0)
        {
            Assert.IsTrue(DateTimeOffset.UtcNow < deadline, "Forgotten actor still has memory records a minute after deletion.");
            await Task.Delay(TimeSpan.FromSeconds(5));
        }
        Assert.AreEqual(1, await CountEvents(kept), "Other actor lost its event.");
        Assert.IsGreaterThan(0, await CountRecords(AgentCoreMemory.UserNamespace(kept)), "Other actor lost its records.");

        await memory.ForgetActor(kept);

        // Sessions (and the actor) stay listed after all their events are deleted; there is no API to remove them, so count events.
        async Task<int> CountEvents(string actorId)
        {
            var memoryId = await memory.GetMemoryId();
            var count = 0;
            foreach (var session in (await agentCore.ListSessionsAsync(new ListSessionsRequest { MemoryId = memoryId, ActorId = actorId })).SessionSummaries ?? [])
                count += (await agentCore.ListEventsAsync(new ListEventsRequest { MemoryId = memoryId, ActorId = actorId, SessionId = session.SessionId })).Events?.Count ?? 0;
            return count;
        }

        async Task<int> CountRecords(string namespacePath) =>
            (await agentCore.ListMemoryRecordsAsync(new ListMemoryRecordsRequest { MemoryId = await memory.GetMemoryId(), NamespacePath = namespacePath })).MemoryRecordSummaries?.Count ?? 0;
    }
}
