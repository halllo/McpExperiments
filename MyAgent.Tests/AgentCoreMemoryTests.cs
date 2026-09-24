using Microsoft.Agents.AI;
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
    }
}
