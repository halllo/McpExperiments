using System.Text.Json;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Compaction;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

[TestClass]
public sealed class ChatHistoryReducingTests
{
    static AIAgent CreateAgent()
    {
        var host = Program.BuildHost();
        var config = host.Services.GetRequiredService<IConfiguration>();
        var openai = Factory.OpenAI(config, host.Services);
        var agent = Factory.CreateAgent("", openai, host.Services, reducer);
        return agent;
    }

    #pragma warning disable MEAI001, MAAI001 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.
        static IChatReducer reducer = ChatStrategyExtensions.AsChatReducer(new PipelineCompactionStrategy(

            // 1. Gentle: collapse old tool-call groups into short summaries
            new ToolResultCompactionStrategy(CompactionTriggers.MessagesExceed(7)),

            // 2. Moderate: use an LLM to summarize older conversation spans into a concise message
            //new SummarizationCompactionStrategy(chatClient, CompactionTriggers.TokensExceed(0x500)),

            // 3. Aggressive: keep only the last N user turns and their responses
            new SlidingWindowCompactionStrategy(CompactionTriggers.TurnsExceed(4)),

            // 4. Emergency: drop oldest groups until under the token budget
            new TruncationCompactionStrategy(CompactionTriggers.TokensExceed(0x8000))
        ));
#pragma warning restore MEAI001, MAAI001 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.


    [TestMethod]
    public async Task NoCompacting()
    {
        var agent = CreateAgent();
        var session = await agent.CreateSessionAsync();

        _ = await agent.RunAsync("Hello!", session);
        _ = await agent.RunAsync("Nice!", session);
        _ = await agent.RunAsync("Cool!", session);
        var answer = await agent.RunAsync("What was the first message I sent you?", session);

        var serializedSession = await agent.SerializeSessionAsync(session);
        Directory.CreateDirectory("ChatSessions");
        File.WriteAllText(Path.Combine("ChatSessions", $"{Guid.NewGuid()}.json"), JsonSerializer.Serialize(serializedSession));
    }

    [TestMethod]
    public async Task FirstMessageGetsCompactedAway()
    {
        var agent = CreateAgent();
        var session = await agent.CreateSessionAsync();

        _ = await agent.RunAsync("Hello!", session);
        _ = await agent.RunAsync("Nice!", session);
        _ = await agent.RunAsync("Cool!", session);
        _ = await agent.RunAsync("Thanks!", session);
        var answer = await agent.RunAsync("What was the first message I sent you?", session);

        var serializedSession = await agent.SerializeSessionAsync(session);
        Directory.CreateDirectory("ChatSessions");
        File.WriteAllText(Path.Combine("ChatSessions", $"{Guid.NewGuid()}.json"), JsonSerializer.Serialize(serializedSession));
    }

    [TestMethod]
    public async Task NewMessageGetsAddedToCompacted()
    {
        var agent = CreateAgent();
        var session = await agent.CreateSessionAsync();

        _ = await agent.RunAsync("Hello!", session);
        _ = await agent.RunAsync("Nice!", session);
        _ = await agent.RunAsync("Cool!", session);
        _ = await agent.RunAsync("Thanks!", session);
        _ = await agent.RunAsync("Awesome!", session);
        var answer = await agent.RunAsync("What was the first message I sent you?", session);

        var serializedSession = await agent.SerializeSessionAsync(session);
        Directory.CreateDirectory("ChatSessions");
        File.WriteAllText(Path.Combine("ChatSessions", $"{Guid.NewGuid()}.json"), JsonSerializer.Serialize(serializedSession));
    }
}
