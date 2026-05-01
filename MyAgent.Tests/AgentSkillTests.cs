#pragma warning disable MEAI001, MAAI001
using System.Text.Json;
using Microsoft.Agents.AI;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

[TestClass]
public sealed class AgentSkillTests
{
    static AIAgent CreateAgent()
    {
        var host = Program.BuildHost();
        var config = host.Services.GetRequiredService<IConfiguration>();
        var openai = Factory.OpenAI(config, host.Services);
        return Factory.CreateAgent("", openai, Factory.GetTools(), host.Services);
    }

    [TestMethod]
    public async Task UnitConverter_ConvertsMilesAndKilograms()
    {
        var agent = CreateAgent();
        var session = await agent.CreateSessionAsync();

        var response = await agent.RunAsync(
            "How many kilometres is 26.2 miles, and how many pounds is 75 kilograms?",
            session);

        // 26.2 × 1.60934 = 42.1645
        // 75   × 2.20462 = 165.3465
        Assert.IsTrue(response.Text.Contains("42.16"),
            $"Expected miles→km conversion (42.16...) in: {response.Text}");
        Assert.IsTrue(response.Text.Contains("165.3"),
            $"Expected kg→pounds conversion (165.3...) in: {response.Text}");

        var serializedSession = await agent.SerializeSessionAsync(session);
        Directory.CreateDirectory("ChatSessions");
        File.WriteAllText(
            Path.Combine("ChatSessions", $"skills_{Guid.NewGuid()}.json"),
            JsonSerializer.Serialize(serializedSession));
    }
}
#pragma warning restore MEAI001, MAAI001
