using System.Text.Json;
using Amazon.BedrockRuntime;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using OpenAI;

namespace MyAgent;

public static class Factory
{
    public static IChatClient OpenAI(IConfiguration configuration, IServiceProvider services)
    {
        var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
        var openaiApiKey = configuration["OPENAI_API_KEY"] ?? throw new InvalidOperationException("OPENAI_API_KEY is not set.");
        return new OpenAIClient(openaiApiKey)
            .GetChatClient("gpt-4o")
            .AsIChatClient()
            .AsBuilder()
            .UseOpenTelemetry(sourceName: applicationName, configure: c => c.EnableSensitiveData = true)
            .Build()
            ;
    }

    public static IChatClient AmazonBedrock(IConfiguration configuration, IServiceProvider services)
    {
        var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
        var runtime = new AmazonBedrockRuntimeClient(
            awsAccessKeyId: configuration["AWSBedrockAccessKeyId"],
            awsSecretAccessKey: configuration["AWSBedrockSecretAccessKey"],
            region: Amazon.RegionEndpoint.GetBySystemName(configuration["AWSBedrockRegion"]));

        return runtime
            .AsIChatClient(defaultModelId:
                "eu.anthropic.claude-sonnet-4-6"
            )
            .AsBuilder()
            .UseOpenTelemetry(sourceName: applicationName, configure: c => c.EnableSensitiveData = true)
            .Build(services)
            ;
    }

    public static AIAgent CreateAgent(string name, IChatClient chatClient, IServiceProvider services, IChatReducer? reducer = null)
    {
        var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
        return chatClient
            .AsAIAgent(
                options: new ChatClientAgentOptions
                {
                    Name = name,
                    ChatOptions = new ChatOptions()
                    {
                        Tools = GetTools(),
                    },
                    ChatHistoryProvider = new FileSystemChatHistoryProvider(reducer: reducer), // DevUI uses InMemoryResponsesService, which stores/loads directly with IConversationStorage.
                    AIContextProviders = [CreateSkillsProvider()],
                },
                services: services)
            .AsBuilder()
            .UseCodeInterpreterSessionOnDemand()
            .UseOpenTelemetry(sourceName: applicationName, configure: c => c.EnableSensitiveData = true)
            .Build(services)
            ;
    }

    public static AIFunction[] GetTools()
    {
        return [
            AIFunctionFactory.Create(
                method: (IServiceProvider services) =>
                {
                    var loggerFactory = services.GetRequiredService<ILoggerFactory>();
                    var logger = loggerFactory.CreateLogger("GetCurrentTimeFunction");
                    logger.LogInformation("GetCurrentTimeFunction called.");

                    return DateTimeOffset.UtcNow;
                },
                name: "get_current_time",
                description: "Get the current UTC time."
            ),
            AIFunctionFactory.Create(
                method: async (IServiceProvider services, string code) =>
                {
                    var codeInterpreter = services.GetRequiredService<CodeInterpreter>();
                    var result = await codeInterpreter.ExecuteCode(code);
                    return result;
                },
                name: "code_interpreter",
                description: "Execute Python code using the code interpreter."
            ),
        ];
    }

#pragma warning disable MAAI001
    public static AgentSkillsProvider CreateSkillsProvider()
    {
        var converterSkill = new AgentInlineSkill(
            name: "unit-converter",
            description: "Converts miles/kilometres and pounds/kilograms.",
            instructions: """
                Use this skill when the user asks for a unit conversion.
                1. Read the conversion-table resource.
                2. Use the convert script with the correct factor.
                3. Return a concise answer with both units.
                """)
            .AddResource("conversion-table", """
                | From       | To         | Factor   |
                |------------|------------|----------|
                | miles      | kilometres | 1.60934  |
                | kilometres | miles      | 0.621371 |
                | pounds     | kilograms  | 0.453592 |
                | kilograms  | pounds     | 2.20462  |
                """)
            .AddScript("convert", (double value, double factor) =>
            {
                double result = Math.Round(value * factor, 4);
                return JsonSerializer.Serialize(new { value, factor, result });
            });

        var provider = new AgentSkillsProviderBuilder()
            .UseSkills([converterSkill])
            .UseFileSkills([
                "/Users/manuel.naujoks/Projects/anthropics-skills/skills/pdf",
                "/Users/manuel.naujoks/Projects/anthropics-skills/skills/docx",
            ])
            .UseFileScriptRunner(async (skill, script, arguments, services, cancellationToken) =>
            {
                var logger = services!.GetRequiredService<ILoggerFactory>().CreateLogger("AgentFileSkillScriptRunner");

                var scriptContent = await File.ReadAllTextAsync(script.FullPath, cancellationToken);
                logger.LogInformation("Running script {ScriptName} with arguments {Arguments}: {Content}", script.Name, arguments, scriptContent);

                //??? how to actually invoke the script?
                var codeInterpreter = services!.GetRequiredService<CodeInterpreter>();
                var result = await codeInterpreter.ExecuteCode(scriptContent, cancellationToken);
                return result;
            })
            .Build();

        return provider;
    }
#pragma warning restore MAAI001
}