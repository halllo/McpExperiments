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

    public static AIAgent CreateAgent(string name, IChatClient chatClient, IServiceProvider services, IChatReducer? reducer = null, IList<AITool>? tools = null)
    {
        var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
        return chatClient
            .AsAIAgent(
                options: new ChatClientAgentOptions
                {
                    Id = Guid.Empty.ToString(),
                    Name = name,
                    ChatOptions = new ChatOptions()
                    {
                        Temperature = 0,
                        Tools = tools,
                    },
                    ChatHistoryProvider = new FileSystemChatHistoryProvider(reducer: reducer), // DevUI uses InMemoryResponsesService, which stores/loads directly with IConversationStorage.
                    AIContextProviders = [CreateSkillsProvider()],
                },
                services: services)
            .AsBuilder()
            .UseCodeInterpreterSessionPerRun()
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
                var logger = services!.GetRequiredService<ILoggerFactory>().CreateLogger("MyAgent.ScriptRunner");
                var codeInterpreter = services!.GetRequiredService<CodeInterpreter>();

                var sandboxScriptsBase = $"skills/{skill.Frontmatter.Name}/scripts";
                var scriptsDir = Path.Combine(skill.Path, "scripts");
                string? sandboxScriptPath = null;
                foreach (var filePath in Directory.EnumerateFiles(scriptsDir, "*", SearchOption.AllDirectories))
                {
                    var relativePath = Path.GetRelativePath(scriptsDir, filePath).Replace('\\', '/');
                    var targetPath = $"{sandboxScriptsBase}/{relativePath}";
                    var fileContent = await File.ReadAllTextAsync(filePath, cancellationToken);
                    await codeInterpreter.WriteFileIfNew(path: targetPath, content: fileContent, cancellationToken: cancellationToken);
                    if (filePath == script.FullPath) sandboxScriptPath = targetPath;
                }
                sandboxScriptPath ??= $"{sandboxScriptsBase}/{Path.GetFileName(script.FullPath)}";

                var commandLineParts = new List<string> { "python3", sandboxScriptPath };
                if (arguments is { ValueKind: JsonValueKind.Array } json)
                    foreach (var element in json.EnumerateArray())
                        commandLineParts.Add(element.GetString()!);

                static string ShellQuote(string s) => "'" + s.Replace("'", "'\\''") + "'";
                var command = string.Join(" ", commandLineParts.Select(ShellQuote));

                logger.LogInformation("Running script {ScriptName}: {Command}", script.Name, command);

                return await codeInterpreter.ExecuteCommand(command, directoryPath: sandboxScriptsBase, cancellationToken);
            })
            .Build();

        return provider;
    }
#pragma warning restore MAAI001
}