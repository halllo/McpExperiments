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
        var environment = services.GetRequiredService<IHostEnvironment>();
        var openaiApiKey = configuration["OPENAI_API_KEY"] ?? throw new InvalidOperationException("OPENAI_API_KEY is not set.");
        return new OpenAIClient(openaiApiKey)
            .GetChatClient("gpt-4o")
            .AsIChatClient()
            .AsBuilder()
            // Sensitive data means the prompts and completions themselves. Useful in the local
            // dashboard, wrong to ship to a shared collector, so it follows the environment.
            .UseOpenTelemetry(sourceName: environment.ApplicationName, configure: c => c.EnableSensitiveData = environment.IsDevelopment())
            .Build()
            ;
    }

    public static IChatClient AmazonBedrock(IConfiguration configuration, IServiceProvider services)
    {
        var environment = services.GetRequiredService<IHostEnvironment>();
        var runtime = new AmazonBedrockRuntimeClient(
            awsAccessKeyId: configuration["AWSBedrockAccessKeyId"],
            awsSecretAccessKey: configuration["AWSBedrockSecretAccessKey"],
            region: Amazon.RegionEndpoint.GetBySystemName(configuration["AWSBedrockRegion"]));

        return runtime
            .AsIChatClient(defaultModelId:
                "eu.anthropic.claude-sonnet-4-6"
            )
            .AsBuilder()
            .UseOpenTelemetry(sourceName: environment.ApplicationName, configure: c => c.EnableSensitiveData = environment.IsDevelopment())
            .Build(services)
            ;
    }

    /// <param name="autoApproveSkillTools">
    /// Bypasses the approval prompts for the skill tools (load_skill, read_skill_resource, run_skill_script).
    /// Intended for automated tests, where nobody is around to approve. Leave <see langword="false"/> for DevUI
    /// so skill invocations still ask for confirmation.
    /// </param>
    /// <param name="memoryActorId">
    /// Whose long-term memories the agent recalls and records. Falls back to <c>AgentCoreMemoryActorId</c> from
    /// configuration, then <c>default-user</c>. Memory is only enabled when <see cref="AgentCoreMemory"/> is registered.
    /// </param>
    public static AIAgent CreateAgent(string name, IChatClient chatClient, IServiceProvider services, IChatReducer? reducer = null, IList<AITool>? tools = null, bool autoApproveSkillTools = false, string? memoryActorId = null)
    {
        var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
        var contextProviders = new List<AIContextProvider> { CreateSkillsProvider(autoApproveSkillTools) };
        if (services.GetService<AgentCoreMemory>() is { } memory)
        {
            var actorId = memoryActorId ?? services.GetRequiredService<IConfiguration>()["AgentCoreMemoryActorId"] ?? "default-user";
            contextProviders.Add(new AgentCoreMemoryProvider(memory, actorId, services.GetRequiredService<ILogger<AgentCoreMemoryProvider>>()));
        }
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
                    AIContextProviders = contextProviders,
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
                    var result = await services.GetRequiredService<CodeInterpreter>().ExecuteCode(code);
                    await SaveNewFiles(result);
                    return result.Output;
                },
                name: "code_interpreter",
                description: "Execute Python code using the code interpreter."
            ),
        ];
    }

#pragma warning disable MAAI001
    /// <param name="autoApproveSkillTools">See <see cref="CreateAgent"/>.</param>
    public static AgentSkillsProvider CreateSkillsProvider(bool autoApproveSkillTools = false)
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
            .UseOptions(o =>
            {
                o.DisableLoadSkillApproval = autoApproveSkillTools;
                o.DisableReadSkillResourceApproval = autoApproveSkillTools;
                o.DisableRunSkillScriptApproval = autoApproveSkillTools;
            })
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

                var filesToUpload = new List<(string path, string content)>();
                foreach (var filePath in Directory.EnumerateFiles(scriptsDir, "*", SearchOption.AllDirectories))
                {
                    var relativePath = Path.GetRelativePath(scriptsDir, filePath).Replace('\\', '/');
                    var targetPath = $"{sandboxScriptsBase}/{relativePath}";
                    filesToUpload.Add((targetPath, await File.ReadAllTextAsync(filePath, cancellationToken)));
                    if (filePath == script.FullPath) sandboxScriptPath = targetPath;
                }
                await codeInterpreter.WriteFilesIfNew(filesToUpload, cancellationToken: cancellationToken);
                sandboxScriptPath ??= $"{sandboxScriptsBase}/{Path.GetFileName(script.FullPath)}";

                var commandLineParts = new List<string> { "python3", sandboxScriptPath };
                if (arguments is { ValueKind: JsonValueKind.Array } json)
                    foreach (var element in json.EnumerateArray())
                        commandLineParts.Add(element.GetString()!);

                static string ShellQuote(string s) => "'" + s.Replace("'", "'\\''") + "'";
                var command = string.Join(" ", commandLineParts.Select(ShellQuote));

                logger.LogInformation("Running script {ScriptName}: {Command}", script.Name, command);

                var result = await codeInterpreter.ExecuteCommand(command, directoryPath: sandboxScriptsBase, cancellationToken: cancellationToken);
                await SaveNewFiles(result);
                return result.Output;
            })
            .Build();

        return provider;
    }
#pragma warning restore MAAI001

    public static async Task SaveNewFiles(SandboxResult result)
    {
        if (result.NewFiles.Count == 0) return;
        var outputDir = Path.Combine("NewFiles", $"{result.SessionId}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}");
        Directory.CreateDirectory(outputDir);
        foreach (var (path, file) in result.NewFiles)
        {
            var localPath = Path.Combine(outputDir, path.TrimStart('/'));
            Directory.CreateDirectory(Path.GetDirectoryName(localPath) ?? outputDir);
            if (file.Blob is { } blob)
            {
                using var fs = File.Create(localPath);
                await blob.CopyToAsync(fs);
            }
            else if (file.Text is { } text)
            {
                await File.WriteAllTextAsync(localPath, text);
            }
        }
    }
}