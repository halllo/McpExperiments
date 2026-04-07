using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
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

    public static AIAgent CreateAgent(string name, IChatClient chatClient, AIFunction[] tools, IServiceProvider services, IChatReducer? reducer = null)
    {
        var applicationName = services.GetRequiredService<IHostEnvironment>().ApplicationName;
        return chatClient
            .AsAIAgent(
                options: new ChatClientAgentOptions
                {
                    Name = name,
                    ChatOptions = new ChatOptions()
                    {
                        Tools = tools,
                    },
                    ChatHistoryProvider = new FileSystemChatHistoryProvider(reducer: reducer), // DevUI uses InMemoryResponsesService, which stores/loads directly with IConversationStorage.
                    AIContextProviders = [],
                },
                services: services)
            .AsBuilder()
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
                var loggerFactory = services.GetRequiredService<ILoggerFactory>();
                var logger = loggerFactory.CreateLogger("CodeInterpreterFunction");
                logger.LogInformation("CodeInterpreterFunction called.");

                var agentCore = services.GetRequiredService<IAmazonBedrockAgentCore>();
                var result = await ExecuteCode(agentCore, logger, code);
                return result;
            },
            name: "code_interpreter",
            description: "Execute Python code using the code interpreter."
        ),
    ];
    }

    public static async Task<string> ExecuteCode(IAmazonBedrockAgentCore agentCore, ILogger logger, string pythonCode)
    {
        var codeInterpreterId = "aws.codeinterpreter.v1";
        var session = await agentCore.StartCodeInterpreterSessionAsync(new StartCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            Name = "TestSession1",
            SessionTimeoutSeconds = 900 // 15 minutes
        });
        var sessionId = session.SessionId;
        logger.LogInformation("Started code interpreter session with ID: {SessionId}", sessionId);

        try
        {
            var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                SessionId = sessionId,
                Name = ToolName.ExecuteCode,
                Arguments = new ToolArguments
                {
                    Language = "python",
                    Code = pythonCode,
                }
            });

            var result = string.Empty;
            await foreach (var message in response.Stream)
            {
                if (message is CodeInterpreterResult resultMessage)
                {
                    logger.LogInformation("Code interpreter result");
                    foreach (var content in resultMessage.Content)
                    {
                        logger.LogInformation("Output type: {Type}, content: {Content}", content.Type, content.Text);
                        result += content.Text;
                    }
                }
                else
                {
                    var type = message.GetType().Name;
                    logger.LogInformation("Received message from code interpreter: {Content}", type);
                }
            }
            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error invoking code interpreter");
            throw;
        }
        finally
        {
            await agentCore.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                SessionId = sessionId
            });
            logger.LogInformation("Ended code interpreter session with ID: {SessionId}", sessionId);
        }
    }
}