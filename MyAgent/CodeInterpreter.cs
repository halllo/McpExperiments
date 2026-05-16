using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using System.Runtime.CompilerServices;

namespace MyAgent;

public class CodeInterpreter(IAmazonBedrockAgentCore agentCore, ILogger<CodeInterpreter> logger)
{
    private const string codeInterpreterId = "aws.codeinterpreter.v1";
    private const string runOptionSessionIdKey = "code_interpreter_sessionid";

    public async Task<string> ExecuteCode(string pythonCode, CancellationToken cancellationToken = default)
    {
        var runContext = AIAgent.CurrentRunContext;
        var runOptions = runContext?.RunOptions;
        if (runOptions is null) throw new InvalidOperationException("RunOptions is not available in the current run context.");

        var sessionId = runOptions.AdditionalProperties?[runOptionSessionIdKey] as string;
        if (sessionId is null)
        {
            var runId = Guid.NewGuid();
            var sessionName = "MyAgentRun_" + runId;
            var session = await agentCore.StartCodeInterpreterSessionAsync(new StartCodeInterpreterSessionRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                Name = sessionName,
                SessionTimeoutSeconds = 900 // 15 minutes
            }, cancellationToken);

            sessionId = session.SessionId;
            runOptions.AdditionalProperties ??= [];
            runOptions.AdditionalProperties?[runOptionSessionIdKey] = sessionId;
            logger.LogInformation("Started code interpreter {CodeInterpreterSessionId}", sessionId);
        }
        else
        {
            logger.LogInformation("Reusing code interpreter {CodeInterpreterSessionId}", sessionId);
            //reuse existing session
        }

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
            }, cancellationToken);

            var result = string.Empty;
            await foreach (var message in response.Stream.WithCancellation(cancellationToken))
            {
                if (message is CodeInterpreterResult resultMessage)
                {
                    foreach (var content in resultMessage.Content)
                    {
                        result += content.Text;
                    }
                }
                else
                {
                    var type = message.GetType().Name;
                }
            }
            logger.LogInformation("Received code interpreter {CodeInterpreterSessionId} result: {Result}", sessionId, result);
            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error invoking code interpreter {CodeInterpreterSessionId}", sessionId);
            throw;
        }
    }

    public async Task CloseCodeInterpreter(CancellationToken cancellationToken = default)
    {
        var runContext = AIAgent.CurrentRunContext;
        var sessionId = runContext?.RunOptions?.AdditionalProperties?[runOptionSessionIdKey] as string;
        if (sessionId is not null)
        {
            await agentCore.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                SessionId = sessionId
            }, cancellationToken);

            runContext?.RunOptions?.AdditionalProperties?.Remove(runOptionSessionIdKey);
            logger.LogInformation("Closed code interpreter {CodeInterpreterSessionId}", sessionId);
        }
    }
}

public static class CodeInterpreterExtensions
{
    extension(AIAgentBuilder agentBuilder)
    {
        public AIAgentBuilder UseCodeInterpreterSessionOnDemand()
        => agentBuilder.Use((inner, services) => new CodeInterpreterSessionClosingMiddleware(inner, services));
    }

    private class CodeInterpreterSessionClosingMiddleware(AIAgent inner, IServiceProvider services) : DelegatingAIAgent(inner)
    {
        protected async override IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session = null,
            AgentRunOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await foreach (var update in base.RunCoreStreamingAsync(messages, session, options, cancellationToken))
            {
                yield return update;
            }

            var codeInterpreter = services.GetRequiredService<CodeInterpreter>();
            await codeInterpreter.CloseCodeInterpreter(cancellationToken);
        }
    }
}