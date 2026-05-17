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
        var sessionId = await EnsureSession(cancellationToken);
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
            logger.LogError(ex, "Error executing code in code interpreter {CodeInterpreterSessionId}", sessionId);
            throw;
        }
    }

    public async Task<string> ExecuteCommand(string command, string? directoryPath = null, CancellationToken cancellationToken = default)
    {
        var sessionId = await EnsureSession(cancellationToken);
        try
        {
            var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                SessionId = sessionId,
                Name = ToolName.ExecuteCommand,
                Arguments = new ToolArguments
                {
                    Command = command,
                    DirectoryPath = directoryPath,
                }
            }, cancellationToken);

            var result = string.Empty;
            await foreach (var message in response.Stream.WithCancellation(cancellationToken))
            {
                if (message is CodeInterpreterResult resultMessage)
                    foreach (var content in resultMessage.Content)
                        result += content.Text;
            }

            logger.LogInformation("ExecuteCommand {Command} result: {Result}", command, result);
            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error executing code in code interpreter {CodeInterpreterSessionId}", sessionId);
            throw;
        }
    }

    public async Task WriteFileIfNew(string path, string content, CancellationToken cancellationToken = default)
    {
        const string uploadedFilesKey = "code_interpreter_uploaded_files";
        var runContext = AIAgent.CurrentRunContext
            ?? throw new InvalidOperationException("RunOptions is not available in the current run context.");

        runContext.RunOptions!.AdditionalProperties ??= [];
        if (!runContext.RunOptions.AdditionalProperties.TryGetValue(uploadedFilesKey, out var uploadedObj)
            || uploadedObj is not HashSet<string> uploadedFiles)
        {
            uploadedFiles = [];
            runContext.RunOptions.AdditionalProperties[uploadedFilesKey] = uploadedFiles;
        }

        if (uploadedFiles.Add(path))
        {
            await WriteFile(path, content, cancellationToken);
            logger.LogDebug("Uploaded -> {Path}", path);
        }
    }

    public async Task WriteFile(string path, string content, CancellationToken cancellationToken = default)
    {
        var sessionId = await EnsureSession(cancellationToken);
        var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.WriteFiles,
            Arguments = new ToolArguments
            {
                Content = [new InputContentBlock { Path = path, Text = content }],
            }
        }, cancellationToken);
        await foreach (var _ in response.Stream.WithCancellation(cancellationToken)) { }
        logger.LogDebug("Wrote file to sandbox: {Path}", path);
    }

    private async Task<string> EnsureSession(CancellationToken cancellationToken)
    {
        var runContext = AIAgent.CurrentRunContext;
        if (runContext?.RunOptions is null)
            throw new InvalidOperationException("RunOptions is not available in the current run context.");

        runContext.RunOptions.AdditionalProperties ??= [];
        var sessionId = runContext.RunOptions.AdditionalProperties.TryGetValue(runOptionSessionIdKey, out var existing)
            ? existing as string
            : null;

        if (sessionId is null)
        {
            var sessionName = "MyAgentRun_" + Guid.NewGuid();
            var started = await agentCore.StartCodeInterpreterSessionAsync(new StartCodeInterpreterSessionRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                Name = sessionName,
                SessionTimeoutSeconds = 900
            }, cancellationToken);

            sessionId = started.SessionId;
            runContext.RunOptions.AdditionalProperties[runOptionSessionIdKey] = sessionId;
            logger.LogInformation("Started code interpreter {CodeInterpreterSessionId}", sessionId);
        }
        else
        {
            logger.LogInformation("Reusing code interpreter {CodeInterpreterSessionId}", sessionId);
        }

        return sessionId;
    }

    public async Task CloseCodeInterpreter(CancellationToken cancellationToken = default)
    {
        var runContext = AIAgent.CurrentRunContext;
        var sessionId = runContext?.RunOptions?.AdditionalProperties?.TryGetValue(runOptionSessionIdKey, out var v) == true
            ? v as string : null;
        if (sessionId is not null)
        {
            await agentCore.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                SessionId = sessionId
            }, cancellationToken);

            runContext!.RunOptions!.AdditionalProperties!.Remove(runOptionSessionIdKey);
            logger.LogInformation("Closed code interpreter {CodeInterpreterSessionId}", sessionId);
        }
    }
}

public static class CodeInterpreterExtensions
{
    extension(AIAgentBuilder agentBuilder)
    {
        public AIAgentBuilder UseCodeInterpreterSessionPerRun()
        => agentBuilder.Use((inner, services) => new CodeInterpreterSessionClosingMiddleware(inner, services));
    }

    private class CodeInterpreterSessionClosingMiddleware(AIAgent inner, IServiceProvider services) : DelegatingAIAgent(inner)
    {
        protected override async Task<AgentResponse> RunCoreAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session = null,
            AgentRunOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            options ??= new AgentRunOptions();
            try
            {
                return await base.RunCoreAsync(messages, session, options, cancellationToken);
            }
            finally
            {
                await services.GetRequiredService<CodeInterpreter>().CloseCodeInterpreter(cancellationToken);
            }
        }

        protected async override IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session = null,
            AgentRunOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            options ??= new AgentRunOptions();

            await foreach (var update in base.RunCoreStreamingAsync(messages, session, options, cancellationToken))
            {
                yield return update;
            }

            await services.GetRequiredService<CodeInterpreter>().CloseCodeInterpreter(cancellationToken);
        }
    }
}