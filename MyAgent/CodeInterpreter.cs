using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using System.Runtime.CompilerServices;
using System.Text;

namespace MyAgent;

public record SandboxFileContent(string Path, string? Text, MemoryStream? Blob);
public record SandboxResult(string SessionId, string Output, IReadOnlyDictionary<string, SandboxFileContent> NewFiles);

public class CodeInterpreter(IAmazonBedrockAgentCore agentCore, ILogger<CodeInterpreter> logger)
{
    private const string codeInterpreterId = "aws.codeinterpreter.v1";
    private const string runOptionSessionIdKey = "code_interpreter_sessionid";

    public async Task<SandboxResult> ExecuteCode(string pythonCode, AgentRunOptions? runOptions = null, CancellationToken cancellationToken = default)
    {
        var sessionId = await EnsureSession(runOptions, cancellationToken);
        try
        {
            var filesBefore = await GetSandboxFileState(sessionId, cancellationToken);

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

            var output = new StringBuilder();
            await foreach (var message in response.Stream.WithCancellation(cancellationToken))
                if (message is CodeInterpreterResult r)
                    foreach (var content in r.Content)
                        output.Append(content.Text);

            var newFiles = await DetectNewFiles(sessionId, filesBefore, cancellationToken);
            logger.LogInformation("Received code interpreter {CodeInterpreterSessionId} result: {Result}", sessionId, output);
            return new SandboxResult(sessionId, output.ToString(), newFiles);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error executing code in code interpreter {CodeInterpreterSessionId}", sessionId);
            throw;
        }
    }

    public async Task<SandboxResult> ExecuteCommand(string command, string? directoryPath = null, AgentRunOptions? runOptions = null, CancellationToken cancellationToken = default)
    {
        var sessionId = await EnsureSession(runOptions, cancellationToken);
        try
        {
            var filesBefore = await GetSandboxFileState(sessionId, cancellationToken);

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

            var output = new StringBuilder();
            await foreach (var message in response.Stream.WithCancellation(cancellationToken))
                if (message is CodeInterpreterResult r)
                    foreach (var content in r.Content)
                        output.Append(content.Text);

            var newFiles = await DetectNewFiles(sessionId, filesBefore, cancellationToken);
            logger.LogInformation("ExecuteCommand {Command} result: {Result}", command, output);
            return new SandboxResult(sessionId, output.ToString(), newFiles);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error executing code in code interpreter {CodeInterpreterSessionId}", sessionId);
            throw;
        }
    }

    public async Task WriteFilesIfNew(IEnumerable<(string path, string content)> files, AgentRunOptions? runOptions = null, CancellationToken cancellationToken = default)
    {
        const string uploadedFilesKey = "code_interpreter_uploaded_files";
        var options = ResolveRunOptions(runOptions);

        options.AdditionalProperties ??= [];
        if (!options.AdditionalProperties.TryGetValue(uploadedFilesKey, out var uploadedObj)
            || uploadedObj is not HashSet<string> uploadedFiles)
        {
            uploadedFiles = [];
            options.AdditionalProperties[uploadedFilesKey] = uploadedFiles;
        }

        var toUpload = files.Where(f => uploadedFiles.Add(f.path)).ToList();
        if (toUpload.Count > 0)
            await WriteFiles(toUpload, runOptions, cancellationToken);
    }

    public async Task WriteFiles(IEnumerable<(string path, string content)> files, AgentRunOptions? runOptions = null, CancellationToken cancellationToken = default)
    {
        var sessionId = await EnsureSession(runOptions, cancellationToken);
        var blocks = files.Select(f => new InputContentBlock { Path = f.path, Text = f.content }).ToList();
        var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.WriteFiles,
            Arguments = new ToolArguments { Content = blocks }
        }, cancellationToken);
        await foreach (var _ in response.Stream.WithCancellation(cancellationToken)) { }
        logger.LogDebug("Wrote {Count} file(s) to sandbox", blocks.Count);
    }

    public async Task<Dictionary<string, SandboxFileContent>> ReadFiles(IEnumerable<string> paths, AgentRunOptions? runOptions = null, CancellationToken cancellationToken = default)
    {
        var sessionId = await EnsureSession(runOptions, cancellationToken);
        return await ReadFilesCore(sessionId, paths, cancellationToken);
    }

    public async Task CloseCodeInterpreter(AgentRunOptions? runOptions = null, CancellationToken cancellationToken = default)
    {
        var options = runOptions ?? AIAgent.CurrentRunContext?.RunOptions;
        var sessionId = options?.AdditionalProperties?.TryGetValue(runOptionSessionIdKey, out var v) == true
            ? v as string : null;
        if (sessionId is not null)
        {
            await agentCore.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
            {
                CodeInterpreterIdentifier = codeInterpreterId,
                SessionId = sessionId
            }, cancellationToken);

            options!.AdditionalProperties!.Remove(runOptionSessionIdKey);
            logger.LogInformation("Closed code interpreter {CodeInterpreterSessionId}", sessionId);
        }
    }

    private async Task<Dictionary<string, SandboxFileContent>> DetectNewFiles(
        string sessionId, Dictionary<string, string> filesBefore, CancellationToken cancellationToken)
    {
        var filesAfter = await GetSandboxFileState(sessionId, cancellationToken);
        var changedPaths = filesAfter
            .Where(kvp => !filesBefore.TryGetValue(kvp.Key, out var before) || before != kvp.Value)
            .Select(kvp => kvp.Key)
            .ToList();
        if (changedPaths.Count == 0) return [];
        var newFiles = await ReadFilesCore(sessionId, changedPaths, cancellationToken);
        if (newFiles.Count > 0)
            logger.LogInformation("Detected {Count} new/modified sandbox file(s)", newFiles.Count);
        return newFiles;
    }

    private async Task<Dictionary<string, string>> GetSandboxFileState(string sessionId, CancellationToken cancellationToken)
    {
        var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.ListFiles,
            Arguments = new ToolArguments { DirectoryPath = "." }
        }, cancellationToken);

        // ListFiles returns resource_link blocks: Name = filename, Uri = file:///./name.
        // Size is never populated, so we can only detect new files (not modifications).
        var state = new Dictionary<string, string>();
        await foreach (var message in response.Stream.WithCancellation(cancellationToken))
        {
            if (message is CodeInterpreterResult r)
                foreach (var c in r.Content ?? [])
                    if (c.Name is { Length: > 0 } name && c.Uri is { Length: > 0 } uri)
                        state[name] = uri;
        }
        return state;
    }

    private async Task<Dictionary<string, SandboxFileContent>> ReadFilesCore(string sessionId, IEnumerable<string> paths, CancellationToken cancellationToken)
    {
        var response = await agentCore.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = codeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.ReadFiles,
            Arguments = new ToolArguments { Paths = [.. paths] }
        }, cancellationToken);

        // Content is in c.Resource; top-level c.Text/c.Data are always null for ReadFiles.
        // Text files: Resource.Text. Binary files: Resource.Blob (stream). Uri: "file:///filename".
        var result = new Dictionary<string, SandboxFileContent>();
        await foreach (var message in response.Stream.WithCancellation(cancellationToken))
        {
            if (message is not CodeInterpreterResult r) continue;
            foreach (var c in r.Content ?? [])
            {
                var resource = c.Resource;
                if (resource is null) continue;

                var path = resource.Uri?.StartsWith("file:///") == true ? resource.Uri[8..] : resource.Uri;
                if (string.IsNullOrEmpty(path)) continue;

                MemoryStream? blob = null;
                if (resource.Blob is MemoryStream ms && ms.Length > 0)
                {
                    ms.Position = 0;
                    blob = ms;
                }

                if (blob is not null || resource.Text is { Length: > 0 })
                    result[path] = new SandboxFileContent(path, resource.Text, blob);
            }
        }
        return result;
    }

    private async Task<string> EnsureSession(AgentRunOptions? runOptions, CancellationToken cancellationToken)
    {
        var options = ResolveRunOptions(runOptions);

        options.AdditionalProperties ??= [];
        var sessionId = options.AdditionalProperties.TryGetValue(runOptionSessionIdKey, out var existing)
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
            options.AdditionalProperties[runOptionSessionIdKey] = sessionId;
            logger.LogInformation("Started code interpreter {CodeInterpreterSessionId}", sessionId);
        }
        else
        {
            logger.LogInformation("Reusing code interpreter {CodeInterpreterSessionId}", sessionId);
        }

        return sessionId;
    }

    private static AgentRunOptions ResolveRunOptions(AgentRunOptions? runOptions) =>
        runOptions ?? AIAgent.CurrentRunContext?.RunOptions
        ?? throw new InvalidOperationException("RunOptions is not available in the current run context.");
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
                await services.GetRequiredService<CodeInterpreter>().CloseCodeInterpreter(options, cancellationToken);
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

            await services.GetRequiredService<CodeInterpreter>().CloseCodeInterpreter(options, cancellationToken);
        }
    }
}
