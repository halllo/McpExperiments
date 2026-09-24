using System.Runtime.CompilerServices;
using System.Text;
using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Amazon.BedrockAgentCoreControl;
using Amazon.BedrockAgentCoreControl.Model;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace MyAgent;

/// <summary>
/// Thin wrapper over Bedrock AgentCore Memory. Short-term memory is the raw event log per actor/session
/// (<see cref="AddTurn"/>); long-term memory is what AgentCore asynchronously extracts from those events
/// with the strategies configured on the memory resource (<see cref="Recall"/>).
/// </summary>
public class AgentCoreMemory(
    IAmazonBedrockAgentCore agentCore,
    IAmazonBedrockAgentCoreControl agentCoreControl,
    IConfiguration configuration,
    ILogger<AgentCoreMemory> logger)
{
    private const string defaultMemoryName = "MyAgentMemory";

    // Everything long-term about a user lives under /users/{actorId}/..., so a single hierarchical search covers facts and preferences.
    public static string UserNamespace(string actorId) => $"/users/{actorId}/";
    public static string SummaryNamespace(string actorId) => $"/summaries/{actorId}/";

    private readonly SemaphoreSlim memoryIdLock = new(1, 1);
    private string? memoryId = configuration["AWSBedrockAgentCoreMemoryId"];

    public async Task<IReadOnlyList<MemoryRecordSummary>> Recall(string actorId, string query, int topK = 5, CancellationToken cancellationToken = default)
    {
        var response = await agentCore.RetrieveMemoryRecordsAsync(new RetrieveMemoryRecordsRequest
        {
            MemoryId = await GetMemoryId(cancellationToken),
            // Namespace only matches records in exactly that namespace (despite the docs saying prefix), NamespacePath includes children.
            NamespacePath = UserNamespace(actorId),
            SearchCriteria = new SearchCriteria { SearchQuery = query, TopK = topK },
            MaxResults = topK,
        }, cancellationToken);

        var records = response.MemoryRecordSummaries ?? [];
        logger.LogInformation("Recalled {Count} memory record(s) for actor {ActorId}", records.Count, actorId);
        return records;
    }

    public async Task AddTurn(string actorId, string sessionId, IEnumerable<ChatMessage> messages, CancellationToken cancellationToken = default)
    {
        // Only plain user/assistant text is worth extracting from; tool calls and results would just be noise.
        var payload = messages
            .Where(m => m.Role == ChatRole.User || m.Role == ChatRole.Assistant)
            .Where(m => !string.IsNullOrWhiteSpace(m.Text))
            .Select(m => new PayloadType
            {
                Conversational = new Conversational
                {
                    Role = m.Role == ChatRole.User ? Role.USER : Role.ASSISTANT,
                    Content = new Amazon.BedrockAgentCore.Model.Content { Text = m.Text },
                }
            })
            .ToList();
        if (payload.Count == 0) return;

        await agentCore.CreateEventAsync(new CreateEventRequest
        {
            MemoryId = await GetMemoryId(cancellationToken),
            ActorId = actorId,
            SessionId = sessionId,
            EventTimestamp = DateTime.UtcNow,
            Payload = payload,
        }, cancellationToken);
        logger.LogInformation("Stored {Count} message(s) as memory event for actor {ActorId}, session {MemorySessionId}", payload.Count, actorId, sessionId);
    }

    /// <summary>
    /// Deletes everything stored for an actor: the raw events of all its sessions (short-term) and the records
    /// extracted from them (long-term). There is no single AgentCore call for this, so it walks sessions and namespaces.
    /// </summary>
    /// <remarks>
    /// Extraction runs asynchronously, so an event stored shortly before this call can still produce records afterwards.
    /// For a guaranteed erasure, call it again a few minutes later.
    /// </remarks>
    public async Task<(int EventsDeleted, int RecordsDeleted)> ForgetActor(string actorId, CancellationToken cancellationToken = default)
    {
        var id = await GetMemoryId(cancellationToken);

        // Events first, so nothing new gets extracted while we delete the records.
        var eventsDeleted = 0;
        await foreach (var sessionId in ListSessions(id, actorId, cancellationToken))
        {
            await foreach (var eventId in ListEvents(id, actorId, sessionId, cancellationToken))
            {
                await agentCore.DeleteEventAsync(new DeleteEventRequest { MemoryId = id, ActorId = actorId, SessionId = sessionId, EventId = eventId }, cancellationToken);
                eventsDeleted++;
            }
        }

        var recordsDeleted = 0;
        foreach (var ns in new[] { UserNamespace(actorId), SummaryNamespace(actorId) })
        {
            var records = await ListRecords(id, ns, cancellationToken).ToListAsync(cancellationToken);
            foreach (var chunk in records.Chunk(100))
            {
                var response = await agentCore.BatchDeleteMemoryRecordsAsync(new BatchDeleteMemoryRecordsRequest
                {
                    MemoryId = id,
                    // Records are listed with a trailing slash on their namespace, but delete answers 404 unless it's trimmed.
                    Records = [.. chunk.Select(r => new MemoryRecordDeleteInput { MemoryRecordId = r.MemoryRecordId, Namespace = r.Namespaces?.FirstOrDefault()?.TrimEnd('/') })],
                }, cancellationToken);
                if (response.FailedRecords is { Count: > 0 } failed)
                    throw new InvalidOperationException($"Deleting {failed.Count} memory record(s) of actor {actorId} failed: {failed[0].ErrorCode} {failed[0].ErrorMessage}");
                recordsDeleted += response.SuccessfulRecords?.Count ?? 0;
            }
        }

        logger.LogInformation("Forgot actor {ActorId}: deleted {EventCount} event(s) and {RecordCount} memory record(s)", actorId, eventsDeleted, recordsDeleted);
        return (eventsDeleted, recordsDeleted);
    }

    private async IAsyncEnumerable<string> ListSessions(string id, string actorId, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string? nextToken = null;
        do
        {
            var page = await agentCore.ListSessionsAsync(new ListSessionsRequest { MemoryId = id, ActorId = actorId, MaxResults = 100, NextToken = nextToken }, cancellationToken);
            foreach (var session in page.SessionSummaries ?? []) yield return session.SessionId;
            nextToken = page.NextToken;
        } while (nextToken is not null);
    }

    private async IAsyncEnumerable<string> ListEvents(string id, string actorId, string sessionId, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string? nextToken = null;
        do
        {
            var page = await agentCore.ListEventsAsync(new ListEventsRequest { MemoryId = id, ActorId = actorId, SessionId = sessionId, IncludePayloads = false, MaxResults = 100, NextToken = nextToken }, cancellationToken);
            foreach (var e in page.Events ?? []) yield return e.EventId;
            nextToken = page.NextToken;
        } while (nextToken is not null);
    }

    private async IAsyncEnumerable<MemoryRecordSummary> ListRecords(string id, string namespacePath, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string? nextToken = null;
        do
        {
            var page = await agentCore.ListMemoryRecordsAsync(new ListMemoryRecordsRequest { MemoryId = id, NamespacePath = namespacePath, MaxResults = 100, NextToken = nextToken }, cancellationToken);
            foreach (var record in page.MemoryRecordSummaries ?? []) yield return record;
            nextToken = page.NextToken;
        } while (nextToken is not null);
    }

    /// <summary>
    /// Uses <c>AWSBedrockAgentCoreMemoryId</c> when configured, otherwise finds or creates a memory
    /// resource named <c>AWSBedrockAgentCoreMemoryName</c> (default <c>MyAgentMemory</c>) and waits until it is active.
    /// </summary>
    public async Task<string> GetMemoryId(CancellationToken cancellationToken = default)
    {
        if (memoryId is not null) return memoryId;

        await memoryIdLock.WaitAsync(cancellationToken);
        try
        {
            if (memoryId is not null) return memoryId;

            var name = configuration["AWSBedrockAgentCoreMemoryName"] ?? defaultMemoryName;
            var id = await FindMemory(name, cancellationToken) ?? await CreateMemory(name, cancellationToken);
            await WaitUntilActive(id, cancellationToken);
            return memoryId = id;
        }
        finally
        {
            memoryIdLock.Release();
        }
    }

    private async Task<string?> FindMemory(string name, CancellationToken cancellationToken)
    {
        string? nextToken = null;
        do
        {
            var page = await agentCoreControl.ListMemoriesAsync(new ListMemoriesRequest { NextToken = nextToken }, cancellationToken);
            // Memory ids are "{name}-{suffix}"; summaries don't carry the name itself.
            var match = page.Memories?.FirstOrDefault(m => m.Id.StartsWith(name + "-") && m.Status != MemoryStatus.DELETING && m.Status != MemoryStatus.FAILED);
            if (match is not null) return match.Id;
            nextToken = page.NextToken;
        } while (nextToken is not null);
        return null;
    }

    private async Task<string> CreateMemory(string name, CancellationToken cancellationToken)
    {
        logger.LogInformation("Creating AgentCore memory {MemoryName}", name);
        var response = await agentCoreControl.CreateMemoryAsync(new CreateMemoryRequest
        {
            Name = name,
            Description = "Memory for MyAgent",
            EventExpiryDuration = 30, // days of short-term event retention
            MemoryStrategies =
            [
                new MemoryStrategyInput { SemanticMemoryStrategy = new SemanticMemoryStrategyInput { Name = "Facts", NamespaceTemplates = ["/users/{actorId}/facts"] } },
                new MemoryStrategyInput { UserPreferenceMemoryStrategy = new UserPreferenceMemoryStrategyInput { Name = "Preferences", NamespaceTemplates = ["/users/{actorId}/preferences"] } },
                new MemoryStrategyInput { SummaryMemoryStrategy = new SummaryMemoryStrategyInput { Name = "Summaries", NamespaceTemplates = ["/summaries/{actorId}/{sessionId}"] } },
            ],
        }, cancellationToken);
        return response.Memory.Id;
    }

    private async Task WaitUntilActive(string id, CancellationToken cancellationToken)
    {
        while (true)
        {
            var memory = (await agentCoreControl.GetMemoryAsync(new GetMemoryRequest { MemoryId = id }, cancellationToken)).Memory;
            if (memory.Status == MemoryStatus.ACTIVE) return;
            if (memory.Status == MemoryStatus.FAILED) throw new InvalidOperationException($"AgentCore memory {id} failed: {memory.FailureReason}");
            logger.LogInformation("Waiting for AgentCore memory {MemoryId} to become active (status {Status})", id, memory.Status);
            await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
        }
    }
}

/// <summary>
/// Recalls long-term memories relevant to the user's input before each run and records the turn afterwards.
/// </summary>
/// <param name="actorId">Whose memories these are. Long-term records are scoped to this, across sessions.</param>
public class AgentCoreMemoryProvider(AgentCoreMemory memory, string actorId, ILogger<AgentCoreMemoryProvider> logger) : AIContextProvider
{
    private readonly ProviderSessionState<State> sessionState = new(
        _ => new State { SessionId = Guid.NewGuid().ToString() },
        nameof(AgentCoreMemoryProvider));

    public class State
    {
        public string SessionId { get; set; } = "";
    }

    // Without this the model insists it cannot remember anything across conversations.
    private const string memoryInstructions = "\nYou have long-term memory: what the user tells you is remembered automatically across conversations, so you don't need to do anything to store it.";

    protected override async ValueTask<AIContext> ProvideAIContextAsync(InvokingContext context, CancellationToken cancellationToken = default)
    {
        var query = string.Join("\n", (context.AIContext.Messages ?? []).Where(m => m.Role == ChatRole.User).Select(m => m.Text));
        if (string.IsNullOrWhiteSpace(query)) return new AIContext { Instructions = memoryInstructions };

        try
        {
            var records = await memory.Recall(actorId, query, cancellationToken: cancellationToken);
            if (records.Count == 0) return new AIContext { Instructions = memoryInstructions };

            var instructions = new StringBuilder(memoryInstructions)
                .AppendLine()
                .AppendLine("Things you remember about the user from earlier conversations (may be outdated; the current conversation takes precedence):");
            foreach (var record in records)
                instructions.Append("- ").AppendLine(record.Content?.Text);
            return new AIContext { Instructions = instructions.ToString() };
        }
        catch (Exception ex)
        {
            // Memory is an enhancement; never fail the run because recall didn't work.
            logger.LogWarning(ex, "Recalling memories for actor {ActorId} failed", actorId);
            return new AIContext();
        }
    }

    protected override async ValueTask StoreAIContextAsync(InvokedContext context, CancellationToken cancellationToken = default)
    {
        if (context.InvokeException is not null) return;
        var state = sessionState.GetOrInitializeState(context.Session);
        sessionState.SaveState(context.Session, state);

        try
        {
            await memory.AddTurn(actorId, state.SessionId, context.RequestMessages.Concat(context.ResponseMessages ?? []), cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Storing memory event for actor {ActorId} failed", actorId);
        }
    }
}
