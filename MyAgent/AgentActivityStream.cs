using System.Runtime.CompilerServices;
using System.Threading.Channels;
using AGUI.Abstractions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace MyAgent;

/// <summary>
/// Lets a tool put <see href="https://docs.ag-ui.com">AG-UI</see> events into the stream of the agent
/// run that called it, while the tool is still running. Resolved per run through
/// <see cref="Current"/>; there is one only on a streaming run of an agent built with
/// <see cref="AgentActivityStreamExtensions.UseActivityStream"/>, so a tool must treat it as optional.
/// </summary>
/// <remarks>
/// An event travels as an update whose raw representation is a <see cref="ChatResponseUpdate"/>
/// carrying the event as <em>its</em> raw representation. <c>AsChatResponseUpdate</c> unwraps the
/// outer layer, and AG-UI's mapper passes any update whose raw representation is a
/// <see cref="BaseEvent"/> through verbatim — so the event reaches the wire exactly as published,
/// and transports that know nothing of AG-UI see an update with no content and ignore it.
/// </remarks>
public sealed class AgentActivityPublisher
{
    const string RunOptionKey = "agui_activity_publisher";

    readonly ChannelWriter<AgentResponseUpdate> _writer;

    internal AgentActivityPublisher(ChannelWriter<AgentResponseUpdate> writer) => _writer = writer;

    /// <summary>The publisher of the agent run the caller is part of, if that run streams.</summary>
    public static AgentActivityPublisher? Current =>
        AIAgent.CurrentRunContext?.RunOptions?.AdditionalProperties?.TryGetValue(RunOptionKey, out var publisher) == true
            ? publisher as AgentActivityPublisher
            : null;

    /// <summary>
    /// Queues <paramref name="evt"/> behind whatever the run has produced so far. Never blocks, and
    /// after the run has ended the event is dropped: nobody is reading any more.
    /// </summary>
    public void Publish(BaseEvent evt) =>
        _writer.TryWrite(new AgentResponseUpdate { RawRepresentation = new ChatResponseUpdate { RawRepresentation = evt } });

    /// <summary>
    /// Adds <paramref name="usage"/> to the run's token count. Unlike <see cref="Publish"/> this is
    /// ordinary content, so every consumer of the run tallies it — AG-UI folds it into
    /// <c>RUN_FINISHED.usage</c>, grouped by <paramref name="modelId"/>.
    /// </summary>
    public void PublishUsage(UsageDetails usage, string? modelId) =>
        _writer.TryWrite(new AgentResponseUpdate
        {
            // Carried by the raw update because the agent-level conversion back to a chat update
            // keeps the raw one whole, model id included, and would otherwise drop the model id.
            RawRepresentation = new ChatResponseUpdate { Contents = [new UsageContent(usage)], ModelId = modelId },
            Contents = [new UsageContent(usage)],
        });

    internal static void Attach(AgentRunOptions options, AgentActivityPublisher publisher)
    {
        options.AdditionalProperties ??= [];
        options.AdditionalProperties[RunOptionKey] = publisher;
    }
}

public static class AgentActivityStreamExtensions
{
    extension(AIAgentBuilder agentBuilder)
    {
        /// <summary>Gives every streaming run an <see cref="AgentActivityPublisher"/> its tools can publish to.</summary>
        public AIAgentBuilder UseActivityStream()
            => agentBuilder.Use((inner, _) => new ActivityStreamMiddleware(inner));
    }

    /// <summary>
    /// Merges the run's own updates and its tools' events into one stream. The merge is the point:
    /// while a tool runs, the function-invoking client yields nothing, so an event a tool published
    /// would otherwise wait for the tool to return — by which time following its progress is moot.
    /// </summary>
    private sealed class ActivityStreamMiddleware(AIAgent inner) : DelegatingAIAgent(inner)
    {
        protected override async IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session = null,
            AgentRunOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            options ??= new AgentRunOptions();

            var channel = Channel.CreateUnbounded<AgentResponseUpdate>(new UnboundedChannelOptions { SingleReader = true });
            AgentActivityPublisher.Attach(options, new AgentActivityPublisher(channel.Writer));

            // Cancelled when the caller stops reading, so a disconnect still stops the run spending.
            using var pumpCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var pump = Task.Run(async () =>
            {
                try
                {
                    await foreach (var update in base.RunCoreStreamingAsync(messages, session, options, pumpCancellation.Token))
                    {
                        await channel.Writer.WriteAsync(update, pumpCancellation.Token);
                    }

                    channel.Writer.TryComplete();
                }
                catch (Exception ex)
                {
                    // Completing with the exception rethrows it to the reader, which is where the
                    // caller decides what a failed run looks like.
                    channel.Writer.TryComplete(ex);
                }
            }, CancellationToken.None);

            try
            {
                await foreach (var update in channel.Reader.ReadAllAsync(cancellationToken))
                {
                    yield return update;
                }
            }
            finally
            {
                await pumpCancellation.CancelAsync();
                await pump; // never throws: every failure completes the channel instead
            }
        }
    }
}
