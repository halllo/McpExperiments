using System.ComponentModel;
using System.Text;
using System.Text.Json;
using AGUI.Abstractions;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;

namespace MyAgent;

/// <summary>
/// The planner–executor pattern as a workflow, offered to an agent as a single tool: a planner breaks
/// a goal into steps, an executor works through them one at a time with the agent's own tools, and a
/// synthesizer turns the step results into one answer. While it runs, the tool publishes the plan's
/// progress as AG-UI <c>ACTIVITY_SNAPSHOT</c> events (see <see cref="AgentActivityPublisher"/>), so a
/// front end can draw the plan and tick its steps off as they happen.
/// </summary>
/// <remarks>
/// Every snapshot carries the whole state and replaces the previous one under the same message id,
/// so a client that joins late or drops a frame still ends up right. The content is
/// <c>{ goal, status, steps: [{ title, status, result }], result }</c>, with <c>status</c> one of
/// <see cref="Status"/>'s values.
/// </remarks>
public static class PlannerExecutor
{
    /// <summary>Name of the workflow.</summary>
    public const string WorkflowName = "planner_executor";

    /// <summary>Name of the tool an agent calls.</summary>
    public const string ToolName = "plan_and_execute";

    /// <summary>The <c>activityType</c> of every snapshot the tool publishes.</summary>
    public const string ActivityType = "planner_executor";

    /// <summary>
    /// The most steps a plan may have. Each step is at least one model call, so this bounds what one
    /// call of the tool can cost; a longer plan is cut, not rejected.
    /// </summary>
    public const int MaxSteps = 6;

    /// <summary>The longest step result a snapshot carries. The tool's own result is never cut.</summary>
    public const int MaxSnapshotResultLength = 2_000;

    /// <summary>What the tool returns when the plan did not complete. Deliberately free of detail, which is logged.</summary>
    public const string FailedResult = "The plan could not be completed.";

    public const string PlannerName = "planner";
    public const string StepExecutorName = "step_executor";
    public const string SynthesizerName = "synthesizer";

    /// <summary>The values of <c>status</c>, on the plan and on each step.</summary>
    public static class Status
    {
        public const string Planning = "planning";
        public const string Executing = "executing";
        public const string Synthesizing = "synthesizing";
        public const string Pending = "pending";
        public const string Running = "running";
        public const string Completed = "completed";
        public const string Failed = "failed";
    }

    /// <summary>
    /// The tool. The executor gets <paramref name="executorTools"/> — never this tool itself, so a
    /// step cannot start a plan of its own.
    /// </summary>
    public static AIFunction CreateTool(IChatClient chatClient, IList<AITool> executorTools) =>
        AIFunctionFactory.Create(
            method: (IServiceProvider services, [Description("The goal to plan and carry out, with everything the steps need to know.")] string goal, CancellationToken cancellationToken) =>
                RunAsync(goal, chatClient, executorTools, services, cancellationToken),
            name: ToolName,
            description: "Plan a task that needs several distinct steps (for example: gather data, compute, then summarize) and carry the steps out one by one. Returns the final answer.");

    /// <param name="runProperties">
    /// Shared by every step the executor runs, as its run options' additional properties — which is
    /// where the code interpreter keeps its session, so the steps share one sandbox.
    /// </param>
    public static Workflow Create(IChatClient chatClient, IList<AITool> executorTools, IServiceProvider? services = null, AdditionalPropertiesDictionary? runProperties = null)
    {
        // Ids pinned for the same reason ArchitectureCouncil pins its own: a node's id is
        // "<agent name>_<agent id>", and a fresh GUID per build would make the graph unstable.
        AIAgent planner = chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Id = PlannerName,
            Name = PlannerName,
            Description = "Breaks a goal into steps.",
            ChatOptions = new ChatOptions
            {
                Temperature = 0,
                Instructions = $"""
                    You plan work for an executor that carries out one step at a time.
                    Break the goal into at most {MaxSteps} concrete, sequential steps. Each step must be
                    achievable on its own, given the results of the steps before it. Use as few steps as
                    the goal needs. Do not carry out any step yourself.
                    """,
            },
        }, services: services);

        AIAgent executor = chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Id = StepExecutorName,
            Name = StepExecutorName,
            Description = "Carries out one step of a plan.",
            ChatOptions = new ChatOptions
            {
                Temperature = 0,
                Instructions = """
                    You carry out exactly one step of a plan, using your tools where they help.
                    Reply with the step's result only: concise, factual, and complete enough for the
                    steps after it to build on.
                    """,
                Tools = executorTools,
            },
        }, services: services);

        AIAgent synthesizer = chatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Id = SynthesizerName,
            Name = SynthesizerName,
            Description = "Turns the step results into the final answer.",
            ChatOptions = new ChatOptions
            {
                Temperature = 0,
                Instructions = """
                    You are given a goal and the results of the steps taken towards it.
                    Answer the goal directly from those results. Do not describe the steps.
                    """,
            },
        }, services: services);

        var planning = new PlanningExecutor(planner);
        var execution = new StepExecutor(executor, synthesizer, runProperties);

        return new WorkflowBuilder(planning)
            .AddEdge(planning, execution)
            .WithOutputFrom(execution)
            .WithName(WorkflowName)
            .WithDescription("Plans a goal as steps, carries them out one by one, and answers from the results.")
            .Build();
    }

    /// <summary>
    /// Runs the workflow for <paramref name="goal"/>, publishing a snapshot on every change of state,
    /// and returns the final answer — or <see cref="FailedResult"/>, since the result reaches the wire
    /// as a tool result and an exception's text can name hosts or keys.
    /// </summary>
    public static async Task<string> RunAsync(string goal, IChatClient chatClient, IList<AITool> executorTools, IServiceProvider services, CancellationToken cancellationToken)
    {
        var logger = services.GetService<ILoggerFactory>()?.CreateLogger("MyAgent.PlannerExecutor") ?? NullLogger.Instance;
        var publisher = AgentActivityPublisher.Current;

        // Keyed by the call, so a client can place the card beside the tool call that produced it.
        var callId = FunctionInvokingChatClient.CurrentContext?.CallContent.CallId ?? Guid.NewGuid().ToString("N");
        var activity = new PlanActivity(goal, $"activity-{callId}");

        // Share the calling run's properties when there is one: its code interpreter session is then
        // the steps' too, and the calling agent's own middleware closes it when the run ends.
        var outerOptions = AIAgent.CurrentRunContext?.RunOptions;
        AdditionalPropertiesDictionary runProperties;
        if (outerOptions is not null)
        {
            runProperties = outerOptions.AdditionalProperties ??= [];
        }
        else
        {
            runProperties = [];
        }

        void Publish() => publisher?.Publish(activity.Snapshot());

        Publish();

        string? output = null;
        try
        {
            var workflow = Create(chatClient, executorTools, services, runProperties);
            await using StreamingRun run = await InProcessExecution.RunStreamingAsync(workflow, goal, cancellationToken: cancellationToken);
            await using var cancelRun = cancellationToken.Register(() => _ = run.CancelRunAsync().AsTask());

            await foreach (WorkflowEvent evt in run.WatchStreamAsync(cancellationToken))
            {
                var changed = true;
                switch (evt)
                {
                    case PlanCreatedEvent created:
                        activity.Planned(created.Steps);
                        break;
                    case StepStartedEvent started:
                        activity.StepStarted(started.Index);
                        break;
                    case StepCompletedEvent completed:
                        activity.StepCompleted(completed.Index, completed.Result);
                        break;
                    case StepFailedEvent failed:
                        activity.StepFailed(failed.Index);
                        break;
                    case SynthesisStartedEvent:
                        activity.Synthesizing();
                        break;
                    case WorkflowOutputEvent outputEvent when outputEvent.Is<string>(out var text):
                        output = text;
                        changed = false;
                        break;
                    case ExecutorFailedEvent executorFailed:
                        logger.LogError(executorFailed.Data, "Planner-executor step {ExecutorId} failed.", executorFailed.ExecutorId);
                        output = null;
                        changed = false;
                        break;
                    case WorkflowErrorEvent workflowError:
                        logger.LogError(workflowError.Exception, "Planner-executor workflow failed.");
                        output = null;
                        changed = false;
                        break;
                    default:
                        changed = false;
                        break;
                }

                if (changed)
                {
                    Publish();
                }

                if (evt is ExecutorFailedEvent or WorkflowErrorEvent)
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Planner-executor run threw.");
            output = null;
        }
        finally
        {
            // Nobody else will close a sandbox the steps opened outside an agent run.
            if (outerOptions is null && services.GetService<CodeInterpreter>() is { } codeInterpreter)
            {
                await codeInterpreter.CloseCodeInterpreter(new AgentRunOptions { AdditionalProperties = runProperties }, CancellationToken.None);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (output is null)
        {
            activity.Fail();
            Publish();
            return FailedResult;
        }

        activity.Complete(output);
        Publish();
        return output;
    }

    // --- the workflow's messages and events ---------------------------------------------------------

    /// <summary>The planner's structured output.</summary>
    public sealed record Plan([property: Description("The steps, in the order they are carried out.")] IReadOnlyList<PlanStep> Steps);

    public sealed record PlanStep(
        [property: Description("A short title for the step, a few words.")] string Title,
        [property: Description("What the executor must do in this step.")] string Instructions);

    /// <summary>What the planner hands the executor: the goal travels with its plan.</summary>
    public sealed record PlannedGoal(string Goal, IReadOnlyList<PlanStep> Steps);

    public sealed class PlanCreatedEvent(IReadOnlyList<PlanStep> steps) : WorkflowEvent(steps)
    {
        public IReadOnlyList<PlanStep> Steps => steps;
    }

    public sealed class StepStartedEvent(int index) : WorkflowEvent(index)
    {
        public int Index => index;
    }

    public sealed class StepCompletedEvent(int index, string result) : WorkflowEvent(result)
    {
        public int Index => index;
        public string Result => result;
    }

    /// <summary>Carries no detail on purpose: the exception follows as an <see cref="ExecutorFailedEvent"/> and is logged.</summary>
    public sealed class StepFailedEvent(int index) : WorkflowEvent(index)
    {
        public int Index => index;
    }

    public sealed class SynthesisStartedEvent() : WorkflowEvent;

    // --- executors ----------------------------------------------------------------------------------

    sealed class PlanningExecutor(AIAgent planner) : Executor<string, PlannedGoal>("planning")
    {
        public override async ValueTask<PlannedGoal> HandleAsync(string goal, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            var response = await planner.RunAsync<Plan>($"Goal: {goal}", cancellationToken: cancellationToken);

            var steps = response.Result?.Steps?
                .Where(step => !string.IsNullOrWhiteSpace(step?.Title))
                .Take(MaxSteps)
                .ToArray() ?? [];

            if (steps.Length == 0)
            {
                throw new InvalidOperationException("The planner produced no steps.");
            }

            await context.AddEventAsync(new PlanCreatedEvent(steps), cancellationToken);
            return new PlannedGoal(goal, steps);
        }
    }

    [YieldsOutput(typeof(string))]
    sealed class StepExecutor(AIAgent executor, AIAgent synthesizer, AdditionalPropertiesDictionary? runProperties)
        : Executor<PlannedGoal>("execution")
    {
        public override async ValueTask HandleAsync(PlannedGoal plan, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            var results = new List<string>();

            for (var index = 0; index < plan.Steps.Count; index++)
            {
                await context.AddEventAsync(new StepStartedEvent(index), cancellationToken);

                string result;
                try
                {
                    var response = await executor.RunAsync(
                        StepPrompt(plan, index, results),
                        options: runProperties is null ? null : new AgentRunOptions { AdditionalProperties = runProperties },
                        cancellationToken: cancellationToken);
                    result = response.Text;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    await context.AddEventAsync(new StepFailedEvent(index), cancellationToken);
                    throw;
                }

                results.Add(result);
                await context.AddEventAsync(new StepCompletedEvent(index, result), cancellationToken);
            }

            await context.AddEventAsync(new SynthesisStartedEvent(), cancellationToken);
            var answer = await synthesizer.RunAsync(SynthesisPrompt(plan, results), cancellationToken: cancellationToken);
            await context.YieldOutputAsync(answer.Text, cancellationToken);
        }

        static string StepPrompt(PlannedGoal plan, int index, List<string> results)
        {
            var prompt = new StringBuilder();
            prompt.AppendLine($"Goal: {plan.Goal}");
            AppendResults(prompt, plan, results);
            var step = plan.Steps[index];
            prompt.AppendLine();
            prompt.AppendLine($"Your step ({index + 1} of {plan.Steps.Count}): {step.Title}");
            prompt.AppendLine(step.Instructions);
            return prompt.ToString();
        }

        static string SynthesisPrompt(PlannedGoal plan, List<string> results)
        {
            var prompt = new StringBuilder();
            prompt.AppendLine($"Goal: {plan.Goal}");
            AppendResults(prompt, plan, results);
            return prompt.ToString();
        }

        static void AppendResults(StringBuilder prompt, PlannedGoal plan, List<string> results)
        {
            if (results.Count == 0)
            {
                return;
            }

            prompt.AppendLine();
            prompt.AppendLine("Results so far:");
            for (var i = 0; i < results.Count; i++)
            {
                prompt.AppendLine($"{i + 1}. {plan.Steps[i].Title}: {results[i]}");
            }
        }
    }

    // --- the activity a client follows --------------------------------------------------------------

    /// <summary>The state behind the snapshots. Only ever touched by the tool's own loop.</summary>
    sealed class PlanActivity(string goal, string messageId)
    {
        sealed class Step(string title)
        {
            public string Title { get; } = title;
            public string Status { get; set; } = PlannerExecutor.Status.Pending;
            public string? Result { get; set; }
        }

        readonly List<Step> _steps = [];
        string _status = Status.Planning;
        string? _result;

        public void Planned(IEnumerable<PlanStep> steps)
        {
            _steps.Clear();
            _steps.AddRange(steps.Select(step => new Step(step.Title)));
            _status = Status.Executing;
        }

        public void StepStarted(int index) => _steps[index].Status = Status.Running;

        public void StepCompleted(int index, string result)
        {
            _steps[index].Status = Status.Completed;
            _steps[index].Result = result.Length > MaxSnapshotResultLength ? result[..MaxSnapshotResultLength] + "…" : result;
        }

        public void StepFailed(int index) => _steps[index].Status = Status.Failed;

        public void Synthesizing() => _status = Status.Synthesizing;

        public void Complete(string result)
        {
            _status = Status.Completed;
            _result = result;
        }

        public void Fail()
        {
            _status = Status.Failed;

            // A step still marked running stopped when the run did.
            foreach (var step in _steps.Where(step => step.Status == Status.Running))
            {
                step.Status = Status.Failed;
            }
        }

        public ActivitySnapshotEvent Snapshot() => new()
        {
            MessageId = messageId,
            ActivityType = ActivityType,
            Replace = true,
            Content = JsonSerializer.SerializeToElement(new
            {
                goal,
                status = _status,
                steps = _steps.Select(step => new { title = step.Title, status = step.Status, result = step.Result }),
                result = _result,
            }, WorkflowAguiStream.Json),
        };
    }
}
