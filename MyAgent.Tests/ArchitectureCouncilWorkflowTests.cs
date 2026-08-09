using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MyAgent.Tests;

/// <summary>
/// Covers how the council is registered and shaped, resolved from DI exactly as DevUI resolves it.
/// None of this needs a model, so none of it sits behind the paid test — it used to, which meant the
/// graph-stability guarantee went unchecked whenever credentials were absent.
/// </summary>
[TestClass]
[TestCategory("Offline")]
public sealed class ArchitectureCouncilWorkflowTests
{
    [TestMethod]
    [Timeout(30_000)]
    public void RegisteredWorkflow_CarriesItsDiKeyAsItsName()
    {
        using var host = StubHost();

        Workflow workflow = host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName);

        Assert.AreEqual(ArchitectureCouncil.WorkflowName, workflow.Name);
        Assert.AreEqual(ArchitectureCouncil.Description, workflow.Description);
    }

    [TestMethod]
    [Timeout(30_000)]
    public void TwoResolutions_DrawTheSameGraph()
    {
        using var host = StubHost();

        // The registration is transient, so the graph DevUI draws comes from a different instance
        // than the one that runs. DevUI matches a run's events to that graph by executor id, which
        // only works while the ids are stable across resolutions — hence the pinned agent ids.
        string[] drawn = ExecutorIdsOf(host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName));
        string[] ran = ExecutorIdsOf(host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName));

        CollectionAssert.AreEqual(drawn, ran,
            $"Two resolutions produced different executor ids, so DevUI cannot follow a run: [{string.Join(", ", drawn)}] vs [{string.Join(", ", ran)}]");
    }

    [TestMethod]
    [Timeout(30_000)]
    public void EveryParticipantIsItsOwnNodeInTheGraph()
    {
        using var host = StubHost();

        string[] ids = ExecutorIdsOf(host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName));

        // A participant's node id is "<agent name>_<agent id>". Distinct ids also matter for a
        // second reason: the group chat deduplicates its participants by agent id, so a collision
        // would quietly drop a panelist.
        foreach (var name in new[]
                 {
                     ArchitectureCouncil.CloudAdvocateName,
                     ArchitectureCouncil.OpenSourcePuristName,
                     ArchitectureCouncil.PrincipalArchitectName,
                 })
        {
            Assert.AreEqual(1, ids.Count(id => id.StartsWith(name, StringComparison.Ordinal)),
                $"Expected exactly one graph node for '{name}', in [{string.Join(", ", ids)}]");
        }
    }

    [TestMethod]
    [Timeout(30_000)]
    public void TheWorkflowIsTransient_BecauseARunTakesExclusiveOwnership()
    {
        using var host = StubHost();

        Workflow first = host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName);
        Workflow second = host.Services.GetRequiredKeyedService<Workflow>(ArchitectureCouncil.WorkflowName);

        // Sharing one instance between two concurrent readers makes the second run fail outright.
        Assert.AreNotSame(first, second, "A shared workflow instance breaks concurrent runs.");
    }

    /// <summary>The nodes of a workflow's graph, the way DevUI extracts them for its view.</summary>
    static string[] ExecutorIdsOf(Workflow workflow)
    {
        var ids = new HashSet<string> { workflow.StartExecutorId };
        foreach (var (sourceId, edges) in workflow.ReflectEdges())
        {
            ids.Add(sourceId);
            foreach (var sinkId in edges.SelectMany(edge => edge.Connection.SinkIds))
            {
                ids.Add(sinkId);
            }
        }

        return [.. ids.OrderBy(id => id, StringComparer.Ordinal)];
    }

    /// <summary>
    /// The real registration, with the chat client replaced. Registering the stub last wins, so the
    /// council itself is built exactly as it is in production — just with nothing to pay for.
    /// </summary>
    static IHost StubHost()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.AddArchitectureCouncil();
        builder.Services.AddKeyedSingleton<IChatClient>(ArchitectureCouncil.WorkflowName, (_, _) => new StubChatClient());
        return builder.Build();
    }
}
