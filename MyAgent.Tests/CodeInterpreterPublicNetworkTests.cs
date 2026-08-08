using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Amazon.BedrockAgentCoreControl;
using Amazon.BedrockAgentCoreControl.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Text;
using System.Text.Json;

namespace MyAgent.Tests;

/// <summary>
/// Proves that a custom code interpreter created with networkMode=PUBLIC can reach the public
/// internet (curl against pokeapi.co), while the built-in aws.codeinterpreter.v1 — which runs in
/// SANDBOX network mode — cannot, and compares the capabilities (preinstalled Python libraries,
/// language runtimes/frameworks, ability to install packages at runtime) of the two.
///
/// The custom interpreter is created on demand and then reused across runs: it is looked up by
/// name via ListCodeInterpreters, so only the first run pays the create + CREATING→READY wait.
/// The equivalent AWS CLI call is:
///
///   aws bedrock-agentcore-control create-code-interpreter --region eu-central-1 \
///     --name PublicNetworkTestCI \
///     --network-configuration '{"networkMode":"PUBLIC"}'
///
/// Delete it again with:
///
///   aws bedrock-agentcore-control delete-code-interpreter --region eu-central-1 \
///     --code-interpreter-id PublicNetworkTestCI-XXXXXXXXXX
/// </summary>
[TestClass, DoNotParallelize]
public sealed class CodeInterpreterPublicNetworkTests
{
    // create-code-interpreter name pattern: [a-zA-Z][a-zA-Z0-9_]{0,47} — no hyphens.
    private const string PublicInterpreterName = "PublicNetworkTestCI";
    private const string SandboxInterpreterId = "aws.codeinterpreter.v1";
    private const string PokeApiCommand = "curl --location 'https://pokeapi.co/api/v2/pokemon/ditto/'";

    public required TestContext TestContext { get; set; }

    private sealed record CommandResult(bool IsError, int? ExitCode, string Text);

    // ── Tests ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The PUBLIC-network interpreter curls the PokeAPI and gets back the Ditto JSON document.
    /// </summary>
    [TestMethod]
    public async Task PublicNetworkInterpreter_Curl_ReturnsDittoJson()
    {
        var ct = TestContext.CancellationToken;
        var interpreterId = await EnsurePublicNetworkInterpreter(ct);

        var client = CodeInterpreterFileOperationTests.BuildClient();
        var sessionId = await StartSession(client, interpreterId, ct);
        try
        {
            var result = await ExecuteCommand(client, interpreterId, sessionId, PokeApiCommand, ct);
            TestContext.WriteLine($"isError={result.IsError} exitCode={result.ExitCode}");
            TestContext.WriteLine($"output={Truncate(result.Text, 2000)}");

            Assert.IsFalse(result.IsError, $"curl reported an error: {Truncate(result.Text, 2000)}");
            Assert.AreEqual(0, result.ExitCode, $"curl exited non-zero: {Truncate(result.Text, 2000)}");

            using var json = JsonDocument.Parse(ExtractJson(result.Text));
            Assert.AreEqual("ditto", json.RootElement.GetProperty("name").GetString());
            Assert.AreEqual(132, json.RootElement.GetProperty("id").GetInt32());
        }
        finally { await StopSession(client, interpreterId, sessionId); }
    }

    /// <summary>
    /// Counter-proof: the built-in interpreter runs in SANDBOX network mode, so the very same curl
    /// call cannot reach pokeapi.co. This is what makes the PUBLIC network configuration the cause
    /// of the test above passing.
    /// </summary>
    [TestMethod]
    public async Task SandboxInterpreter_Curl_CannotReachPublicInternet()
    {
        var ct = TestContext.CancellationToken;
        var client = CodeInterpreterFileOperationTests.BuildClient();
        var sessionId = await StartSession(client, SandboxInterpreterId, ct);
        try
        {
            var result = await ExecuteCommand(client, SandboxInterpreterId, sessionId, PokeApiCommand, ct);
            TestContext.WriteLine($"isError={result.IsError} exitCode={result.ExitCode}");
            TestContext.WriteLine($"output={Truncate(result.Text, 2000)}");

            Assert.IsFalse(result.Text.Contains("\"name\": \"ditto\"", StringComparison.Ordinal)
                || result.Text.Contains("\"name\":\"ditto\"", StringComparison.Ordinal),
                $"Expected the sandbox interpreter to have no internet access, but curl returned the "
                + $"PokeAPI document: {Truncate(result.Text, 2000)}");
            Assert.IsTrue(result.IsError || result.ExitCode != 0,
                $"Expected curl to fail without public network access, but it succeeded: "
                + $"{Truncate(result.Text, 2000)}");
        }
        finally { await StopSession(client, SandboxInterpreterId, sessionId); }
    }

    // ── Capability comparison: PUBLIC vs SANDBOX ─────────────────────────────

    /// <summary>
    /// Compares the preinstalled Python libraries of both interpreters. Both run the same sandbox
    /// image, so the library inventory is expected to be identical — the network mode changes what
    /// the sandbox may reach, not what it ships with.
    /// </summary>
    [TestMethod]
    public async Task Compare_InstalledPythonLibraries_PublicVsSandbox()
    {
        var ct = TestContext.CancellationToken;
        var interpreterId = await EnsurePublicNetworkInterpreter(ct);

        var publicPackages = ParsePipList(await RunSingle(interpreterId, PipListCommand, ct));
        var sandboxPackages = ParsePipList(await RunSingle(SandboxInterpreterId, PipListCommand, ct));

        TestContext.WriteLine($"PUBLIC  : {publicPackages.Count} python packages");
        TestContext.WriteLine($"SANDBOX : {sandboxPackages.Count} python packages");
        TestContext.WriteLine("packages: " + string.Join(", ",
            publicPackages.OrderBy(p => p.Key).Select(p => $"{p.Key}=={p.Value}")));

        Assert.IsGreaterThan(0, publicPackages.Count, "pip list returned no packages for the PUBLIC interpreter");
        Assert.IsGreaterThan(0, sandboxPackages.Count, "pip list returned no packages for the SANDBOX interpreter");

        var onlyPublic = publicPackages.Keys.Except(sandboxPackages.Keys).Order().ToList();
        var onlySandbox = sandboxPackages.Keys.Except(publicPackages.Keys).Order().ToList();
        var versionMismatches = publicPackages.Keys.Intersect(sandboxPackages.Keys)
            .Where(name => publicPackages[name] != sandboxPackages[name])
            .Select(name => $"{name}: PUBLIC={publicPackages[name]} SANDBOX={sandboxPackages[name]}")
            .Order()
            .ToList();

        TestContext.WriteLine($"only in PUBLIC : [{string.Join(", ", onlyPublic)}]");
        TestContext.WriteLine($"only in SANDBOX: [{string.Join(", ", onlySandbox)}]");
        TestContext.WriteLine($"version diffs  : [{string.Join(", ", versionMismatches)}]");

        Assert.IsEmpty(onlyPublic, $"Packages present only in the PUBLIC interpreter: {string.Join(", ", onlyPublic)}");
        Assert.IsEmpty(onlySandbox, $"Packages present only in the SANDBOX interpreter: {string.Join(", ", onlySandbox)}");
        Assert.IsEmpty(versionMismatches, $"Package version differences: {string.Join("; ", versionMismatches)}");
    }

    /// <summary>
    /// Compares the language runtimes / frameworks on PATH in both interpreters, again expecting an
    /// identical inventory across network modes.
    /// </summary>
    [TestMethod]
    public async Task Compare_InstalledFrameworks_PublicVsSandbox()
    {
        var ct = TestContext.CancellationToken;
        var interpreterId = await EnsurePublicNetworkInterpreter(ct);

        var publicTools = ParseToolProbe(await RunSingle(interpreterId, FrameworkProbeCommand, ct));
        var sandboxTools = ParseToolProbe(await RunSingle(SandboxInterpreterId, FrameworkProbeCommand, ct));

        TestContext.WriteLine($"{"tool",-12} {"PUBLIC",-40} SANDBOX");
        foreach (var tool in ProbedTools)
            TestContext.WriteLine($"{tool,-12} {publicTools.GetValueOrDefault(tool, "?"),-40} " +
                                  $"{sandboxTools.GetValueOrDefault(tool, "?")}");

        CollectionAssert.AreEquivalent(ProbedTools, publicTools.Keys.ToList(),
            "The framework probe did not report every tool for the PUBLIC interpreter");

        var differences = ProbedTools
            .Where(tool => publicTools.GetValueOrDefault(tool) != sandboxTools.GetValueOrDefault(tool))
            .Select(tool => $"{tool}: PUBLIC=[{publicTools.GetValueOrDefault(tool)}] " +
                            $"SANDBOX=[{sandboxTools.GetValueOrDefault(tool)}]")
            .ToList();
        Assert.IsEmpty(differences, $"Framework differences between the two interpreters: {string.Join("; ", differences)}");
    }

    /// <summary>
    /// The capability that the public network actually unlocks: pulling a library that is not part
    /// of the image from PyPI at runtime and importing it.
    /// </summary>
    [TestMethod]
    public async Task PublicNetworkInterpreter_PipInstall_AddsLibraryFromPyPI()
    {
        var ct = TestContext.CancellationToken;
        var interpreterId = await EnsurePublicNetworkInterpreter(ct);

        var client = CodeInterpreterFileOperationTests.BuildClient();
        var sessionId = await StartSession(client, interpreterId, ct);
        try
        {
            var before = await ExecuteCommand(client, interpreterId, sessionId, ImportProbeCommand, ct);
            TestContext.WriteLine($"before install: exitCode={before.ExitCode} output={before.Text.Trim()}");
            Assert.AreNotEqual(0, before.ExitCode,
                $"'{PipInstallPackage}' is already part of the image, so this test cannot prove anything");

            var install = await ExecuteCommand(client, interpreterId, sessionId, PipInstallCommand, ct);
            TestContext.WriteLine($"pip install: exitCode={install.ExitCode} output={Truncate(install.Text, 2000)}");
            Assert.AreEqual(0, install.ExitCode, $"pip install failed: {Truncate(install.Text, 2000)}");

            var after = await ExecuteCommand(client, interpreterId, sessionId, ImportProbeCommand, ct);
            TestContext.WriteLine($"after install: exitCode={after.ExitCode} output={after.Text.Trim()}");
            Assert.AreEqual(0, after.ExitCode,
                $"'{PipInstallPackage}' could not be imported after installing it: {Truncate(after.Text, 2000)}");
        }
        finally { await StopSession(client, interpreterId, sessionId); }
    }

    /// <summary>
    /// Counter-proof: without public network access, the same pip install cannot reach PyPI.
    /// </summary>
    [TestMethod]
    public async Task SandboxInterpreter_PipInstall_CannotReachPyPI()
    {
        var ct = TestContext.CancellationToken;
        var client = CodeInterpreterFileOperationTests.BuildClient();
        var sessionId = await StartSession(client, SandboxInterpreterId, ct);
        try
        {
            var install = await ExecuteCommand(client, SandboxInterpreterId, sessionId, PipInstallCommand, ct);
            TestContext.WriteLine($"pip install: exitCode={install.ExitCode} output={Truncate(install.Text, 2000)}");
            Assert.AreNotEqual(0, install.ExitCode,
                $"Expected pip install to fail without public network access, but it succeeded: "
                + Truncate(install.Text, 2000));

            var after = await ExecuteCommand(client, SandboxInterpreterId, sessionId, ImportProbeCommand, ct);
            TestContext.WriteLine($"after install: exitCode={after.ExitCode} output={after.Text.Trim()}");
            Assert.AreNotEqual(0, after.ExitCode, $"'{PipInstallPackage}' unexpectedly importable in the sandbox");
        }
        finally { await StopSession(client, SandboxInterpreterId, sessionId); }
    }

    // ── Capability probes ────────────────────────────────────────────────────

    private const string PipListCommand = "python3 -m pip list --format=json";

    // Small pure-python package that is not part of the sandbox image.
    private const string PipInstallPackage = "cowsay";
    private const string PipInstallCommand = $"python3 -m pip install --quiet --disable-pip-version-check {PipInstallPackage}";
    private const string ImportProbeCommand = $"python3 -c 'import {PipInstallPackage}; print({PipInstallPackage}.__name__)'";

    private static readonly List<string> ProbedTools =
        ["python3", "pip", "node", "npm", "java", "dotnet", "go", "gcc", "make", "git",
         "curl", "wget", "jq", "ruby", "perl", "php", "rustc", "sqlite3", "ffmpeg", "pandoc"];

    // Prints one "<tool>\t<version>" line per tool, "-" when the tool is not on PATH. The version is
    // the first non-empty line of `--version` (perl, for one, leads with a blank line).
    private static readonly string FrameworkProbeCommand = $$"""
        for tool in {{string.Join(" ", ProbedTools)}}; do
          if command -v "$tool" >/dev/null 2>&1; then
            version=$("$tool" --version 2>&1 | awk 'NF{print; exit}')
            printf '%s\t%s\n' "$tool" "${version:-installed}"
          else
            printf '%s\t-\n' "$tool"
          fi
        done
        """;

    /// <summary>Runs one command in a throwaway session on the given interpreter.</summary>
    async Task<CommandResult> RunSingle(string interpreterId, string command, CancellationToken ct)
    {
        var client = CodeInterpreterFileOperationTests.BuildClient();
        var sessionId = await StartSession(client, interpreterId, ct);
        try { return await ExecuteCommand(client, interpreterId, sessionId, command, ct); }
        finally { await StopSession(client, interpreterId, sessionId); }
    }

    /// <summary>Turns `pip list --format=json` output into a name → version map.</summary>
    Dictionary<string, string> ParsePipList(CommandResult result)
    {
        Assert.AreEqual(0, result.ExitCode, $"pip list failed: {Truncate(result.Text, 2000)}");
        using var json = JsonDocument.Parse(ExtractJsonArray(result.Text));
        return json.RootElement.EnumerateArray().ToDictionary(
            e => e.GetProperty("name").GetString()!,
            e => e.GetProperty("version").GetString()!,
            StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Turns the tab-separated framework probe output into a tool → version map.</summary>
    Dictionary<string, string> ParseToolProbe(CommandResult result)
    {
        Assert.AreEqual(0, result.ExitCode, $"framework probe failed: {Truncate(result.Text, 2000)}");
        return result.Text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('\t', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0], parts => parts[1]);
    }

    // ── Control-plane: find or create the PUBLIC-network interpreter ─────────

    static IAmazonBedrockAgentCoreControl BuildControlClient()
    {
        var config = Program.BuildHost().Services.GetRequiredService<IConfiguration>();
        return new AmazonBedrockAgentCoreControlClient(
            awsAccessKeyId: config["AWSBedrockAccessKeyId"],
            awsSecretAccessKey: config["AWSBedrockSecretAccessKey"],
            region: Amazon.RegionEndpoint.GetBySystemName(config["AWSBedrockRegion"]));
    }

    async Task<string> EnsurePublicNetworkInterpreter(CancellationToken ct)
    {
        var control = BuildControlClient();

        var existing = await FindByName(control, PublicInterpreterName, ct);
        if (existing is not null)
        {
            TestContext.WriteLine($"Reusing existing code interpreter {existing} ({PublicInterpreterName})");
            await WaitUntilReady(control, existing, ct);
            return existing;
        }

        var created = await control.CreateCodeInterpreterAsync(new CreateCodeInterpreterRequest
        {
            Name = PublicInterpreterName,
            Description = "Code interpreter with public internet access (integration tests)",
            NetworkConfiguration = new CodeInterpreterNetworkConfiguration
            {
                NetworkMode = CodeInterpreterNetworkMode.PUBLIC,
            },
        }, ct);

        TestContext.WriteLine($"Created code interpreter {created.CodeInterpreterId} status={created.Status}");
        await WaitUntilReady(control, created.CodeInterpreterId, ct);
        return created.CodeInterpreterId;
    }

    static async Task<string?> FindByName(IAmazonBedrockAgentCoreControl control, string name, CancellationToken ct)
    {
        string? nextToken = null;
        do
        {
            var page = await control.ListCodeInterpretersAsync(new ListCodeInterpretersRequest
            {
                Type = ResourceType.CUSTOM,
                MaxResults = 100,
                NextToken = nextToken,
            }, ct);

            var match = (page.CodeInterpreterSummaries ?? [])
                .FirstOrDefault(s => s.Name == name && s.Status != CodeInterpreterStatus.DELETED
                                                    && s.Status != CodeInterpreterStatus.DELETING);
            if (match is not null) return match.CodeInterpreterId;

            nextToken = page.NextToken;
        }
        while (!string.IsNullOrEmpty(nextToken));

        return null;
    }

    async Task WaitUntilReady(IAmazonBedrockAgentCoreControl control, string interpreterId, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow.AddMinutes(3);
        while (true)
        {
            var get = await control.GetCodeInterpreterAsync(new GetCodeInterpreterRequest
            {
                CodeInterpreterId = interpreterId,
            }, ct);

            if (get.Status == CodeInterpreterStatus.READY)
            {
                Assert.AreEqual(CodeInterpreterNetworkMode.PUBLIC, get.NetworkConfiguration?.NetworkMode,
                    $"Code interpreter '{interpreterId}' is not configured for public network access");
                TestContext.WriteLine($"Code interpreter {interpreterId} is READY (networkMode=PUBLIC)");
                return;
            }

            Assert.AreNotEqual(CodeInterpreterStatus.CREATE_FAILED, get.Status,
                $"Code interpreter '{interpreterId}' failed to create: {get.FailureReason}");
            Assert.IsLessThan(deadline, DateTime.UtcNow,
                $"Code interpreter '{interpreterId}' did not become READY (last status: {get.Status})");

            TestContext.WriteLine($"Code interpreter {interpreterId} status={get.Status}, waiting…");
            await Task.Delay(TimeSpan.FromSeconds(3), ct);
        }
    }

    // ── Data-plane helpers ───────────────────────────────────────────────────

    static async Task<string> StartSession(IAmazonBedrockAgentCore client, string interpreterId, CancellationToken ct)
    {
        var started = await client.StartCodeInterpreterSessionAsync(new StartCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = interpreterId,
            Name = "PublicNetworkTest_" + Guid.NewGuid(),
            SessionTimeoutSeconds = 300,
        }, ct);
        return started.SessionId;
    }

    static Task StopSession(IAmazonBedrockAgentCore client, string interpreterId, string sessionId) =>
        client.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = interpreterId,
            SessionId = sessionId,
        });

    static async Task<CommandResult> ExecuteCommand(
        IAmazonBedrockAgentCore client, string interpreterId, string sessionId, string command, CancellationToken ct)
    {
        var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = interpreterId,
            SessionId = sessionId,
            Name = ToolName.ExecuteCommand,
            Arguments = new ToolArguments { Command = command },
        }, ct);

        var text = new StringBuilder();
        var isError = false;
        int? exitCode = null;
        await foreach (var message in response.Stream.WithCancellation(ct))
        {
            if (message is not CodeInterpreterResult r) continue;
            isError |= r.IsError == true;
            exitCode ??= r.StructuredContent?.ExitCode;
            foreach (var content in r.Content ?? [])
                text.Append(content.Text);
        }
        return new CommandResult(isError, exitCode, text.ToString());
    }

    /// <summary>Pulls the JSON document out of curl output (which also carries the progress meter).</summary>
    static string ExtractJson(string output)
    {
        var start = output.IndexOf('{');
        var end = output.LastIndexOf('}');
        return start >= 0 && end > start ? output[start..(end + 1)] : output;
    }

    /// <summary>Pulls the JSON array out of command output that may carry extra chatter.</summary>
    static string ExtractJsonArray(string output)
    {
        var start = output.IndexOf('[');
        var end = output.LastIndexOf(']');
        return start >= 0 && end > start ? output[start..(end + 1)] : output;
    }

    static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + $"… ({value.Length} chars total)";
}
