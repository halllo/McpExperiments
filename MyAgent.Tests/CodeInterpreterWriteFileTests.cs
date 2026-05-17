using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

/// <summary>
/// Directly exercises the AWS Bedrock Code Interpreter WriteFiles API to diagnose
/// which path patterns are accepted and which trigger "potential path traversal detected".
/// No dependency on our CodeInterpreter wrapper or agent stack.
/// </summary>
[TestClass, Ignore("Just for diagnostics.")]
public sealed class CodeInterpreterWriteFileTests
{
    private const string CodeInterpreterId = "aws.codeinterpreter.v1";

    static IAmazonBedrockAgentCore BuildClient()
    {
        var config = Program.BuildHost().Services.GetRequiredService<IConfiguration>();
        return new AmazonBedrockAgentCoreClient(
            awsAccessKeyId: config["AWSBedrockAccessKeyId"],
            awsSecretAccessKey: config["AWSBedrockSecretAccessKey"],
            region: Amazon.RegionEndpoint.GetBySystemName(config["AWSBedrockRegion"]));
    }

    static async Task<string> StartSession(IAmazonBedrockAgentCore client, CancellationToken ct)
    {
        var r = await client.StartCodeInterpreterSessionAsync(new StartCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = CodeInterpreterId,
            Name = "WriteFileTest_" + Guid.NewGuid(),
            SessionTimeoutSeconds = 300,
        }, ct);
        return r.SessionId;
    }

    static async Task StopSession(IAmazonBedrockAgentCore client, string sessionId)
    {
        await client.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = CodeInterpreterId,
            SessionId = sessionId,
        });
    }

    static async Task<(bool isError, string text)> WriteFiles(
        IAmazonBedrockAgentCore client, string sessionId, string path, string content, CancellationToken ct)
    {
        var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = CodeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.WriteFiles,
            Arguments = new ToolArguments
            {
                Content = [new InputContentBlock { Path = path, Text = content }],
            },
        }, ct);

        var text = new System.Text.StringBuilder();
        var isError = false;
        await foreach (var msg in response.Stream.WithCancellation(ct))
        {
            if (msg is CodeInterpreterResult r)
            {
                isError |= r.IsError == true;
                foreach (var c in r.Content ?? [])
                    text.Append(c.Text);
            }
        }
        return (isError, text.ToString());
    }

    static async Task<string> ExecuteCommand(
        IAmazonBedrockAgentCore client, string sessionId, string command, CancellationToken ct)
    {
        var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = CodeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.ExecuteCommand,
            Arguments = new ToolArguments { Command = command },
        }, ct);

        var text = new System.Text.StringBuilder();
        await foreach (var msg in response.Stream.WithCancellation(ct))
            if (msg is CodeInterpreterResult r)
                foreach (var c in r.Content ?? [])
                    text.Append(c.Text);
        return text.ToString();
    }

    public required TestContext TestContext { get; set; }

    // Absolute /tmp/ paths — expected to be rejected
    [TestMethod] public Task WriteFiles_FlatTmpPath() =>
        RunWriteTest("/tmp/hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_OneLevelSubdir() =>
        RunWriteTest("/tmp/subdir/hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_FourLevelSubdir() =>
        RunWriteTest("/tmp/skills/pdf/scripts/hello.txt", TestContext.CancellationToken);

    // Relative paths — expected to succeed
    [TestMethod] public Task WriteFiles_RelativeFlat() =>
        RunWriteTest("hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_RelativeSubdir() =>
        RunWriteTest("scripts/hello.txt", TestContext.CancellationToken);

    // Home-relative paths — expected to succeed
    [TestMethod] public Task WriteFiles_HomeFlat() =>
        RunWriteTest("~/hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_HomeSubdir() =>
        RunWriteTest("~/scripts/hello.txt", TestContext.CancellationToken);

    /// <summary>
    /// Discovers the sandbox working directory and $HOME so we know how relative paths resolve.
    /// </summary>
    [TestMethod]
    public async Task Diagnose_SandboxPaths()
    {
        var client = BuildClient();
        var ct = TestContext.CancellationToken;
        var sessionId = await StartSession(client, ct);
        try
        {
            var pwd    = await ExecuteCommand(client, sessionId, "pwd", ct);
            var home   = await ExecuteCommand(client, sessionId, "echo $HOME", ct);
            var whoami = await ExecuteCommand(client, sessionId, "whoami", ct);
            var ls     = await ExecuteCommand(client, sessionId, "ls -la ~", ct);

            TestContext.WriteLine($"pwd    = {pwd.Trim()}");
            TestContext.WriteLine($"$HOME  = {home.Trim()}");
            TestContext.WriteLine($"whoami = {whoami.Trim()}");
            TestContext.WriteLine($"ls ~   =\n{ls}");

            // Not a real assertion — just collecting diagnostics.
            Assert.IsGreaterThan(pwd.Length, 0, "Expected non-empty pwd");
        }
        finally
        {
            await StopSession(client, sessionId);
        }
    }

    async Task RunWriteTest(string path, CancellationToken ct)
    {
        var client = BuildClient();
        var sessionId = await StartSession(client, ct);
        try
        {
            const string content = "hello from WriteFiles";

            var (isError, writeText) = await WriteFiles(client, sessionId, path, content, ct);
            TestContext.WriteLine($"WriteFiles path={path} isError={isError} response={writeText}");

            if (isError)
            {
                Assert.Fail($"WriteFiles rejected path '{path}': {writeText}");
                return;
            }

            // Verify the file exists and has the expected content
            var readBack = await ExecuteCommand(client, sessionId, $"cat {path}", ct);
            TestContext.WriteLine($"cat result: {readBack}");
            Assert.AreEqual(content, readBack.Trim(),
                $"File at '{path}' did not contain expected content");
        }
        finally
        {
            await StopSession(client, sessionId);
        }
    }
}
