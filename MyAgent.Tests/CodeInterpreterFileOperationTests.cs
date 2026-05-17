using Amazon.BedrockAgentCore;
using Amazon.BedrockAgentCore.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

/// <summary>
/// Directly exercises the AWS Bedrock Code Interpreter file-operation APIs (WriteFiles, ReadFiles,
/// ListFiles) to diagnose accepted path patterns, response shapes, and sandbox layout.
/// No dependency on our CodeInterpreter wrapper or agent stack.
/// </summary>
[TestClass]
public sealed class CodeInterpreterFileOperationTests
{
    private const string CodeInterpreterId = "aws.codeinterpreter.v1";
    public required TestContext TestContext { get; set; }

    internal static IAmazonBedrockAgentCore BuildClient()
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
            Name = "FileOpTest_" + Guid.NewGuid(),
            SessionTimeoutSeconds = 300,
        }, ct);
        return r.SessionId;
    }

    static Task StopSession(IAmazonBedrockAgentCore client, string sessionId) =>
        client.StopCodeInterpreterSessionAsync(new StopCodeInterpreterSessionRequest
        {
            CodeInterpreterIdentifier = CodeInterpreterId,
            SessionId = sessionId,
        });

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

    static async Task WriteFile(
        IAmazonBedrockAgentCore client, string sessionId, string path, string content, CancellationToken ct)
    {
        var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
        {
            CodeInterpreterIdentifier = CodeInterpreterId,
            SessionId = sessionId,
            Name = ToolName.WriteFiles,
            Arguments = new ToolArguments { Content = [new InputContentBlock { Path = path, Text = content }] },
        }, ct);
        await foreach (var _ in response.Stream.WithCancellation(ct)) { }
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

    // ── WriteFiles path acceptance tests ─────────────────────────────────────

    // Absolute /tmp/ paths — rejected by the API (path traversal guard)
    [TestMethod] public Task WriteFiles_FlatTmpPath() =>
        RunExpectRejectedTest("/tmp/hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_OneLevelSubdir() =>
        RunExpectRejectedTest("/tmp/subdir/hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_FourLevelSubdir() =>
        RunExpectRejectedTest("/tmp/skills/pdf/scripts/hello.txt", TestContext.CancellationToken);

    // Relative paths — succeed and round-trip cleanly
    [TestMethod] public Task WriteFiles_RelativeFlat() =>
        RunWriteTest("hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_RelativeSubdir() =>
        RunWriteTest("scripts/hello.txt", TestContext.CancellationToken);

    // ~/paths — write accepted but WriteFiles does NOT expand ~, so cat ~/path reads the
    // shell-expanded location which is different; just assert the write itself succeeds.
    [TestMethod] public Task WriteFiles_HomeFlat() =>
        RunWriteAcceptedTest("~/hello.txt", TestContext.CancellationToken);

    [TestMethod] public Task WriteFiles_HomeSubdir() =>
        RunWriteAcceptedTest("~/scripts/hello.txt", TestContext.CancellationToken);

    async Task RunWriteTest(string path, CancellationToken ct)
    {
        var client = BuildClient();
        var sessionId = await StartSession(client, ct);
        try
        {
            const string content = "hello from WriteFiles";
            var (isError, writeText) = await WriteFiles(client, sessionId, path, content, ct);
            TestContext.WriteLine($"WriteFiles path={path} isError={isError} response={writeText}");
            Assert.IsFalse(isError, $"WriteFiles rejected path '{path}': {writeText}");

            var readBack = await ExecuteCommand(client, sessionId, $"cat {path}", ct);
            TestContext.WriteLine($"cat result: {readBack}");
            Assert.AreEqual(content, readBack.Trim(), $"File at '{path}' did not contain expected content");
        }
        finally { await StopSession(client, sessionId); }
    }

    async Task RunWriteAcceptedTest(string path, CancellationToken ct)
    {
        var client = BuildClient();
        var sessionId = await StartSession(client, ct);
        try
        {
            var (isError, writeText) = await WriteFiles(client, sessionId, path, "hello from WriteFiles", ct);
            TestContext.WriteLine($"WriteFiles path={path} isError={isError} response={writeText}");
            Assert.IsFalse(isError, $"WriteFiles rejected path '{path}': {writeText}");
        }
        finally { await StopSession(client, sessionId); }
    }

    async Task RunExpectRejectedTest(string path, CancellationToken ct)
    {
        var client = BuildClient();
        var sessionId = await StartSession(client, ct);
        try
        {
            var (isError, writeText) = await WriteFiles(client, sessionId, path, "hello from WriteFiles", ct);
            TestContext.WriteLine($"WriteFiles path={path} isError={isError} response={writeText}");
            Assert.IsTrue(isError, $"Expected WriteFiles to reject path '{path}' but it succeeded");
        }
        finally { await StopSession(client, sessionId); }
    }

    // ── Sandbox environment diagnostics ──────────────────────────────────────

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

            Assert.IsGreaterThan(0, pwd.Length, "Expected non-empty pwd");
        }
        finally
        {
            await StopSession(client, sessionId);
        }
    }

    // ── ListFiles / ReadFiles response shape diagnostics ─────────────────────

    /// <summary>
    /// Calls ListFiles and dumps every field of every ContentBlock so we know the exact response shape.
    /// </summary>
    [TestMethod]
    public async Task Diagnose_ListFiles_ResponseShape()
    {
        var client = BuildClient();
        var ct = TestContext.CancellationToken;
        var sessionId = await StartSession(client, ct);
        try
        {
            await WriteFile(client, sessionId, "list_diag.txt", "list diag content", ct);

            var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
            {
                CodeInterpreterIdentifier = CodeInterpreterId,
                SessionId = sessionId,
                Name = ToolName.ListFiles,
                Arguments = new ToolArguments { DirectoryPath = "." },
            }, ct);

            await foreach (var msg in response.Stream.WithCancellation(ct))
            {
                TestContext.WriteLine($"Message type: {msg.GetType().Name}");
                if (msg is CodeInterpreterResult r)
                {
                    TestContext.WriteLine($"  IsError={r.IsError}");
                    if (r.StructuredContent is { } sc)
                        TestContext.WriteLine($"  StructuredContent: ExitCode={sc.ExitCode}, Stdout=[{sc.Stdout}], Stderr=[{sc.Stderr}]");
                    foreach (var c in r.Content ?? [])
                        TestContext.WriteLine($"  Content: Type={c.Type}, Name=[{c.Name}], Uri=[{c.Uri}], Size={c.Size}, MimeType=[{c.MimeType}], Text=[{c.Text}], HasData={c.Data != null}");
                }
            }
        }
        finally { await StopSession(client, sessionId); }
    }

    /// <summary>
    /// Writes a binary file via ExecuteCommand, then calls ReadFiles and dumps every field
    /// to confirm where binary content lands (Resource.Blob vs Resource.Text).
    /// </summary>
    [TestMethod]
    public async Task Diagnose_ReadFiles_BinaryResponseShape()
    {
        var client = BuildClient();
        var ct = TestContext.CancellationToken;
        var sessionId = await StartSession(client, ct);
        try
        {
            // Write a binary file with non-UTF-8 bytes via shell
            await ExecuteCommand(client, sessionId, "printf '\\x00\\x01\\x02\\x03\\xFF\\xFE\\xFD\\xFC' > binary_diag.bin", ct);

            var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
            {
                CodeInterpreterIdentifier = CodeInterpreterId,
                SessionId = sessionId,
                Name = ToolName.ReadFiles,
                Arguments = new ToolArguments { Paths = ["binary_diag.bin"] },
            }, ct);

            await foreach (var msg in response.Stream.WithCancellation(ct))
            {
                if (msg is not CodeInterpreterResult r) continue;
                TestContext.WriteLine($"IsError={r.IsError}");
                foreach (var c in r.Content ?? [])
                {
                    var resource = c.Resource;
                    if (resource is null) { TestContext.WriteLine("  content block with null Resource"); continue; }

                    string? blobSnippet = null;
                    if (resource.Blob != null)
                    {
                        using var ms = new System.IO.MemoryStream();
                        await resource.Blob.CopyToAsync(ms, ct);
                        blobSnippet = $"{ms.Length} bytes: [{BitConverter.ToString(ms.ToArray())}]";
                    }
                    TestContext.WriteLine($"  Resource.Uri=[{resource.Uri}] MimeType=[{resource.MimeType}] Text=[{resource.Text}] Blob={blobSnippet ?? "null"}");
                }
            }
        }
        finally { await StopSession(client, sessionId); }
    }

    /// <summary>
    /// Calls ReadFiles with several path formats and dumps every field of every ContentBlock
    /// to find out which format the API actually accepts and where it puts the content.
    /// </summary>
    [TestMethod]
    public async Task Diagnose_ReadFiles_ResponseShape()
    {
        var client = BuildClient();
        var ct = TestContext.CancellationToken;
        var sessionId = await StartSession(client, ct);
        try
        {
            const string content = "hello read diag";
            await WriteFile(client, sessionId, "read_diag.txt", content, ct);

            var pathsToTry = new[]
            {
                "read_diag.txt",
                "./read_diag.txt",
                "file:///./read_diag.txt",
            };

            foreach (var path in pathsToTry)
            {
                TestContext.WriteLine($"\n--- ReadFiles path=[{path}] ---");
                var response = await client.InvokeCodeInterpreterAsync(new InvokeCodeInterpreterRequest
                {
                    CodeInterpreterIdentifier = CodeInterpreterId,
                    SessionId = sessionId,
                    Name = ToolName.ReadFiles,
                    Arguments = new ToolArguments { Paths = [path] },
                }, ct);

                await foreach (var msg in response.Stream.WithCancellation(ct))
                {
                    TestContext.WriteLine($"Message type: {msg.GetType().FullName}");
                    // Dump all readable properties via reflection
                    foreach (var prop in msg.GetType().GetProperties())
                    {
                        try
                        {
                            var val = prop.GetValue(msg);
                            if (val is System.Collections.IEnumerable enumerable and not string)
                            {
                                TestContext.WriteLine($"  {prop.Name}: [list]");
                                foreach (var item in enumerable)
                                {
                                    TestContext.WriteLine($"    item type: {item?.GetType().Name}");
                                    if (item != null)
                                        foreach (var p2 in item.GetType().GetProperties())
                                        {
                                            try
                                            {
                                                var v2 = p2.GetValue(item);
                                                if (v2 != null && v2.GetType().Namespace?.StartsWith("Amazon") == true)
                                                {
                                                    TestContext.WriteLine($"      {p2.Name} = [{v2}] (expanding)");
                                                    foreach (var p3 in v2.GetType().GetProperties())
                                                        try { TestContext.WriteLine($"        {p3.Name} = [{p3.GetValue(v2)}]"); } catch { }
                                                }
                                                else
                                                {
                                                    TestContext.WriteLine($"      {p2.Name} = [{v2}]");
                                                }
                                            }
                                            catch { }
                                        }
                                }
                            }
                            else
                            {
                                TestContext.WriteLine($"  {prop.Name} = [{val}]");
                            }
                        }
                        catch { }
                    }
                }
            }
        }
        finally { await StopSession(client, sessionId); }
    }
}
