using Microsoft.Agents.AI;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

[TestClass, DoNotParallelize]
public sealed class CodeInterpreterFileCaptureTests
{
    public required TestContext TestContext { get; set; }

    async Task<string> RunAndFindOutputFile(string fileName, string pythonCode, Action<string> onOutputDir)
    {
        var workDir = Directory.GetCurrentDirectory();
        var dirsBefore = new HashSet<string>(Directory.GetDirectories(workDir));

        var runOptions = new AgentRunOptions();
        var codeInterpreter = Program.BuildHost().Services.GetRequiredService<CodeInterpreter>();
        try
        {
            var result = await codeInterpreter.ExecuteCode(pythonCode, runOptions, TestContext.CancellationToken);
            await Factory.SaveNewFiles(result);
        }
        finally
        {
            await codeInterpreter.CloseCodeInterpreter(runOptions);
        }

        var newDirs = Directory.GetDirectories(workDir).Where(d => !dirsBefore.Contains(d)).ToList();
        Assert.AreEqual(1, newDirs.Count,
            $"Expected exactly one new output directory. Found: [{string.Join(", ", newDirs.Select(Path.GetFileName))}]");

        onOutputDir(newDirs[0]);

        var allFiles = Directory.GetFiles(newDirs[0], "*", SearchOption.AllDirectories);
        var foundFiles = allFiles
            .Where(f => string.Equals(Path.GetFileName(f), fileName, StringComparison.Ordinal))
            .ToArray();
        Assert.AreEqual(1, foundFiles.Length,
            $"Expected exactly one '{fileName}' in '{newDirs[0]}'. " +
            $"Actual contents: [{string.Join(", ", allFiles.Select(f => Path.GetRelativePath(newDirs[0], f)))}]");

        return foundFiles[0];
    }

    [TestMethod]
    public async Task ExecuteCode_CreatedFile_IsDetectedAndStoredLocally()
    {
        const string fileName = "ci_capture_test.txt";
        const string fileContent = "hello from capture test";
        string? outputDir = null;

        try
        {
            var filePath = await RunAndFindOutputFile(fileName, $"""
                import os
                with open(os.path.expanduser('~/{fileName}'), 'w') as f:
                    f.write('{fileContent}')
                print('done')
                """, d => outputDir = d);

            var savedContent = await File.ReadAllTextAsync(filePath, TestContext.CancellationToken);
            Assert.AreEqual(fileContent, savedContent.Trim());
        }
        finally
        {
            if (outputDir is not null) try { Directory.Delete(outputDir, recursive: true); } catch { }
        }
    }

    [TestMethod]
    public async Task ExecuteCode_CreatedBinaryFile_IsDetectedAndStoredLocally()
    {
        const string fileName = "ci_binary_test.bin";
        byte[] expectedBytes = [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC];
        var byteList = string.Join(", ", expectedBytes.Select(b => b.ToString()));
        string? outputDir = null;

        try
        {
            var filePath = await RunAndFindOutputFile(fileName, $"""
                import os
                data = bytes([{byteList}])
                with open(os.path.expanduser('~/{fileName}'), 'wb') as f:
                    f.write(data)
                print('done')
                """, d => outputDir = d);

            var savedBytes = await File.ReadAllBytesAsync(filePath, TestContext.CancellationToken);
            CollectionAssert.AreEqual(expectedBytes, savedBytes,
                $"Binary content mismatch. Expected [{BitConverter.ToString(expectedBytes)}] " +
                $"but got [{BitConverter.ToString(savedBytes)}]");
        }
        finally
        {
            if (outputDir is not null) try { Directory.Delete(outputDir, recursive: true); } catch { }
        }
    }
}
