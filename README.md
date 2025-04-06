# MCP Experiments

These MCP experiments are based on Laurent Kempé's [tutorial](https://laurentkempe.com/2025/03/22/model-context-protocol-made-easy-building-an-mcp-server-in-csharp/).

There is a dotnet MCP server over stdio that provides a function to return the current time.

There is a dotnet MCP client that makes it available to a local LLM which invokes it.

It uses the official [mcp-csharp-sdk](https://github.com/modelcontextprotocol/csharp-sdk).

## Claude Desktop

To add it to [Claude Desktop](https://claude.ai/download), change the `claude_desktop_config.json` like this:

```json
{
    "mcpServers": {
        "getTime": {
            "command": "D:\\McpExperiments\\MyMCPServer.Stdio\\bin\\Debug\\net9.0\\MyMCPServer.Stdio.exe"
        },
        "getVibe": {
            "command": "npx",
            "args": [
                "mcp-remote@0.0.9",
                "http://localhost:5253/sse"
            ]
        }
    }
}
```

Claude Desktop seems to not yet natively support SSE transport.

## Authorization

Web-based MCP servers using SSE should require authorization. According to the [specification](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/) the MCP server should also be an OAuth server.

Microsoft [plans to implement all specified authentication protocols described in the MCP spec](https://devblogs.microsoft.com/blog/microsoft-partners-with-anthropic-to-create-official-c-sdk-for-model-context-protocol?commentid=47#comment-47), but there is no roadmap yet.

In this repository I am attempting to build an OAuth server middleware for MCP servers.

OAuth server build based on <https://youtu.be/EBVKlm0wyTE>.

todo

## Resources

- [MCP](https://github.com/modelcontextprotocol)
- [Dotnet SDK](https://github.com/modelcontextprotocol/csharp-sdk)
- [Clients](https://modelcontextprotocol.io/clients)
