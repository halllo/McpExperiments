# MCP Experiments

These MCP experiments are based on Laurent Kempé's great [tutorial](https://laurentkempe.com/2025/03/22/model-context-protocol-made-easy-building-an-mcp-server-in-csharp/).

There is a dotnet MCP server over stdio that provides a function to return the current time.

There is a dotnet MCP client that makes it available to a local LLM which invokes it.

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

## Resources

- [MCP](https://github.com/modelcontextprotocol)
- [Dotnet SDK](https://github.com/modelcontextprotocol/csharp-sdk)
- [Clients](https://modelcontextprotocol.io/clients)
