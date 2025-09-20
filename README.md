# MCP Experiments

These MCP experiments are based on Laurent Kempé's [tutorial](https://laurentkempe.com/2025/03/22/model-context-protocol-made-easy-building-an-mcp-server-in-csharp/).

There is a dotnet MCP server over stdio that provides a function to return the current time.

There is a dotnet MCP client that makes it available to a local LLM which invokes it.

It uses the official [mcp-csharp-sdk](https://github.com/modelcontextprotocol/csharp-sdk).

## Develop

Build all MCP projects:

```powershell
dotnet build
```

Start the MCP server over SSE and streamable HTTP:

```powershell
dotnet run --project MyMCPServer.Sse --launch-profile https
```

## Authorization

Web-based MCP servers using SSE or streamable HTTP should require authorization.

Microsoft [plans to implement all specified authentication protocols described in the MCP spec](https://devblogs.microsoft.com/blog/microsoft-partners-with-anthropic-to-create-official-c-sdk-for-model-context-protocol?commentid=47#comment-47), but there is no roadmap yet.

In this repository I am experimenting with differnt kinds of authentication and authorization for MCP servers. To test it, we can use the _mcp inspector_ and the browser developer tools.

```powershell
npx @modelcontextprotocol/inspector
```

### MCP server as Identity Provider

~~According to the first [specification](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/) the MCP server should also be an OAuth authorization server. To experiment with that, I built a light-weight OAuth server base on <https://youtu.be/EBVKlm0wyTE>.~~

### MCP server as Resource Provider

According to the current [specification](https://modelcontextprotocol.io/specification/draft/basic/authorization) the MCP server should provide _Protected Resource Metadata_ to point to an OAuth server's _Authorization Service Metadata_. That AS should implement _Dynamic Client Registration_.

We use [Duende Identity Server](https://duendesoftware.com/products/identityserver) to build a centralized Authorization Server. Unfortunately Duende does not yet support MCP in combination with `@modelcontextprotocol/inspector`. So I had to apply a few adjustments to my [experimental instance of Duende](https://github.com/halllo/PermissionedNotes/tree/main/IdentityServer).

- provide the OIDC discovery document also at `.well-known/oauth-authorization-server`
- the discovery document needs to also include the `registration_endpoint` endpoint for DCR
- MCP inspector does not register clients with any scopes, so we add all scopes to the newly registered clients
- MCP inspector registers a public client without a client_secret and does not remember and provide generated secrets in the `/token` request, so we dont generate a secret and dont require one, unless explicitly requested via `require_client_secret=true` (⚠️ This could be problematic if other clients expect a different default, so we would need some means to differentiate the clients expectations.)
- MCP inspector does not follow redirects of DCR endpoint, so we cannot use frontchannel authorization
- MCP inspector does not provide scopes during the `/authorize` request (just the resource indicator), so we inject all scopes of the resource to bypass Duende's `missing scope` validation

As next steps I need to look into MCP inspector to better understand if it could

- pass scopes during DCR and `/authorize`
- follow redirects and deal with DCR requiring authorization

#### Limitations

⚠️ MCP inspector currently requires the oauth-protected-resource's resource identifier to match the origin of the MCP endpoint. [Does protected resource's resource identifier HAVE TO match MCP server's URI? #812](https://github.com/modelcontextprotocol/inspector/issues/812). That is making localhost debugging more difficult, but spec compliant.

⚠️ MCP inspector currently does not follow the `resource_metadata` URI of the `WWW-Authenticate` response header to locate the protected resource metadata according to [Section 5 of RFC9728](https://www.ietf.org/rfc/rfc9728.html#name-use-of-www-authenticate-for) ([OAuth flow does not support resourceMetadataUrl #576](https://github.com/modelcontextprotocol/inspector/issues/576)). Instead it follows a set of hardcoded rules or permutations to find one:

1. <http://localhost:5253/.well-known/oauth-protected-resource/bot>
2. <http://localhost:5253/.well-known/oauth-protected-resource>
3. <http://localhost:5253/.well-known/oauth-authorization-server>
4. <http://localhost:5253/.well-known/openid-configuration>

When the returned WWW-Authenticate contains `Bearer realm="McpAuth", resource_metadata="http://localhost:5253/bot/.well-known/oauth-protected-resource"`, it should immediately acquire the protected resource metadata from <http://localhost:5253/bot/.well-known/oauth-protected-resource>. If no `resource_metadata` is provided, then it may fall back to trying permutations.

## Claude Desktop

To install local MCP servers (stdio) in [Claude Desktop](https://claude.ai/download), we can easily add them to the `claude_desktop_config.json` like this:

```json
{
    "mcpServers": {
        "getTime": {
            "command": "D:\\McpExperiments\\MyMCPServer.Stdio\\bin\\Debug\\net9.0\\MyMCPServer.Stdio.exe"
        },
        "getCli": {
            "command": "D:\\McpExperiments\\MyMCPServer.Stdio.Cli\\bin\\Debug\\net9.0\\MyMCPServer.Stdio.Cli.exe",
            "args": [ 
                "mcp"
            ]
        }
    }
}
```

Claude Desktop supports remote MCP servers as "Connectors" ([Building Remote MCP Servers](https://support.anthropic.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)), but adding custom ones only on Pro/Max or Enterprise/Team plans ([Getting Started with Custom Connectors Using Remote MCP](https://support.anthropic.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp)).

Custom OAuth `client_id` are currently only available for Claude for Work. For non-work accounts it requires DCR. A localhost hosted MCP server can be added, but "connecting" it does not seem to work: Claude Desktop just opens Claude Web but does not actually do anything and Claude Web just reloads the page.

We can use [mcp-remote](https://www.npmjs.com/package/mcp-remote) for that. By default it uses _Dynamic Client Registration_ and stores its client credentials in `~\.mcp-auth`. But we can provide static oauth metadata:

```powershell
$env:NODE_OPTIONS='--use-system-ca'
npx mcp-remote 'http://localhost:5253/bot' 63113 --static-oauth-client-info '{\"client_id\":\"mcp-remote\"}'
```

```cmd
set NODE_OPTIONS=--use-system-ca
npx mcp-remote http://localhost:5253/bot 63113 --static-oauth-client-info "{\"client_id\":\"mcp-remote\"}"
```

```json
{
    "mcpServers": {
        "getVibe": {
            "command": "npx",
            "args": [
                "mcp-remote",
                "http://localhost:5253/bot",
                "63113",
                "--static-oauth-client-info",
                "{\"client_id\":\"mcp-remote\"}"
            ],
            "env": {
                "NODE_OPTIONS": "--use-system-ca"
            }
        }
    }
}
```

Or via script [claude_desktop.cmd](MyMCPServer.Sse/claude_desktop.cmd):

```json
{
  "mcpServers": {
    "getVibe": {
      "command": "D:\\McpExperiments\\MyMCPServer.Sse\\claude_desktop.cmd"
    }
  }
}
```

However, this currently fails during "Completing authorization" with a 404. What endpoint is it trying to call?
The protected resource metadata is detected with a `testTransport`, but not fed forward into the actual transport in [connectToRemoteServer()](https://github.com/geelen/mcp-remote/blob/ce68351da4991bb795c2cccb94bf3649e5843cf4/src/lib/utils.ts#L312C1-L336C69):

```typescript
const transport = sseTransport ? new SSEClientTransport(url, {
  authProvider,
  requestInit: { headers },
  eventSourceInit
}) : new StreamableHTTPClientTransport(url, {
 authProvider,
 requestInit: { headers }
});
try {
  debugLog("Attempting to connect to remote server", { sseTransport });
  if (client) {
    debugLog("Connecting client to transport");
    await client.connect(transport);
  } else {
    debugLog("Starting transport directly");
    await transport.start();
    if (!sseTransport) {
      debugLog("Creating test transport for HTTP-only connection test");
      const testTransport = new StreamableHTTPClientTransport(url, { authProvider, requestInit: { headers } });
      const testClient = new Client({ name: "mcp-remote-fallback-test", version: "0.0.0" }, { capabilities: {} });
      await testClient.connect(testTransport);
    }
  }
  return transport;
} catch (error) {
  transport._resourceMetadataUrl = testTransport._resourceMetadataUrl;//this line would fix it (todo: pr!)
  //...interactive authentication
}
```

## ChatGPT

MCP support requires ChatGPT Plus. Then users can enable "Developer mode" (which is still in BETA) and create a new connector. Custom OAuth `client_id` is not supported.

Adding a localhost hosted MCP server only resulted in "Error fetching OAuth configuration".

## Resources

- [MCP](https://github.com/modelcontextprotocol)
- [Dotnet SDK](https://github.com/modelcontextprotocol/csharp-sdk)
- [Clients](https://modelcontextprotocol.io/clients)
