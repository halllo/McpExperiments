# MCP Experiments

These MCP experiments are a playground for better understanding the technology.

```powershell
aspire run
```

This system makes the following endpoints available via its gateway:

- **/my-mcp-server/mcp** Experimental MCP Server
- **/my-mcp-web-client** Experimental MCP Host
- **/identity** Identity Server

## Deploy as Azure Container Apps

```powershell
$env:ASPIRE_CONTAINER_RUNTIME='podman'; aspire deploy
```

```zsh
ASPIRE_CONTAINER_RUNTIME=podman aspire deploy
```

## Clients & Compatibility

I have tested MCP authentication with the following clients.

### csharp-sdk

```csharp
var httpClientTransport = new HttpClientTransport(new()
{
 Name = "Vibe MCP Server",
 Endpoint = new Uri("https://gateway.gentlemeadow-305c776b.germanywestcentral.azurecontainerapps.io/my-mcp-server/mcp"),
 TransportMode = HttpTransportMode.StreamableHttp,
 OAuth = new()
 {
  ClientId = "mcp_console",
  RedirectUri = new Uri("http://localhost:1179/callback"),
  AuthorizationRedirectDelegate = AuthorizationUrl.Handle,
  TokenCache = tokenCache,
 },
}, http);

await using var mcpClient = await McpClient.CreateAsync(httpClientTransport);
```

Works great.

### MCP Inspector

```powershell
npx @modelcontextprotocol/inspector
```

⚠️ MCP inspector currently does not follow the `resource_metadata` URI of the `WWW-Authenticate` response header to locate the protected resource metadata according to [Section 5 of RFC9728](https://www.ietf.org/rfc/rfc9728.html#name-use-of-www-authenticate-for) ([OAuth flow does not support resourceMetadataUrl #576](https://github.com/modelcontextprotocol/inspector/issues/576)). Instead it follows a set of hardcoded rules or permutations to find one:

1. <http://localhost:5253/.well-known/oauth-protected-resource/my-mcp-server>
2. <http://localhost:5253/.well-known/oauth-protected-resource>
3. <http://localhost:5253/.well-known/oauth-authorization-server>
4. <http://localhost:5253/.well-known/openid-configuration>

When the returned WWW-Authenticate contains `Bearer realm="McpAuth", resource_metadata="http://localhost:5253/my-mcp-server/.well-known/oauth-protected-resource"`, MCP inspector should immediately acquire the protected resource metadata from <http://localhost:5253/my-mcp-server/.well-known/oauth-protected-resource>. If no `resource_metadata` is provided, then it may fall back to trying permutations.

We can add an proxy endpoint at root level, that proxies the request to the subresource:

```csharp
yarp.AddRoute("/.well-known/oauth-protected-resource/my-mcp-server/mcp", myMcpServer);
```

Now MCP inspector successfully connects to the gatewayed MCP server at /my-mcp-sever.

### MCPJam Inspector

```powershell
npx @mcpjam/inspector@latest
```

If you run it against self-signed certs locally:

```powershell
$env:NODE_TLS_REJECT_UNAUTHORIZED=0; npx @mcpjam/inspector@latest -v
```

```zsh
NODE_TLS_REJECT_UNAUTHORIZED=0 npx @mcpjam/inspector@latest -v
```

Authentication is a little bit flakey, but the OAuth Debugger works great.

### Claude

Get the desktop app form [Claude](https://claude.ai/download).

#### Web (Claude.ai)

Similar to the MCP Inspector, Claude.ai does not seem to support PRM behind a path like `/my-mcp-server/.well-known/oauth-protected-resource/mcp` and ASM behind a path like `/identity/.well-known/openid-configuration`. That means we cannot use the gatewayed approach.

It does work when Identity Server and MCP Server run on different subdomains without any base path:

- <https://my-mcp-server.hosting.io/mcp>
- <https://identity-server.hosting.io>

#### Desktop

To install local MCP servers (stdio), we can easily add them to the `claude_desktop_config.json` like this:

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

~~Claude Desktop supports remote MCP servers as "Connectors" ([Building Remote MCP Servers](https://support.anthropic.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)), but adding custom ones only on Pro/Max or Enterprise/Team plans ([Getting Started with Custom Connectors Using Remote MCP](https://support.anthropic.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp)).~~

~~Custom OAuth `client_id` are currently only available for Claude for Work. For non-work accounts it requires DCR. A localhost hosted MCP server can be added, but "connecting" it does not seem to work: Claude Desktop just opens Claude Web but does not actually do anything and Claude Web just reloads the page.~~

Custom connectors as remote MCP servers can also be added, with a OAuth ClientId & Secret. However custom connectors try to do auth at /authorize, not at at the authorize endpoint configured in the metadata of the authorization server configured in the protected resource metadata of the MCP server.

We can use [mcp-remote](https://www.npmjs.com/package/mcp-remote) for that. By default it uses _Dynamic Client Registration_ and stores its client credentials in `~\.mcp-auth`. But we can provide static oauth metadata:

```powershell
$env:NODE_OPTIONS='--use-system-ca'
npx mcp-remote 'http://localhost:5253/my-mcp-server' 63113 --static-oauth-client-info '{\"client_id\":\"mcp-remote\"}'
```

```cmd
set NODE_OPTIONS=--use-system-ca
npx mcp-remote http://localhost:5253/my-mcp-server 63113 --static-oauth-client-info "{\"client_id\":\"mcp-remote\"}"
```

If `set NODE_OPTIONS=--use-system-ca` does not work anymore (`--use-system-ca is not allowed in NODE_OPTIONS`), consider `$env:NODE_TLS_REJECT_UNAUTHORIZED = "0"`.

Powershell does have an escaping problem, so we best put the oauth data in a separate json file and reference it like this:

```powershell
npx mcp-remote 'http://localhost:5253/my-mcp-server' 63113 --static-oauth-client-info "@D:\McpExperiments\MyMCPServer.Sse\mcp-remote-oauth-client-info.json"
```

In the `claude_desktop_config.json` it looks like this:

```json
{
    "mcpServers": {
        "getVibe": {
            "command": "npx",
            "args": [
                "mcp-remote",
                "http://localhost:5253/my-mcp-server",
                "63113",
                "--static-oauth-client-info",
                "@D:\\McpExperiments\\MyMCPServer.Sse\\mcp-remote-oauth-client-info.json"
            ],
            "env": {
                "NODE_OPTIONS": "--use-system-ca"
            }
        }
    },
    "isUsingBuiltInNodeForMcp": false
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

I have proposed the fix with [Resource metadata is remembered throughout the entire login flow. #167](https://github.com/geelen/mcp-remote/pull/167). Until this is merged, we can to compile `mcp-remote` locally and set it up like this:

```bash
git clone https://github.com/halllo/mcp-remote.git
cd mcp-remote
git checkout -b remembers_resource_metadata origin/remembers_resource_metadata
pnpm install
pnpm build
npm link #make it available everywhere
npm list -g --depth=0 #to verify its actually available
npx mcp-remote #use linked version everywhere
```

Make sure your Claude Desktop instance does not use its built-in Node.js, but instead uses your operating system's version of Node.js. Under Settings / Extensions / Advanced Settings you should see the same Node.js version that you used when you ran `npm link`.

### ChatGPT

MCP support requires ChatGPT Plus. Then users can enable "Developer mode" (which is still in BETA) and create a new connector. Custom OAuth `client_id` is not supported.

Adding a localhost hosted MCP server only resulted in "Error fetching OAuth configuration".

### Nanobot

To better test the MCP servers of this project, we can use a local MCP host like [nanobot](https://www.nanobot.ai). It seems to support OAuth and mcp-ui.

```bash
export OPENAI_API_KEY=sk-proj-...
nanobot run ./nanobot.yaml
```

It seems to require client_secret and auth_endpoint, even though the client config does not require a secret and the authorize endpoint can be determined based on PRM and authorization server metadata.

However nanobot still fails with a weird error:

```log
failed to setup auth: failed to create oauth proxy: invalid mode: middleware
```

## Resources

- [MCP](https://github.com/modelcontextprotocol)
- [Dotnet SDK](https://github.com/modelcontextprotocol/csharp-sdk)
- [Clients](https://modelcontextprotocol.io/clients)
