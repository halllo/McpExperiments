var builder = DistributedApplication.CreateBuilder(args);

// Identity Server is pinned to port 5001 so its issuer URI is stable and
// matches what MyMCPServer.Sse uses as a JWT audience/authority.
// Port 5001 is pinned in IdentityServer/Properties/launchSettings.json so the issuer URI is stable.
var identityServer = builder.AddProject<Projects.IdentityServer>("identity-server");

var mcpServer = builder.AddProject<Projects.MyMCPServer_Sse>("mcp-server")
    .WithReference(identityServer)
    .WaitFor(identityServer);

builder.AddProject<Projects.MyMCPClient_Web>("mcp-web-client")
    .WithReference(identityServer)
    .WithReference(mcpServer)
    .WaitFor(identityServer)
    .WaitFor(mcpServer);

builder.AddProject<Projects.MyAgent>("agent")
    .WithReference(identityServer)
    .WithReference(mcpServer)
    .WaitFor(identityServer)
    .WaitFor(mcpServer);

builder.Build().Run();
