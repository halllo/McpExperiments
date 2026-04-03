var builder = DistributedApplication.CreateBuilder(args);

builder.AddAzureContainerAppEnvironment("my-mcp-experiments");

var identityServer = builder.AddProject<Projects.IdentityServer>("identity-server")
    .WithExternalHttpEndpoints()
    ;

var myMcpServer = builder.AddProject<Projects.MyMCPServer_Sse>("my-mcp-server")
    .WithReference(identityServer)
    .WaitFor(identityServer)
    .WithExternalHttpEndpoints()
    ;

var myMcpWebClient = builder.AddProject<Projects.MyMCPClient_Web>("my-mcp-web-client")
    .WithReference(identityServer)
    .WithReference(myMcpServer)
    .WaitFor(identityServer)
    .WaitFor(myMcpServer)
    ;

var myAgent = builder.AddProject<Projects.MyAgent>("my-agent")
    .WithReference(identityServer)
    .WithReference(myMcpServer)
    .WaitFor(identityServer)
    .WaitFor(myMcpServer)
    ;

var gateway = builder.AddYarp("gateway")
    .WithImageTag("2.3-preview-arm64v8")
    .WithHostHttpsPort(8443)
    .WithHostPort(8080)
    .WithStaticFiles("../wwwroot")
    .WithConfiguration(yarp =>
    {
        yarp.AddRoute("/identity/{**catch-all}", identityServer);
        yarp.AddRoute("/my-mcp-server/{**catch-all}", myMcpServer);
        yarp.AddRoute("/.well-known/oauth-protected-resource/my-mcp-server/mcp", myMcpServer);
        yarp.AddRoute("/my-mcp-web-client/{**catch-all}", myMcpWebClient);
        yarp.AddRoute("/my-agent/{**catch-all}", myAgent);
    })
    .WithExternalHttpEndpoints()
    ;

builder.Build().Run();
