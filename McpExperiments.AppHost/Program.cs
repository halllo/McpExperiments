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
    /* Pinned to arm64v8 to work around a bug in the 2.3-preview (amd64) image introduced in Aspire 13.2.0.
     * The YARP gateway's Program.cs calls AddServiceDiscovery() twice (once inside AddServiceDefaults(),
     * once explicitly), which causes a NullReferenceException in ConfigurationServiceEndpointProviderOptionsValidator
     * with newer versions of Microsoft.Extensions.ServiceDiscovery. The arm64v8 nightly image lags behind
     * in package versions and still handles the double registration gracefully.
     * This workaround has an expiry date — once the arm64v8 image catches up, it will break too.
     * Upstream fix needed in dotnet/yarp: remove the redundant builder.Services.AddServiceDiscovery() in Program.cs.
     *
     * Double registration: https://github.com/dotnet/yarp/blob/main/src/Application/Program.cs
     * AddServiceDefaults (call #1): https://github.com/dotnet/yarp/blob/main/src/Application/Extensions.cs
     * Image tags: mcr.microsoft.com/dotnet/nightly/yarp
     *
     * Should be fixed with Yarp 3.0: https://github.com/dotnet/yarp/pull/3007
     */
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
