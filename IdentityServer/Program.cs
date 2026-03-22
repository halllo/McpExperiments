using IdentityServer;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddIdentityServer()
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients)
    .AddTestUsers(Config.TestUsers);

var app = builder.Build();

app.MapDefaultEndpoints();
app.UseIdentityServer();

app.Run();
