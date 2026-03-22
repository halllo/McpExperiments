using IdentityServer;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddRazorPages();

builder.Services.AddIdentityServer()
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiResources(Config.ApiResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients)
    .AddTestUsers(Config.TestUsers);

var app = builder.Build();

app.MapDefaultEndpoints();
app.UseStaticFiles();
app.UseIdentityServer();
app.UseAuthorization();
app.MapRazorPages().RequireAuthorization();

app.Run();
