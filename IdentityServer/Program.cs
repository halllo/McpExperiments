using IdentityServer;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
      ForwardedHeaders.XForwardedFor |
      ForwardedHeaders.XForwardedHost |
      ForwardedHeaders.XForwardedProto;
    // Optionally clear KnownIPNetworks and KnownProxies to trust all (for cloud/proxy scenarios)
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddRazorPages();

builder.Services.AddIdentityServer(options =>
{
    options.KeyManagement.Enabled = false;// Disable automatic key management to prevent file system access
})
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiResources(Config.ApiResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients)
    .AddTestUsers(Config.TestUsers)
    .AddProfileService<CustomProfileService>()
    .AddDeveloperSigningCredential(persistKey: false/*no file system access*/);


var app = builder.Build();

app.UseForwardedHeaders();
app.UsePathBase("/identity");

app.MapDefaultEndpoints();
app.UseStaticFiles();
app.UseRouting();
app.UseIdentityServer();
app.UseAuthorization();
app.MapRazorPages().RequireAuthorization();

app.Run();
