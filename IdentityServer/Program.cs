using IdentityServer;
using Microsoft.AspNetCore.HttpOverrides;

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

app.UsePathBase("/identity");

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
	ForwardedHeaders =
	  ForwardedHeaders.XForwardedFor
	| ForwardedHeaders.XForwardedHost
	| ForwardedHeaders.XForwardedProto
});

app.MapDefaultEndpoints();
app.UseStaticFiles();
app.UseRouting();
app.UseIdentityServer();
app.UseAuthorization();
app.MapRazorPages().RequireAuthorization();

app.Run();
