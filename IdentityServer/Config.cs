using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using System.Security.Claims;

namespace IdentityServer;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
    [
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResource("verification", "Email verification", ["email_verified"]),
    ];

    public static IEnumerable<ApiResource> ApiResources =>
    [
        new ApiResource("https://gateway-mcpexperiments.dev.localhost:8443/my-mcp-server/mcp") { Scopes = ["notes", "admin"] },
        new ApiResource("https://gateway.gentlemeadow-305c776b.germanywestcentral.azurecontainerapps.io/my-mcp-server/mcp") { Scopes = ["notes", "admin"] },
    ];

    public static IEnumerable<ApiScope> ApiScopes =>
    [
        new ApiScope("notes"),
        new ApiScope("admin"),
    ];

    public static IEnumerable<Client> Clients =>
    [
        new Client
        {
            ClientId = "mcp_host_web",
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.Code,
            RedirectUris =
            {
                // MyMCPServer.Sse
                "https://localhost:7296/signin-oidc",
                // MyMCPClient.Web
                "https://localhost:7208/signin-oidc",
            },
            PostLogoutRedirectUris =
            {
                "https://localhost:7296/signout-callback-oidc",
                "https://localhost:7208/signout-callback-oidc",
            },
            AllowedScopes = { "openid", "profile", "verification", "notes", "admin" },
            AllowOfflineAccess = true,
        },
        new Client
        {
            ClientId = "mcp_console",
            AllowedGrantTypes = GrantTypes.Code,
            RedirectUris = { "http://localhost:1179/callback" },
            AllowedScopes = { "openid", "profile", "verification", "notes", "admin" },
            RequireClientSecret = false,
            RequirePkce = true,
            AllowOfflineAccess = true,
        },
        new Client
        {
            ClientId = "https://www.mcpjam.com/.well-known/oauth/client-metadata.json",
            ClientName = "MCPJam",
            AllowedGrantTypes = GrantTypes.Code,
            RequireClientSecret = false,
            RequirePkce = true,
            RedirectUris =
            {
                "mcpjam://oauth/callback",
                "mcpjam://authkit/callback",
                "http://127.0.0.1:6274/oauth/callback",
                "http://127.0.0.1:6274/callback",
                "http://127.0.0.1:6274/oauth/callback/debug",
                "http://localhost:6274/oauth/callback",
                "http://localhost:6274/callback",
                "http://localhost:6274/oauth/callback/debug",
                "http://127.0.0.1:5173/oauth/callback",
                "http://127.0.0.1:5173/oauth/callback/debug",
                "http://localhost:5173/oauth/callback",
                "http://localhost:5173/oauth/callback/debug",
                "https://app.mcpjam.com/oauth/callback",
                "https://app.mcpjam.com/oauth/callback/debug",
            },
            AllowedScopes = { "openid", "profile", "verification", "notes", "admin" },
        },
    ];

    public static List<TestUser> TestUsers =>
    [
        new TestUser
        {
            SubjectId = "1",
            Username = "alice",
            Password = "alice",
            Claims =
            {
                new Claim("name", "Alice"),
                new Claim("email_verified", "true"),
            },
        },
    ];
}
