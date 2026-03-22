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

    public static IEnumerable<ApiScope> ApiScopes =>
    [
        new ApiScope("notes"),
        new ApiScope("admin"),
    ];

    public static IEnumerable<Client> Clients =>
    [
        new Client
        {
            ClientId = "mcp_server",
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
