using Duende.IdentityModel;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using System.Security.Claims;

namespace IdentityServer;

public sealed class CustomProfileService : IProfileService
{
    public Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        AddClaim(context, JwtClaimTypes.Name);
        AddClaim(context, JwtClaimTypes.GivenName);
        return Task.CompletedTask;
    }

    private static void AddClaim(ProfileDataRequestContext context, string type)
    {
        var value = context.Subject.FindFirstValue(type);
        if (!string.IsNullOrWhiteSpace(value))
        {
            context.IssuedClaims.Add(new Claim(type, value));
        }
    }

    public Task IsActiveAsync(IsActiveContext context)
    {
        return Task.CompletedTask;
    }
}