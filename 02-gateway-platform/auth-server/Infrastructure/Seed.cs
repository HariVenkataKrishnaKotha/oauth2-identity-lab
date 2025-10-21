using AuthServer.Identity;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Infrastructure;

public static class Seed
{
    public static async Task InitializeAsync(
        IServiceProvider sp,
        string issuer,
        CancellationToken ct = default)
    {
        using var scope = sp.CreateScope();
        var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var appMgr = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeMgr = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        // 1) Roles
        foreach (var r in new[] { "Onboardee", "Manager", "Admin" })
        {
            if (!await roleMgr.RoleExistsAsync(r))
                await roleMgr.CreateAsync(new ApplicationRole { Name = r, NormalizedName = r.ToUpperInvariant() });
        }

        // 2) (Optional) Seed a test manager user (change in prod)
        var managerEmail = "manager@example.com";
        var existing = await userMgr.FindByEmailAsync(managerEmail);
        if (existing is null)
        {
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                Email = managerEmail,
                UserName = managerEmail,
                EmailConfirmed = true
            };
            var result = await userMgr.CreateAsync(user, "P@ssw0rd!123");
            if (result.Succeeded)
                await userMgr.AddToRoleAsync(user, "Manager");
        }

        // 3) Scopes
        async Task EnsureScope(string name, string? display = null)
        {
            if (await scopeMgr.FindByNameAsync(name, ct) is null)
            {
                await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = name,
                    DisplayName = display ?? name
                }, ct);
            }
        }
        await EnsureScope(Scopes.OpenId, "OpenID");
        await EnsureScope(Scopes.Email, "Email");
        await EnsureScope(Scopes.Profile, "Profile");
        await EnsureScope(Scopes.OfflineAccess, "Offline access");
        await EnsureScope("onboarding.read", "Onboarding read");
        await EnsureScope("onboarding.write", "Onboarding write");

        // 4) Nuxt SSR public client (Authorization Code + PKCE)
        if (await appMgr.FindByClientIdAsync("nuxt-ssr", ct) is null)
        {
            await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "nuxt-ssr",
                ConsentType = ConsentTypes.Implicit, // no consent screen for first pass (adjust later)
                DisplayName = "Nuxt Frontend",
                ClientType = ClientTypes.Public,
                RedirectUris =
                {
                    new Uri("https://nuxt.example.com/callback") // CHANGE
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://nuxt.example.com/logout-callback") // CHANGE
                },
                Permissions =
                {
                    // Endpoint permissions (7.x)
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.Revocation,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    // (Public SPA/SSR typically should NOT get Introspection)
                
                    // Grant types
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                
                    // Response types
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                
                    // Scope permissions:
                    // NOTE: "openid" & "offline_access" DON'T need explicit permission entries in 7.x docs.
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Prefixes.Scope + "onboarding.read",
                    OpenIddictConstants.Permissions.Prefixes.Scope + "onboarding.write"
                },
                                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }

            }, ct);
        }

        // 5) YARP Gateway confidential client (for future use)
        if (await appMgr.FindByClientIdAsync("yarp-gateway", ct) is null)
        {
            await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "yarp-gateway",
                ClientSecret = "dev-only-change-me",
                DisplayName = "YARP Gateway",
                ClientType = ClientTypes.Confidential,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.ClientCredentials,
                    "onboarding.read"
                }
            }, ct);
        }
    }
}
