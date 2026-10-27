using AuthServer.Data;
using AuthServer.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Infrastructure;

public static class Seed
{
    public static async Task InitializeAsync(IServiceProvider services, string issuer)
    {
        using var scope = services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await SeedRolesAsync(scope.ServiceProvider);
        await SeedClientsAsync(scope.ServiceProvider, issuer);
        await SeedScopesAsync(scope.ServiceProvider);
    }

    private static async Task SeedRolesAsync(IServiceProvider services)
    {
        var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();

        string[] roles = { "Manager", "Onboardee" };

        foreach (var roleName in roles)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
            }
        }
    }

    private static async Task SeedClientsAsync(IServiceProvider services, string issuer)
    {
        var manager = services.GetRequiredService<IOpenIddictApplicationManager>();

        // Nuxt SSR Client (Authorization Code + PKCE)
        var nuxtClient = await manager.FindByClientIdAsync("nuxt-ssr");
        if (nuxtClient is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "nuxt-ssr",
                ClientType = ClientTypes.Public, // No client secret for public clients
                DisplayName = "Nuxt SSR Application",

                // ✅ CRITICAL: Redirect URIs
                RedirectUris =
                {
                    new Uri("https://localhost:3000/auth/callback"),
                    new Uri("http://localhost:3000/auth/callback")
                },

                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:3000"),
                    new Uri("http://localhost:3000")
                },

                // ✅ CRITICAL: Permissions
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Revocation,
                    Permissions.Endpoints.EndSession,

                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,

                    Permissions.ResponseTypes.Code,
                    
                    // ✅ Scopes
                    Permissions.Prefixes.Scope + Scopes.OpenId,
                    Permissions.Prefixes.Scope + Scopes.Email,
                    Permissions.Prefixes.Scope + Scopes.Profile,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Permissions.Prefixes.Scope + "onboarding.read",
                    Permissions.Prefixes.Scope + "onboarding.write"
                },

                // ✅ CRITICAL: PKCE requirement
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }

        // Gateway Client (for introspection)
        var gatewayClient = await manager.FindByClientIdAsync("yarp-gateway");
        if (gatewayClient is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "yarp-gateway",
                ClientSecret = "dev-only-change-me", // Use a real secret in production!
                ClientType = ClientTypes.Confidential,
                DisplayName = "YARP Gateway",
                Permissions =
                {
                    Permissions.Endpoints.Introspection,
                    Permissions.Endpoints.Revocation
                }
            });
        }
    }

    private static async Task SeedScopesAsync(IServiceProvider services)
    {
        var manager = services.GetRequiredService<IOpenIddictScopeManager>();

        var scopes = new[]
        {
            new { Name = "onboarding.read", DisplayName = "Read onboarding data", Description = "Allows reading onboarding information" },
            new { Name = "onboarding.write", DisplayName = "Write onboarding data", Description = "Allows modifying onboarding information" }
        };

        foreach (var scope in scopes)
        {
            var existingScope = await manager.FindByNameAsync(scope.Name);
            if (existingScope is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = scope.Name,
                    DisplayName = scope.DisplayName,
                    Description = scope.Description,
                    Resources = { "resource-api" }
                });
            }
        }
    }
}