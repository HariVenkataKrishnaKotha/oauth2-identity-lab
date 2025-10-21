using AuthServer.Identity;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Controllers;

[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _users;
    public AuthorizationController(UserManager<ApplicationUser> users) => _users = users;

    [HttpGet("/connect/authorize")]
    [Authorize] // must be signed in (cookie)
    public async Task<IActionResult> AuthorizeAsync()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OIDC request missing.");

        var user = await _users.GetUserAsync(User) ?? throw new InvalidOperationException("User missing.");
        var roles = await _users.GetRolesAsync(user);

        // Build the principal used by OpenIddict to mint the code/tokens
        var claims = new List<Claim>
        {
            new(Claims.Subject, user.Id.ToString()),
            new(Claims.Name, user.UserName ?? user.Email ?? user.Id.ToString())
        };

        foreach (var r in roles) claims.Add(new Claim(Claims.Role, r));

        if (roles.Contains("Onboardee") && user.OnboardId is Guid oid)
            claims.Add(new Claim("onboard_id", oid.ToString()));

        if (roles.Contains("Manager"))
            claims.Add(new Claim("perm", "badge_approve")); // fine-grained permission

        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Scopes — honor client request but enforce least privilege
        var allowed = new HashSet<string>
        {
            Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.OfflineAccess,
            "onboarding.read", "onboarding.write"
        };
        principal.SetScopes(request.GetScopes().Where(allowed.Contains));

        // Optional: map scopes → resources (APIs)
        principal.SetResources("resource-api");

        // Mark which claims go into which tokens
        principal.SetDestinations(static claim => claim.Type switch
        {
            Claims.Name or Claims.Subject or Claims.Role => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            "onboard_id" or "perm" => new[] { Destinations.AccessToken },
            _ => new[] { Destinations.AccessToken }
        });

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}
