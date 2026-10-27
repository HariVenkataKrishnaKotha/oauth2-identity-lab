using Microsoft.AspNetCore.Authorization;

namespace ResourceApi.Security;

public sealed class ScopeRequirement : IAuthorizationRequirement
{
    public string RequiredScope { get; }
    public ScopeRequirement(string requiredScope) => RequiredScope = requiredScope;
}

public sealed class ScopeRequirementHandler : AuthorizationHandler<ScopeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        // Access tokens carry a space-delimited "scope" claim
        var scopeClaims = context.User.FindAll("scope").Select(c => c.Value);
        var scopes = string.Join(' ', scopeClaims).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (scopes.Contains(requirement.RequiredScope, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
