using System.Text.Json;
using AuthServer.Domain;
using AuthServer.Infrastructure;
using AuthServer.Logic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Endpoints;

public static class AuthorizeEndpoint
{
    public static void MapAuthorize(this IEndpointRouteBuilder app)
    {
        app.MapGet("/connect/authorize", HandleAsync);
    }

    public sealed class AuthorizeRequest
    {
        public string? response_type { get; init; }
        public string? client_id { get; init; }
        public string? redirect_uri { get; init; }
        public string? scope { get; init; }
        public string? state { get; init; }
        public string? code_challenge { get; init; }
        public string? code_challenge_method { get; init; }
    }

    private static async Task<IResult> HandleAsync([AsParameters] AuthorizeRequest req, [FromServices] AuthDbContext db)
    {
        // Reject the historic Implicit flow early and clearly (RFC 6749 §4.2)
        if (string.Equals(req.response_type, "token", StringComparison.Ordinal))
        {
            // If we have a safe redirect, send an OAuth error redirect; otherwise, return 400.
            if (!string.IsNullOrWhiteSpace(req.client_id))
            {
                var client = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == req.client_id);
                if (client is not null)
                {
                    var registered = JsonSerializer.Deserialize<string[]>(client.RedirectUrisJson) ?? Array.Empty<string>();
                    var redirect = !string.IsNullOrEmpty(req.redirect_uri)
                        ? (registered.Contains(req.redirect_uri, StringComparer.Ordinal) ? req.redirect_uri : null)
                        : (registered.Length == 1 ? registered[0] : null);

                    if (!string.IsNullOrEmpty(redirect))
                        return OAuthResults.RedirectError(redirect!, "unsupported_response_type", "Implicit flow is not supported.", req.state);
                }
            }
            return Results.BadRequest(new { error = "unsupported_response_type", error_description = "Implicit flow is not supported." });
        }

        // Only Authorization Code is supported
        if (!string.Equals(req.response_type, "code", StringComparison.Ordinal))
            return Results.BadRequest(new { error = "unsupported_response_type" });

        if (string.IsNullOrWhiteSpace(req.client_id))
            return Results.BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

        var clientRec = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == req.client_id);
        if (clientRec is null)
            return Results.BadRequest(new { error = "unauthorized_client" });

        // Redirect URI selection (exact match or single registered)
        var registeredUris = JsonSerializer.Deserialize<string[]>(clientRec.RedirectUrisJson) ?? Array.Empty<string>();
        string? redirectUri = req.redirect_uri;
        if (!string.IsNullOrEmpty(redirectUri))
        {
            if (!registeredUris.Contains(redirectUri, StringComparer.Ordinal))
                return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri not registered" });
        }
        else
        {
            if (registeredUris.Length == 1) redirectUri = registeredUris[0];
            else return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri required" });
        }

        // Scope ⊆ allowed
        var allowed = JsonSerializer.Deserialize<string[]>(clientRec.AllowedScopesJson) ?? Array.Empty<string>();
        if (!OAuthHelpers.IsSubsetOfScopes(req.scope ?? "", allowed))
            return OAuthResults.RedirectError(redirectUri!, "invalid_scope", state: req.state);

        // PKCE policy: required for public clients, S256 only; confidential may omit
        if (!clientRec.IsConfidential)
        {
            if (string.IsNullOrEmpty(req.code_challenge) || string.IsNullOrEmpty(req.code_challenge_method))
                return OAuthResults.RedirectError(redirectUri!, "invalid_request", "PKCE required for public clients.", req.state);

            if (!string.Equals(req.code_challenge_method, "S256", StringComparison.Ordinal))
                return OAuthResults.RedirectError(redirectUri!, "invalid_request", "Only S256 is allowed for public clients.", req.state);
        }
        else
        {
            if (!string.IsNullOrEmpty(req.code_challenge_method) &&
                !string.Equals(req.code_challenge_method, "S256", StringComparison.Ordinal) &&
                !string.Equals(req.code_challenge_method, "plain", StringComparison.Ordinal))
                return OAuthResults.RedirectError(redirectUri!, "invalid_request", "unsupported code_challenge_method", req.state);
        }

        // (Dev) Assume user is authenticated & consented
        var resourceOwnerId = await DevUser.GetAliceId(db);

        // Issue authorization code
        var code = OAuthHelpers.GenerateCode();
        var record = new AuthorizationCode
        {
            Code = code,
            ClientDbId = clientRec.Id,
            ClientId = clientRec.ClientId,
            ResourceOwnerId = resourceOwnerId,
            RedirectUri = redirectUri!,
            ScopeCsv = (req.scope ?? "").Trim(),
            CodeChallenge = req.code_challenge,
            CodeChallengeMethod = req.code_challenge_method,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(5),
            Used = false
        };
        db.AuthorizationCodes.Add(record);
        await db.SaveChangesAsync();

        // Success redirect
        var ub = new UriBuilder(redirectUri!);
        var q = System.Web.HttpUtility.ParseQueryString(ub.Query);
        q["code"] = code;
        if (!string.IsNullOrEmpty(req.state)) q["state"] = req.state;
        ub.Query = q.ToString();

        return Results.Redirect(ub.ToString());
    }
}
