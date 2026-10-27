using System.Security.Cryptography;
using System.Text;
using AuthServer.Infrastructure;
using AuthServer.Logic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Endpoints;

public static class TokenEndpoint
{
    public static void MapToken(this IEndpointRouteBuilder app)
    {
        app.MapPost("/connect/token", HandleAsync).DisableAntiforgery();
    }

    private static async Task<IResult> HandleAsync(HttpContext ctx, HttpRequest http, [FromServices] AuthDbContext db)
    {
        if (!http.HasFormContentType)
            return OAuthResults.TokenError("invalid_request", "Content-Type must be application/x-www-form-urlencoded.");

        var form = await http.ReadFormAsync();
        var grantType = form["grant_type"].ToString();

        if (string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
        {
            var code = form["code"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var clientId = form["client_id"].ToString();
            var codeVerifier = form["code_verifier"].ToString();

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(redirectUri) || string.IsNullOrEmpty(clientId))
                return OAuthResults.TokenError("invalid_request", "code, redirect_uri, client_id required.");

            var rec = await db.AuthorizationCodes.FirstOrDefaultAsync(x => x.Code == code);
            if (rec is null || rec.ExpiresUtc < DateTime.UtcNow || rec.Used)
                return OAuthResults.TokenError("invalid_grant", "Authorization code is invalid, expired, or already used.");

            if (!string.Equals(rec.ClientId, clientId, StringComparison.Ordinal) ||
                !string.Equals(rec.RedirectUri, redirectUri, StringComparison.Ordinal))
                return OAuthResults.TokenError("invalid_grant", "client_id or redirect_uri mismatch.");

            // PKCE verification (if challenge was used)
            if (!string.IsNullOrEmpty(rec.CodeChallenge))
            {
                if (string.IsNullOrEmpty(codeVerifier))
                    return OAuthResults.TokenError("invalid_request", "code_verifier required when PKCE was used.");

                string computed;
                if (string.Equals(rec.CodeChallengeMethod, "S256", StringComparison.Ordinal))
                {
                    using var sha = SHA256.Create();
                    var bytes = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                    computed = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                }
                else computed = codeVerifier;

                if (!string.Equals(computed, rec.CodeChallenge, StringComparison.Ordinal))
                    return OAuthResults.TokenError("invalid_grant", "PKCE verification failed.");
            }

            rec.Used = true;
            await db.SaveChangesAsync();

            var tokenSvc = ctx.RequestServices.GetRequiredService<TokenService>();
            var (access, exp, refresh) = await tokenSvc.IssueForAuthCodeAsync(rec);

            return OAuthResults.Json(new
            {
                access_token = access,
                token_type = "Bearer",
                expires_in = (int)TimeSpan.FromMinutes(10).TotalSeconds,
                refresh_token = refresh,
                scope = rec.ScopeCsv
            });
        }
        else if (string.Equals(grantType, "client_credentials", StringComparison.Ordinal))
        {
            string? clientId = form["client_id"];
            string? clientSecret = form["client_secret"];

            // Support client_secret_basic
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                if (http.Headers.TryGetValue("Authorization", out var auth) && auth.Count > 0)
                {
                    var val = auth.ToString();
                    if (val.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            var raw = val["Basic ".Length..].Trim();
                            var bytes = Convert.FromBase64String(raw);
                            var pair = Encoding.ASCII.GetString(bytes);
                            var idx = pair.IndexOf(':');
                            if (idx > -1)
                            {
                                clientId = Uri.UnescapeDataString(pair[..idx]);
                                clientSecret = Uri.UnescapeDataString(pair[(idx + 1)..]);
                            }
                        }
                        catch { /* ignore */ }
                    }
                }
            }

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                return OAuthResults.InvalidClient("Missing client credentials.");

            var client = await db.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client is null || !client.IsConfidential || client.ClientSecretHash == null || client.ClientSecretSalt == null)
                return OAuthResults.TokenError("unauthorized_client", "Client is not allowed to use this grant.");

            if (!AuthServer.Security.SecretHasher.Verify(clientSecret!, client.ClientSecretHash, client.ClientSecretSalt))
                return OAuthResults.InvalidClient("Invalid client secret.");

            // Scope: if omitted, issue all allowed scopes; else must be subset of allowed
            var requestedScope = form["scope"].ToString();
            var allowed = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.AllowedScopesJson) ?? Array.Empty<string>();
            string scopeToIssue = requestedScope;
            if (string.IsNullOrWhiteSpace(scopeToIssue))
            {
                scopeToIssue = string.Join(' ', allowed);
            }
            else if (!AuthServer.Logic.OAuthHelpers.IsSubsetOfScopes(scopeToIssue, allowed))
            {
                return OAuthResults.TokenError("invalid_scope");
            }

            var tokenSvc = ctx.RequestServices.GetRequiredService<TokenService>();
            var (access, exp) = tokenSvc.IssueForClientCredentials(client, scopeToIssue);
            return OAuthResults.Json(new
            {
                access_token = access,
                token_type = "Bearer",
                expires_in = (int)TimeSpan.FromMinutes(10).TotalSeconds,
                scope = scopeToIssue
            });
        }
        else if (string.Equals(grantType, "refresh_token", StringComparison.Ordinal))
        {
            var refresh = form["refresh_token"].ToString();
            var requestedScope = form["scope"].ToString(); // optional, for scope narrowing

            if (string.IsNullOrEmpty(refresh))
                return OAuthResults.TokenError("invalid_request", "refresh_token required.");

            try
            {
                var tokenSvc = ctx.RequestServices.GetRequiredService<TokenService>();
                var (access, exp, newRefresh) = await tokenSvc.ExchangeRefreshAsync(refresh, string.IsNullOrWhiteSpace(requestedScope) ? null : requestedScope);
                return OAuthResults.Json(new
                {
                    access_token = access,
                    token_type = "Bearer",
                    expires_in = (int)TimeSpan.FromMinutes(10).TotalSeconds,
                    refresh_token = newRefresh,
                    scope = string.IsNullOrWhiteSpace(requestedScope) ? null : requestedScope
                });
            }
            catch (InvalidOperationException ioe) when (ioe.Message == "invalid_refresh")
            {
                return OAuthResults.TokenError("invalid_grant");
            }
            catch (InvalidOperationException ioe) when (ioe.Message == "reused_refresh_detected")
            {
                // Reuse detected: family revoked — respond with invalid_grant (don’t reveal details)
                return OAuthResults.TokenError("invalid_grant");
            }
            catch (InvalidOperationException ioe) when (ioe.Message == "invalid_scope")
            {
                return OAuthResults.TokenError("invalid_scope");
            }
            catch
            {
                return OAuthResults.TokenError("invalid_grant");
            }
        }
        else
        {
            return OAuthResults.TokenError("unsupported_grant_type");
        }
    }
}
