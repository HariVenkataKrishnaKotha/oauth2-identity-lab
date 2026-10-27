using Microsoft.AspNetCore.Http;
using System.Net;
using System.Security.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace ResourceApi.Security;

public static class BearerErrors
{
    // Map exceptions to RFC 6750 error + description
    public static (string error, string description) FromAuthenticateFailure(Exception? ex)
    {
        if (ex is null)
            return ("invalid_token", "No access token was provided.");

        // Common cases
        if (ex is SecurityTokenExpiredException)
            return ("invalid_token", "The access token expired.");
        if (ex is SecurityTokenInvalidSignatureException)
            return ("invalid_token", "The token signature is invalid.");
        if (ex is SecurityTokenInvalidAudienceException)
            return ("invalid_token", "The token audience is invalid.");
        if (ex is SecurityTokenInvalidIssuerException)
            return ("invalid_token", "The token issuer is invalid.");
        if (ex is SecurityTokenNoExpirationException or SecurityTokenInvalidLifetimeException)
            return ("invalid_token", "The token lifetime is invalid.");
        if (ex is AuthenticationException)
            return ("invalid_token", ex.Message);

        // Default
        return ("invalid_token", Sanitize(ex.Message));
    }

    // Build WWW-Authenticate header value per RFC 6750 §3
    public static string BuildWwwAuthenticate(string realm, string? error = null, string? description = null, IEnumerable<string>? scopes = null)
    {
        var parts = new List<string> { $"Bearer realm=\"{Escape(realm)}\"" };
        if (!string.IsNullOrEmpty(error)) parts.Add($"error=\"{Escape(error)}\"");
        if (!string.IsNullOrEmpty(description)) parts.Add($"error_description=\"{Escape(description)}\"");
        if (scopes != null)
        {
            var s = string.Join(' ', scopes);
            if (!string.IsNullOrWhiteSpace(s)) parts.Add($"scope=\"{Escape(s)}\"");
        }
        return string.Join(", ", parts);
    }

    public static void ApplyNoStore(HttpResponse res)
    {
        res.Headers["Cache-Control"] = "no-store";
        res.Headers["Pragma"] = "no-cache";
        res.ContentType = "application/json; charset=utf-8";
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    private static string Sanitize(string s) => s.Replace("\r", " ").Replace("\n", " ");
}
