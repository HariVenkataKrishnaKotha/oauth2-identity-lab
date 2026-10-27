using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace ResourceApi.Security;

public static class BearerErrors
{
    public static (string error, string description) FromAuthenticateFailure(Exception? ex)
    {
        if (ex is null) return ("invalid_token", "No access token was provided.");
        return ex switch
        {
            SecurityTokenExpiredException => ("invalid_token", "The access token expired."),
            SecurityTokenInvalidSignatureException => ("invalid_token", "The token signature is invalid."),
            SecurityTokenInvalidAudienceException => ("invalid_token", "The token audience is invalid."),
            SecurityTokenInvalidIssuerException => ("invalid_token", "The token issuer is invalid."),
            SecurityTokenNoExpirationException => ("invalid_token", "The token has no expiration."),
            SecurityTokenInvalidLifetimeException => ("invalid_token", "The token lifetime is invalid."),
            _ => ("invalid_token", ex.Message.Replace("\r", " ").Replace("\n", " "))
        };
    }

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
}
