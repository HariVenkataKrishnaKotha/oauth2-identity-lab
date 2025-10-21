using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Gateway.Auth;

public interface ITokenAuthenticator
{
    Task<(bool ok, ClaimsPrincipal? principal, string source, string? error)> AuthenticateAsync(string bearerToken, CancellationToken ct);
}

public sealed class TokenAuthenticator : ITokenAuthenticator
{
    private readonly IJwksProvider _jwks;
    private readonly IConfiguration _cfg;
    private readonly IIntrospectionClient _introspect;
    private readonly IDistributedCache _cache;
    private readonly ILogger<TokenAuthenticator> _log;

    private readonly JwtSecurityTokenHandler _handler = new();

    public TokenAuthenticator(IJwksProvider jwks, IConfiguration cfg, IIntrospectionClient introspect, IDistributedCache cache, ILogger<TokenAuthenticator> log)
    {
        _jwks = jwks;
        _cfg = cfg;
        _introspect = introspect;
        _cache = cache;
        _log = log;
    }

    public async Task<(bool ok, ClaimsPrincipal? principal, string source, string? error)>
    AuthenticateAsync(string bearerToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bearerToken))
            return (false, null, "none", "empty");

        var mode = (_cfg["Gateway:ValidationMode"] ?? "JwtFirst").Trim();
        var preferIntrospection = mode.Equals("PreferIntrospection", StringComparison.OrdinalIgnoreCase);
        var introspectionOnly = mode.Equals("IntrospectionOnly", StringComparison.OrdinalIgnoreCase);

        // Helper local function: do introspection once
        async Task<(bool ok, ClaimsPrincipal? principal, string? err)> IntrospectOnce()
        {
            var (active, p, err) = await _introspect.IntrospectAsync(bearerToken, ct);
            return (active, p, err);
        }

        // Prefer introspection path — best for ephemeral keys
        if (preferIntrospection || introspectionOnly)
        {
            var (ok, p, err) = await IntrospectOnce();
            if (ok) return (true, p, "introspection", null);
            if (introspectionOnly) return (false, null, "introspection", err);
            // fall through to JWT as a backup if PreferIntrospection
        }

        // JWT-first path (or backup if PreferIntrospection failed)
        JwtSecurityToken? jwt = null;
        try { jwt = new JwtSecurityTokenHandler().ReadJwtToken(bearerToken); } catch { /* opaque token */ }

        // If no KID or not a JWT, go straight to introspection
        if (jwt is null || string.IsNullOrEmpty(jwt.Header.Kid))
        {
            var (ok, p, err) = await IntrospectOnce();
            return ok ? (true, p, "introspection", null) : (false, null, "introspection", err);
        }

        try
        {
            var jwks = await _jwks.GetAsync(ct);
            var keys = jwks.GetSigningKeys();
            var audiences = _cfg.GetSection("Gateway:ExpectedAudiences").Get<string[]>() ?? Array.Empty<string>();
            var issuer = _cfg["Gateway:Issuer"] ?? throw new InvalidOperationException("Gateway:Issuer missing");

            var tvp = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = audiences.Length > 0,
                ValidAudiences = audiences,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(_cfg.GetValue("Gateway:TokenClockSkewSeconds", 60))
            };

            var handler = new JwtSecurityTokenHandler();
            var p = handler.ValidateToken(bearerToken, tvp, out _);
            return (true, p, "jwt", null);
        }
        catch (SecurityTokenSignatureKeyNotFoundException)
        {
            // Ephemeral key likely rotated. Invalidate JWKS, retry, else introspect.
            await _jwks.InvalidateAsync(ct);
            try
            {
                var jwks = await _jwks.GetAsync(ct);
                var keys = jwks.GetSigningKeys();
                var audiences = _cfg.GetSection("Gateway:ExpectedAudiences").Get<string[]>() ?? Array.Empty<string>();
                var issuer = _cfg["Gateway:Issuer"]!;
                var tvp = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = keys,
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = audiences.Length > 0,
                    ValidAudiences = audiences,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(_cfg.GetValue("Gateway:TokenClockSkewSeconds", 60))
                };
                var handler = new JwtSecurityTokenHandler();
                var p = handler.ValidateToken(bearerToken, tvp, out _);
                return (true, p, "jwt", null);
            }
            catch
            {
                // Fall back
                var (ok, p, err) = await IntrospectOnce();
                return ok ? (true, p, "introspection", null) : (false, null, "introspection", err);
            }
        }
        catch (Exception)
        {
            // Any other JWT parse/validation error -> introspection fallback
            var (ok, p, err) = await IntrospectOnce();
            return ok ? (true, p, "introspection", null) : (false, null, "introspection", err);
        }
    }


}
