using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthServer.Domain;
using AuthServer.Infrastructure;
using AuthServer.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Logic;

public sealed class TokenService
{
    private readonly AuthDbContext _db;
    private readonly SigningCredentials _signing;
    private readonly SecurityKey _publicKey;
    private readonly OAuthTokenOptions _opt;

    public TokenService(AuthDbContext db, SigningCredentials signing, SecurityKey publicKey, OAuthTokenOptions opt)
    {
        _db = db;
        _signing = signing;
        _publicKey = publicKey;
        _opt = opt;
    }

    public async Task<(string accessToken, DateTimeOffset expires, string? refreshHandle)>
        IssueForAuthCodeAsync(AuthorizationCode codeRec)
    {
        var sub = codeRec.ResourceOwnerId.ToString();
        var clientId = codeRec.ClientId;
        var scope = (codeRec.ScopeCsv ?? "").Trim();

        var (jwt, exp) = CreateJwt(sub, clientId, scope);

        // start a new family for this chain of refreshes
        var familyId = Guid.NewGuid();
        var refresh = await IssueRefreshAsync(codeRec.ResourceOwnerId, codeRec.ClientDbId, scope, familyId, rotationParent: null);

        return (jwt, exp, refresh);
    }

    public (string accessToken, DateTimeOffset expires)
        IssueForClientCredentials(OAuthClient client, string scope)
    {
        var sub = $"client:{client.ClientId}";
        var (jwt, exp) = CreateJwt(sub, client.ClientId, scope ?? "");
        return (jwt, exp);
    }

    public async Task<(string newAccess, DateTimeOffset expires, string newRefresh)>
        ExchangeRefreshAsync(string handle, string? requestedScope = null)
    {
        var rec = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.Handle == handle);
        if (rec is null || rec.ExpiresUtc < DateTime.UtcNow)
            throw new InvalidOperationException("invalid_refresh");

        if (rec.Revoked)
        {
            await RevokeFamilyAsync(rec.FamilyId);
            rec.CompromisedAtUtc ??= DateTime.UtcNow;
            await _db.SaveChangesAsync();
            throw new InvalidOperationException("reused_refresh_detected");
        }

        var client = await _db.OAuthClients.FirstAsync(c => c.Id == rec.ClientDbId);

        // scope narrowing:
        // - must be subset of the original issued scopes
        // - must be subset of the client's allowed scopes
        var originalScopeCsv = (rec.ScopeCsv ?? "").Trim();
        var allowedScopes = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.AllowedScopesJson) ?? Array.Empty<string>();

        var scopeNew = originalScopeCsv;
        if (!string.IsNullOrWhiteSpace(requestedScope))
        {
            if (!OAuthHelpers.IsSubsetOfScopes(requestedScope, originalScopeCsv) ||
                !OAuthHelpers.IsSubsetOfScopes(requestedScope, allowedScopes))
                throw new InvalidOperationException("invalid_scope");

            scopeNew = requestedScope.Trim();
        }

        // rotate
        rec.Revoked = true;
        var newHandle = await IssueRefreshAsync(rec.ResourceOwnerId, rec.ClientDbId, scopeNew, rec.FamilyId, rotationParent: rec.Handle);
        rec.ReplacedBy = newHandle;
        await _db.SaveChangesAsync();

        var sub = rec.ResourceOwnerId.ToString();
        var (jwt, exp) = CreateJwt(sub, client.ClientId, scopeNew);
        return (jwt, exp, newHandle);
    }

    private async Task RevokeFamilyAsync(Guid familyId)
    {
        var all = await _db.RefreshTokens.Where(r => r.FamilyId == familyId && !r.Revoked).ToListAsync();
        foreach (var r in all)
        {
            r.Revoked = true;
            r.CompromisedAtUtc ??= DateTime.UtcNow;
        }
    }

    private (string token, DateTimeOffset expires) CreateJwt(string sub, string clientId, string scope)
    {
        var now = DateTime.UtcNow;
        var exp = now.Add(_opt.AccessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            new("client_id", clientId),
            new("scope", scope),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, ToUnix(now).ToString(), ClaimValueTypes.Integer64)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = _opt.Issuer,
            Audience = _opt.Audience,
            NotBefore = now,
            Expires = exp,
            SigningCredentials = _signing
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(descriptor);
        var s = handler.WriteToken(token); // for debugging: can use https://jwt.io to decode/verify with the public key
        return (handler.WriteToken(token), new DateTimeOffset(exp));
    }

    private async Task<string> IssueRefreshAsync(Guid resourceOwnerId, Guid clientDbId, string scope, Guid familyId, string? rotationParent)
    {
        var handle = Base64Url(RandomNumberGenerator.GetBytes(32));
        var rec = new RefreshToken
        {
            Handle = handle,
            FamilyId = familyId,
            ClientDbId = clientDbId,
            ResourceOwnerId = resourceOwnerId,
            ScopeCsv = scope,
            ExpiresUtc = DateTime.UtcNow.Add(_opt.RefreshTokenLifetime),
            Revoked = false,
            RotationParent = rotationParent
        };
        _db.RefreshTokens.Add(rec);
        await _db.SaveChangesAsync();
        return handle;
    }

    private static string Base64Url(byte[] b)
        => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static long ToUnix(DateTime d)
        => (long)Math.Floor((d.ToUniversalTime() - DateTime.UnixEpoch).TotalSeconds);
}
