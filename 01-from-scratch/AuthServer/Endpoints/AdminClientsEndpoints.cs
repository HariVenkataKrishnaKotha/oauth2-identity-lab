using System.Text.Json;
using AuthServer.Domain;
using AuthServer.Infrastructure;
using AuthServer.Logic;
using AuthServer.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Endpoints;

public static class AdminClientsEndpoints
{
    public static void MapAdminClients(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/admin/clients")
            .AddEndpointFilter(new LocalOnlyFilter()) // dev safety: only allow loopback
            .WithTags("Admin: Clients");

        grp.MapGet("/", ListAsync);
        grp.MapPost("/register", RegisterAsync);
        grp.MapPost("/{clientId}/rotate-secret", RotateSecretAsync);
    }

    // Dev-only filter: allow only loopback callers
    private sealed class LocalOnlyFilter : IEndpointFilter
    {
        public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
        {
            var remote = ctx.HttpContext.Connection.RemoteIpAddress;
            if (remote is null || !(remote.IsLoopback() ?? false))
                return ValueTask.FromResult<object?>(Results.Forbid());
            return next(ctx);
        }
    }

    private static async Task<IResult> ListAsync([FromServices] AuthDbContext db)
    {
        var raw = await db.OAuthClients.AsNoTracking()
            .Select(c => new {
                c.ClientId,
                c.IsConfidential,
                c.TokenEndpointAuthMethod,
                c.DisplayName,
                RedirectUrisJson = c.RedirectUrisJson,
                AllowedScopesJson = c.AllowedScopesJson,
                c.CreatedUtc
            })
            .ToListAsync();

        var items = raw.Select(c => new {
            c.ClientId,
            c.IsConfidential,
            c.TokenEndpointAuthMethod,
            c.DisplayName,
            RedirectUris = System.Text.Json.JsonSerializer.Deserialize<string[]>(c.RedirectUrisJson)
                           ?? Array.Empty<string>(),
            AllowedScopes = System.Text.Json.JsonSerializer.Deserialize<string[]>(c.AllowedScopesJson)
                           ?? Array.Empty<string>(),
            c.CreatedUtc
        });

        return Results.Ok(items);
    }


    public sealed record RegisterRequest(
        string ClientType,                    // "public" | "confidential"
        string[] RedirectUris,
        string[] AllowedScopes,
        string? DisplayName = null,
        string TokenEndpointAuthMethod = "client_secret_basic" // for confidential
    );

    public sealed record RegisterResponse(
        string ClientId,
        string? ClientSecret,                 // only for confidential; show once
        bool IsConfidential
    );

    private static async Task<IResult> RegisterAsync([FromBody] RegisterRequest req, [FromServices] AuthDbContext db)
    {
        var isConf = string.Equals(req.ClientType, "confidential", StringComparison.OrdinalIgnoreCase);
        if (req.RedirectUris is null || req.RedirectUris.Length == 0)
            return Results.BadRequest(new { error = "invalid_redirect_uris" });

        foreach (var r in req.RedirectUris)
            if (!Validation.IsValidRedirectUri(r))
                return Results.BadRequest(new { error = "invalid_redirect_uri", uri = r });

        if (!Validation.IsValidScopeList(string.Join(' ', req.AllowedScopes ?? Array.Empty<string>())))
            return Results.BadRequest(new { error = "invalid_scope" });

        // Check scopes exist (optional, best effort)
        var allowedScopes = req.AllowedScopes ?? Array.Empty<string>();

        var clientId = ClientIdSecret.NewClientId();
        byte[]? secretHash = null;
        byte[]? secretSalt = null;
        string? rawSecret = null;

        if (isConf)
        {
            rawSecret = ClientIdSecret.NewClientSecret();
            (secretHash, secretSalt) = SecretHasher.Hash(rawSecret);
        }

        var client = new OAuthClient
        {
            ClientId = clientId,
            IsConfidential = isConf,
            TokenEndpointAuthMethod = isConf ? (req.TokenEndpointAuthMethod ?? "client_secret_basic") : "none",
            DisplayName = req.DisplayName,
            ClientSecretHash = secretHash,
            ClientSecretSalt = secretSalt,
            RedirectUrisJson = JsonSerializer.Serialize(req.RedirectUris),
            AllowedScopesJson = JsonSerializer.Serialize(allowedScopes)
        };

        db.OAuthClients.Add(client);
        await db.SaveChangesAsync();

        return Results.Ok(new RegisterResponse(clientId, rawSecret, isConf));
    }

    private static async Task<IResult> RotateSecretAsync(string clientId, [FromServices] AuthDbContext db)
    {
        var client = await db.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client is null) return Results.NotFound();

        if (!client.IsConfidential)
            return Results.BadRequest(new { error = "public_client_has_no_secret" });

        var newSecret = ClientIdSecret.NewClientSecret();
        var (hash, salt) = SecretHasher.Hash(newSecret);
        client.ClientSecretHash = hash;
        client.ClientSecretSalt = salt;
        await db.SaveChangesAsync();

        return Results.Ok(new { client_id = clientId, client_secret = newSecret });
    }

    private static bool? IsLoopback(this System.Net.IPAddress ip)
    {
        if (System.Net.IPAddress.IsLoopback(ip)) return true;
        // For IPv6-mapped loopback (::ffff:127.0.0.1)
        if (ip.ToString().StartsWith("::ffff:127.0.0.1")) return true;
        return false;
    }
}
