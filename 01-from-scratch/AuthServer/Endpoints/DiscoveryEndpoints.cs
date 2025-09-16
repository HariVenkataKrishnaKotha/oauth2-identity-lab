using System.Security.Cryptography;
using AuthServer.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Endpoints;

public static class DiscoveryEndpoints
{
    public static void MapDiscovery(this IEndpointRouteBuilder app)
    {
        app.MapGet("/oauth/.well-known/jwks.json", GetJwks)
           .WithTags("Discovery");

        app.MapGet("/oauth/.well-known/openid-configuration", GetConfig)
           .WithTags("Discovery");
    }

    private static IResult GetJwks([FromServices] SecurityKey pubKey)
    {
        if (pubKey is not RsaSecurityKey rsa || rsa.Rsa == null)
            return Results.Problem("No RSA public key available");

        var p = rsa.Rsa.ExportParameters(false);

        static string B64Url(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var jwk = new
        {
            kty = "RSA",
            use = "sig",
            kid = rsa.KeyId,
            e = B64Url(p.Exponent!),
            n = B64Url(p.Modulus!)
        };

        return Results.Json(new { keys = new[] { jwk } });
    }

    private static IResult GetConfig(HttpContext ctx)
    {
        // Must match OAuthTokenOptions.Issuer (Program.cs registration)
        var issuer = "http://localhost:5018";

        var meta = new
        {
            issuer,
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            jwks_uri = $"{issuer}/oauth/.well-known/jwks.json",

            // Simple capability set for our server
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code", "client_credentials", "refresh_token" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
            code_challenge_methods_supported = new[] { "plain", "S256" },
            scopes_supported = new[] { "weather.read" }
        };

        return Results.Json(meta);
    }
}
