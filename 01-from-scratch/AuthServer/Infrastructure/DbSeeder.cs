using System.Text.Json;
using AuthServer.Domain;
using AuthServer.Security;

namespace AuthServer.Infrastructure;

public static class DbSeeder
{
    public static async Task SeedAsync(AuthDbContext db)
    {
        if (!db.ResourceOwners.Any())
        {
            var (uHash, uSalt) = SecretHasher.Hash("P@ssw0rd!");
            db.ResourceOwners.Add(new ResourceOwner { Username = "alice", PasswordHash = uHash, PasswordSalt = uSalt });
        }

        if (!db.OAuthClients.Any(c => c.ClientId == "demo-spa"))
        {
            var (hash, salt) = AuthServer.Security.SecretHasher.Hash("svc-secret-very-strong");
            db.OAuthClients.Add(new OAuthClient
            {
                ClientId = "demo-spa",
                ClientSecretHash = hash,
                ClientSecretSalt = salt,
                IsConfidential = true,
                DisplayName = "Weather Reporter Service",
                // JSON string array; AuthorizeEndpoint parses it with JsonSerializer.Deserialize<string[]>
                RedirectUrisJson = System.Text.Json.JsonSerializer.Serialize(new[] { "http://localhost:4200/callback" }),
                AllowedScopesJson = System.Text.Json.JsonSerializer.Serialize(new[] { "weather.read" })
            });
            await db.SaveChangesAsync();
        }


        if (!db.Scopes.Any())
        {
            db.Scopes.Add(new Scope { Name = "weather.read", DisplayName = "Read weather" });
            await db.SaveChangesAsync();
        }

        await db.SaveChangesAsync();
    }
}
