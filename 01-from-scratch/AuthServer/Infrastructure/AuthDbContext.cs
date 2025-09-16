using AuthServer.Domain;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Infrastructure;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<ResourceOwner> ResourceOwners => Set<ResourceOwner>();
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<Scope> Scopes => Set<Scope>();
    public DbSet<ResourceOwnerConsent> ResourceOwnerConsents => Set<ResourceOwnerConsent>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<ResourceOwner>(e =>
        {
            e.HasIndex(x => x.Username).IsUnique();
            e.Property(x => x.Username).HasMaxLength(200).IsRequired();
            e.Property(x => x.PasswordHash).IsRequired();
            e.Property(x => x.PasswordSalt).IsRequired();
        });

        b.Entity<OAuthClient>(e =>
        {
            e.HasIndex(x => x.ClientId).IsUnique();
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.TokenEndpointAuthMethod).HasMaxLength(50).IsRequired();
            e.Property(x => x.RedirectUrisJson).IsRequired();
            e.Property(x => x.AllowedScopesJson).IsRequired();
        });

        b.Entity<AuthorizationCode>(e =>
        {
            e.HasIndex(x => x.Code).IsUnique();
            e.Property(x => x.Code).HasMaxLength(120).IsRequired();
            e.Property(x => x.RedirectUri).HasMaxLength(2000).IsRequired();
            e.Property(x => x.CodeChallenge).HasMaxLength(255);
            e.Property(x => x.CodeChallengeMethod).HasMaxLength(10);
        });

        b.Entity<Scope>(e =>
        {
            e.HasIndex(x => x.Name).IsUnique();
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
        });

        b.Entity<ResourceOwnerConsent>(e =>
        {
            e.HasIndex(x => new { x.ResourceOwnerId, x.ClientDbId }).IsUnique();
            e.Property(x => x.ScopeCsv).HasMaxLength(1000).IsRequired();
        });

        b.Entity<RefreshToken>(e =>
        {
            e.HasIndex(x => x.Handle).IsUnique();
            e.Property(x => x.Handle).HasMaxLength(200).IsRequired();
            e.Property(x => x.ScopeCsv).HasMaxLength(1000).IsRequired();
            e.Property(x => x.RotationParent).HasMaxLength(200);
            e.Property(x => x.ReplacedBy).HasMaxLength(200);
        });
    }
}
