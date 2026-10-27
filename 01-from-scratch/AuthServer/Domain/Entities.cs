namespace AuthServer.Domain;

public sealed class ResourceOwner
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Username { get; set; } = default!;
    public byte[] PasswordHash { get; set; } = default!;
    public byte[] PasswordSalt { get; set; } = default!;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class OAuthClient
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ClientId { get; set; } = default!;
    public byte[]? ClientSecretHash { get; set; }
    public byte[]? ClientSecretSalt { get; set; }
    public bool IsConfidential { get; set; }
    public string TokenEndpointAuthMethod { get; set; } = "client_secret_basic";
    public string? DisplayName { get; set; }
    public string RedirectUrisJson { get; set; } = "[]";
    public string AllowedScopesJson { get; set; } = "[]";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class AuthorizationCode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Code { get; set; } = default!;
    public Guid ClientDbId { get; set; }
    public string ClientId { get; set; } = default!;
    public Guid ResourceOwnerId { get; set; }
    public string RedirectUri { get; set; } = default!;
    public string ScopeCsv { get; set; } = "";
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public bool Used { get; set; }
}

public sealed class Scope
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = default!;
    public string DisplayName { get; set; } = default!;
    public string? Description { get; set; }
}

public sealed class ResourceOwnerConsent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ResourceOwnerId { get; set; }
    public Guid ClientDbId { get; set; }
    public string ScopeCsv { get; set; } = "";
    public DateTime GrantedUtc { get; set; } = DateTime.UtcNow;
}

// === Refresh Tokens with Rotation + Reuse Detection ===
public sealed class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // Opaque handle returned to client
    public string Handle { get; set; } = default!;

    // Family groups all rotated tokens derived from the first issuance
    public Guid FamilyId { get; set; } = Guid.NewGuid();

    public Guid ClientDbId { get; set; }
    public Guid ResourceOwnerId { get; set; }

    // Scopes originally granted (space-delimited)
    public string ScopeCsv { get; set; } = "";

    public DateTime ExpiresUtc { get; set; }

    // Standard revocation flag (set when rotated or revoked)
    public bool Revoked { get; set; }

    // Rotation lineage (optional)
    public string? RotationParent { get; set; }
    public string? ReplacedBy { get; set; }

    // Reuse detection — set when we detect reuse of a revoked handle
    public DateTime? CompromisedAtUtc { get; set; }
}
