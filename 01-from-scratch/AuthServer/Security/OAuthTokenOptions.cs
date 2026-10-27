namespace AuthServer.Security;

public sealed class OAuthTokenOptions
{
    public string Issuer { get; init; } = default!;
    public string Audience { get; init; } = default!;
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(30);
}
