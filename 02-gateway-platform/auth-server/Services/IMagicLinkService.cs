public interface IMagicLinkService
{
    Task<string> CreateVerifySessionAsync(Guid tempUserId, TimeSpan ttl, CancellationToken ct);
    Task<(bool ok, Guid tempUserId)> RedeemAsync(string verifySessionId, CancellationToken ct);
}
