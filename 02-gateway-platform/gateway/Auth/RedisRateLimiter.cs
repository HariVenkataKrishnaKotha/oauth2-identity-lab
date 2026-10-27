using StackExchange.Redis;

namespace Gateway.Auth;

public interface IRedisRateLimiter
{
    /// <summary>
    /// Sliding window limiter: returns true if the request should be blocked.
    /// </summary>
    Task<bool> ShouldLimitAsync(string bucketKey, int maxHits, TimeSpan window, CancellationToken ct);
}

public sealed class RedisRateLimiter : IRedisRateLimiter
{
    private readonly IConnectionMultiplexer _mux;
    public RedisRateLimiter(IConnectionMultiplexer mux) => _mux = mux;

    public async Task<bool> ShouldLimitAsync(string bucketKey, int maxHits, TimeSpan window, CancellationToken ct)
    {
        var db = _mux.GetDatabase();
        // We use INCR + EXPIRE only on first hit in window (simple sliding window approximation)
        var count = await db.StringIncrementAsync(bucketKey);
        if (count == 1) await db.KeyExpireAsync(bucketKey, window);
        return count > maxHits;
    }
}
