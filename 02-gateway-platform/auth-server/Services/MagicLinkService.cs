using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using StackExchange.Redis;

namespace AuthServer.Services;
public sealed class MagicLinkService : IMagicLinkService
{
    private readonly IConnectionMultiplexer _mux;
    private static readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public MagicLinkService(IConnectionMultiplexer mux) => _mux = mux;

    public async Task<string> CreateVerifySessionAsync(Guid tempUserId, TimeSpan ttl, CancellationToken ct)
    {
        var db = _mux.GetDatabase();
        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        var payload = new VerifySessionPayload
        {
            TempUserId = tempUserId,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await db.StringSetAsync(RedisKeys.VerifySession(id), JsonSerializer.Serialize(payload, _json), ttl);
        return id;
    }

    public async Task<(bool ok, Guid tempUserId)> RedeemAsync(string verifySessionId, CancellationToken ct)
    {
        var db = _mux.GetDatabase();
        var key = RedisKeys.VerifySession(verifySessionId);
        var json = await db.StringGetAsync(key);
        if (json.IsNullOrEmpty) return (false, Guid.Empty);

        // one-time use
        await db.KeyDeleteAsync(key);

        // Explicit string conversion: RedisValue also converts to ReadOnlyMemory<byte>,
        // which C# 14 span conversions make ambiguous with the string overload (CS0121).
        var doc = JsonSerializer.Deserialize<VerifySessionPayload>((string)json!, _json);
        return doc is null ? (false, Guid.Empty) : (true, doc.TempUserId);
    }

    private sealed class VerifySessionPayload
    {
        public Guid TempUserId { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }
}
