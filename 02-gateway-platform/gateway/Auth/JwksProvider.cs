using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Gateway.Auth;

public interface IJwksProvider
{
    Task<JsonWebKeySet> GetAsync(CancellationToken ct);
    Task InvalidateAsync(CancellationToken ct);
}

public sealed class JwksProvider : IJwksProvider
{
    private readonly IHttpClientFactory _http;
    private readonly IDistributedCache _cache;
    private readonly ILogger<JwksProvider> _log;
    private readonly string _jwksUri;
    private readonly string _cacheKey;
    private readonly IConfiguration _configuration;

    private JsonWebKeySet? _memory; // short-circuit for the process
    private static readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public JwksProvider(IHttpClientFactory http, IDistributedCache cache, IConfiguration cfg, ILogger<JwksProvider> log)
    {
        _http = http;
        _cache = cache;
        _log = log;
        _configuration = cfg;
        _jwksUri = cfg["Gateway:JwksUri"] ?? throw new InvalidOperationException("Gateway:JwksUri missing");
        _cacheKey = cfg["Redis:JwksCacheKey"] ?? "jwks:cache";
    }

    public async Task<JsonWebKeySet> GetAsync(CancellationToken ct)
    {
        if (_memory is not null) return _memory;

        // Try Redis
        var cached = await _cache.GetStringAsync(_cacheKey, ct);
        if (!string.IsNullOrWhiteSpace(cached))
        {
            try
            {
                _memory = new JsonWebKeySet(cached);
                return _memory;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to parse JWKS from cache; refetching");
            }
        }

        // Fetch fresh
        var http = _http.CreateClient("jwks");
        using var resp = await http.GetAsync(_jwksUri, ct);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync(ct);

        _memory = new JsonWebKeySet(json);

        var ttlSeconds = int.TryParse(
    _configuration["Redis:JwksCacheSeconds"], out var s) ? Math.Clamp(s, 15, 300) : 60;

        await _cache.SetStringAsync(_cacheKey, json, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(ttlSeconds)
        }, ct);

        return _memory;
    }

    public async Task InvalidateAsync(CancellationToken ct)
    {
        _memory = null;
        await _cache.RemoveAsync(_cacheKey, ct);
    }
}
