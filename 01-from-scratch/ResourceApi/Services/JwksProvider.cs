using System.Net.Http.Json;
using Microsoft.IdentityModel.Tokens;

namespace ResourceApi.Services;

public sealed class JwksProvider
{
    private readonly HttpClient _http;
    private readonly string _jwksUri;
    private volatile IList<SecurityKey> _keys = new List<SecurityKey>();
    private readonly object _lock = new();

    public JwksProvider(HttpClient http, string jwksUri)
    {
        _http = http;
        _jwksUri = jwksUri;
    }

    public async Task RefreshAsync(CancellationToken ct = default)
    {
        var set = await _http.GetFromJsonAsync<JsonWebKeySet>(_jwksUri, ct);
        if (set is null || set.Keys.Count == 0) throw new InvalidOperationException("Empty JWKS");

        var keys = set.Keys.Cast<SecurityKey>().ToList();
        lock (_lock) _keys = keys;
    }

    public IEnumerable<SecurityKey> GetAllKeys()
    {
        var snapshot = _keys; // volatile read
        return snapshot;
    }

    public IEnumerable<SecurityKey> Resolve(string? kid)
    {
        var keys = GetAllKeys();
        if (string.IsNullOrEmpty(kid)) return keys;

        return keys.Where(k =>
        {
            if (k is JsonWebKey jwk) return string.Equals(jwk.Kid, kid, StringComparison.Ordinal);
            if (k is RsaSecurityKey rsa) return string.Equals(rsa.KeyId, kid, StringComparison.Ordinal);
            return false;
        });
    }
}
