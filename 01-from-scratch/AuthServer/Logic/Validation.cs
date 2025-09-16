using System.Text.RegularExpressions;

namespace AuthServer.Logic;

public static class Validation
{
    // Basic redirect rules: exact match, https except localhost/loopback in dev, no fragments.
    public static bool IsValidRedirectUri(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u)) return false;
        if (!string.IsNullOrEmpty(u.Fragment)) return false; // no fragments per best practices

        if (u.Scheme == Uri.UriSchemeHttps) return true;

        // Allow http only for loopback dev origins
        if (u.Scheme == Uri.UriSchemeHttp &&
            (u.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
             u.Host.Equals("127.0.0.1") || u.Host.Equals("::1")))
            return true;

        return false;
    }

    // Space-separated scopes: letters, numbers, dot, dash, colon
    public static bool IsValidScopeList(string scopeCsv)
    {
        if (string.IsNullOrWhiteSpace(scopeCsv)) return true;
        var parts = scopeCsv.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var rx = new Regex(@"^[a-zA-Z0-9\.\-\:]+$");
        return parts.All(p => rx.IsMatch(p));
    }
}
