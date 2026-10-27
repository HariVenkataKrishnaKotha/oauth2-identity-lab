using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Logic;

public static class OAuthHelpers
{
    public static string GenerateCode(int bytes = 32)
        => Base64UrlEncode(RandomNumberGenerator.GetBytes(bytes));

    // Split a space-delimited scope string into tokens
    public static string[] SplitScopes(string? csv)
        => string.IsNullOrWhiteSpace(csv)
            ? Array.Empty<string>()
            : csv.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static string Base64UrlEncode(byte[] input)
        => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // requested scopes must all be in allowed[] (array version)
    public static bool IsSubsetOfScopes(string? requestedCsv, string[] allowed)
    {
        var req = SplitScopes(requestedCsv);
        if (req.Length == 0) return true;
        return req.All(s => allowed.Contains(s, StringComparer.Ordinal));
    }

    // requested scopes must all be in allowedCsv (string version)
    public static bool IsSubsetOfScopes(string? requestedCsv, string? allowedCsv)
        => IsSubsetOfScopes(requestedCsv, SplitScopes(allowedCsv));

    // convenience: convert array back to csv
    public static string JoinScopes(IEnumerable<string> scopes)
        => string.Join(' ', scopes);
}
