using Microsoft.AspNetCore.Http;

namespace AuthServer.Logic;

public static class OAuthResults
{
    // JSON with RFC-required no-store headers for token endpoint responses.
    public static IResult Json(object body, int statusCode = StatusCodes.Status200OK)
        => new HeaderedJsonResult(body, statusCode, new HeaderDictionary
        {
            ["Cache-Control"] = "no-store",
            ["Pragma"] = "no-cache",
            ["Content-Type"] = "application/json; charset=utf-8"
        });

    // Authorization endpoint error redirect (append error & state to query)
    public static IResult RedirectError(string redirectUri, string error, string? description = null, string? state = null, string? errorUri = null)
    {
        var ub = new UriBuilder(redirectUri);
        var q = System.Web.HttpUtility.ParseQueryString(ub.Query);
        q["error"] = error;
        if (!string.IsNullOrEmpty(description)) q["error_description"] = description;
        if (!string.IsNullOrEmpty(errorUri)) q["error_uri"] = errorUri;
        if (!string.IsNullOrEmpty(state)) q["state"] = state;
        ub.Query = q.ToString();
        return Results.Redirect(ub.ToString());
    }

    // Token endpoint errors (JSON) + proper status code + WWW-Authenticate
    public static IResult TokenError(string error, string? description = null, int statusCode = StatusCodes.Status400BadRequest)
    {
        var headers = new HeaderDictionary
        {
            ["Cache-Control"] = "no-store",
            ["Pragma"] = "no-cache",
            ["Content-Type"] = "application/json; charset=utf-8",
            ["WWW-Authenticate"] = BuildWwwAuthenticate(error, description)
        };
        return new HeaderedJsonResult(new { error, error_description = description }, statusCode, headers);
    }

    // Special case per §5.2: invalid_client → 401 + WWW-Authenticate
    public static IResult InvalidClient(string? description = null)
        => TokenError("invalid_client", description ?? "Client authentication failed.", StatusCodes.Status401Unauthorized);

    private static string BuildWwwAuthenticate(string error, string? description)
    {
        var s = $"Bearer error=\"{error}\"";
        if (!string.IsNullOrEmpty(description))
        {
            var esc = description.Replace("\\", "\\\\").Replace("\"", "\\\"");
            s += $", error_description=\"{esc}\"";
        }
        return s;
    }

    private sealed class HeaderedJsonResult : IResult
    {
        private readonly object _body;
        private readonly int _status;
        private readonly IHeaderDictionary _headers;

        public HeaderedJsonResult(object body, int status, IHeaderDictionary headers)
        {
            _body = body; _status = status; _headers = headers;
        }

        public async Task ExecuteAsync(HttpContext http)
        {
            http.Response.StatusCode = _status;
            foreach (var h in _headers) http.Response.Headers[h.Key] = h.Value;
            await http.Response.WriteAsJsonAsync(_body);
        }
    }
}
