using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Gateway.Auth;

/// <summary>
/// Custom authentication handler that validates JWT tokens from Bearer header
/// </summary>
public class GatewayAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ITokenAuthenticator _tokenAuthenticator;
    private readonly ILogger<GatewayAuthenticationHandler> _logger;

    public GatewayAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder,
        ITokenAuthenticator tokenAuthenticator)
        : base(options, loggerFactory, encoder)
    {
        _tokenAuthenticator = tokenAuthenticator;
        _logger = loggerFactory.CreateLogger<GatewayAuthenticationHandler>();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Get Authorization header
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            _logger.LogDebug("No Authorization header present");
            return AuthenticateResult.NoResult();
        }

        var authHeaderValue = authHeader.ToString();

        // Check if it's a Bearer token
        if (!authHeaderValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("Authorization header is not Bearer");
            return AuthenticateResult.NoResult();
        }

        // Extract token
        var token = authHeaderValue.Substring("Bearer ".Length).Trim();

        if (string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("Bearer token is empty");
            return AuthenticateResult.Fail("Empty bearer token");
        }

        _logger.LogDebug("Authenticating token (first 20 chars): {Token}...",
            token.Substring(0, Math.Min(20, token.Length)));

        // Validate token
        var (ok, principal, source, error) = await _tokenAuthenticator.AuthenticateAsync(token, Context.RequestAborted);

        if (!ok || principal == null)
        {
            _logger.LogWarning("Token authentication failed: {Error} (source: {Source})", error, source);
            return AuthenticateResult.Fail(error ?? "Invalid token");
        }

        _logger.LogInformation("Token authenticated successfully via {Source}", source);

        // Create authentication ticket
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        Response.Headers.Append("WWW-Authenticate", "Bearer");
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        return Task.CompletedTask;
    }
}