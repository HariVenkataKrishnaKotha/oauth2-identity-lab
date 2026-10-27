using Gateway.Auth;
using Gateway.Infrastructure;
using Gateway.Policies;
using Gateway.Transforms;
using Microsoft.AspNetCore.Authorization;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using StackExchange.Redis;
using System.Net;
using Yarp.ReverseProxy.Forwarder;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// SERVICE REGISTRATION

// Redis: multiplexer + distributed cache (Local instance)
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(cfg["Redis:Configuration"]!));

builder.Services.AddStackExchangeRedisCache(opt =>
{
    opt.Configuration = cfg["Redis:Configuration"];
});

builder.Services.AddSingleton<IRedisRateLimiter, RedisRateLimiter>();
//builder.Services.AddSingleton<IForwarderHttpClientFactory, MtlsForwarderHttpClientFactory>();

// HTTP clients
//builder.Services.AddHttpClient("jwks");
//builder.Services.AddHttpClient("introspection");

//Auth Services
//builder.Services.AddScoped<IJwksProvider, JwksProvider>();
//builder.Services.AddScoped<IIntrospectionClient, IntrospectionClient>();
builder.Services.AddScoped<ITokenAuthenticator, TokenAuthenticator>();

builder.Services.AddHttpClient<IJwksProvider, JwksProvider>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    });

builder.Services.AddHttpClient<IIntrospectionClient, IntrospectionClient>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    });

// OpenTelemetry
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("Gateway", serviceVersion: "1.0.0"))
    .WithMetrics(m => m
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddRuntimeInstrumentation())
    .WithTracing(t => t
        .AddAspNetCoreInstrumentation(o => { o.RecordException = true; })
        .AddHttpClientInstrumentation());

// Authorization policies
builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();
builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("ApiDefault", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new ScopeRequirement("onboarding.read"));
    });
    opt.AddPolicy("ManagerWrite", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new ScopeRequirement("onboarding.write"));
        policy.RequireRole("Manager");
        policy.RequireClaim("perm", "badge_approve");
    });
});

// CORS
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("Nuxt", p => p
        .WithOrigins("https://localhost:3000", "http://localhost:3000")
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});

// Health checks
builder.Services.AddHealthChecks();

// YARP Reverse Proxy

builder.Services.AddReverseProxy()
    .LoadFromConfig(cfg.GetSection("ReverseProxy"))
    .ConfigureHttpClient((context, handler) =>
    {
        // Don't follow redirects - let browser handle them
        handler.AllowAutoRedirect = false;
    });

// BUILD APPLICATION

var app = builder.Build();
var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Gateway");

// MIDDLEWARE PIPELINE

app.UseHttpsRedirection();

// Security headers
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

// CORS
app.UseCors("Nuxt");

// Simple request logging
app.Use(async (ctx, next) =>
{
    logger.LogInformation("Gateway: {Method} {Path}{QueryString}",
        ctx.Request.Method,
        ctx.Request.Path,
        ctx.Request.QueryString);

    await next();

    logger.LogInformation("Gateway: Response {Status} for {Path}",
        ctx.Response.StatusCode,
        ctx.Request.Path);
});

// Test endpoint - bypass all auth
app.MapGet("/test-token", async (HttpContext ctx, IConfiguration config) =>
{
    var token = ctx.Request.Headers.Authorization.ToString().Replace("Bearer ", "");

    var authenticator = ctx.RequestServices.GetRequiredService<ITokenAuthenticator>();
    var result = await authenticator.AuthenticateAsync(token, ctx.RequestAborted);

    return Results.Ok(new
    {
        Success = result.ok,
        Source = result.source,
        Error = result.error,
        HasPrincipal = result.principal != null,
        Claims = result.principal?.Claims.Select(c => new { c.Type, c.Value }).ToList()
    });
});

// Paths the gateway lets through WITHOUT a Bearer token. Everything else,
// including everything the catch-all "api-routes" route sends to
// resource-api, must carry a valid access token.
//
// Exact matches only (case-insensitive). Keep this list in sync with the
// "auth" routes in appsettings.json: any path not listed here falls through
// to the catch-all and needs a token.
// - /connect/authorize, /connect/token, /connect/introspect,
//   /connect/userinfo: OpenIddict endpoints that authenticate the caller
//   themselves (cookie, client credentials or PKCE, or their own token check).
// - /Account/Login, /Account/Enroll: auth-server Razor pages (cookie-based).
//   Both post back to the same path; neither uses sub-paths or static
//   assets under /Account/.
// - /onboarding/identify, /onboarding/magic: auth-server passwordless entry
//   points. They run before the onboardee has any token (identify checks
//   last name + DOB, magic redeems the one-time link and sets the cookie).
// - /health/live, /health/ready: the gateway's own probes.
string[] publicExactPaths =
[
    "/connect/authorize",
    "/connect/token",
    "/connect/introspect",
    "/connect/userinfo",
    "/Account/Login",
    "/Account/Enroll",
    "/onboarding/identify",
    "/onboarding/magic",
    "/health/live",
    "/health/ready"
];

// Segment-bounded prefix: everything under /.well-known/ is public
// discovery and JWKS data, routed to auth-server by the "well-known" route.
string[] publicPathPrefixes =
[
    "/.well-known/"
];

// Auth middleware: validate the Authorization Bearer token for every
// non-public path before it is proxied
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";

    var isPublicPath =
        publicExactPaths.Any(p => string.Equals(path, p, StringComparison.OrdinalIgnoreCase)) ||
        publicPathPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    if (isPublicPath)
    {
        // Skip Bearer token validation - pass through immediately
        await next();
        return;
    }

    // Everything else (including all resource-api routes) requires a Bearer token
    var authz = ctx.Request.Headers.Authorization.ToString();
    var token = authz.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        ? authz.Substring("Bearer ".Length).Trim()
        : null;

    if (string.IsNullOrEmpty(token))
    {
        ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        await ctx.Response.WriteAsJsonAsync(new { error = "missing_bearer" });
        return;
    }

    var authenticator = ctx.RequestServices.GetRequiredService<ITokenAuthenticator>();
    var (ok, principal, source, err) = await authenticator.AuthenticateAsync(token, ctx.RequestAborted);

    if (!ok || principal is null)
    {
        ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        await ctx.Response.WriteAsJsonAsync(new { error = "invalid_token", reason = err });
        return;
    }

    // Set user and mark source
    ctx.User = principal;
    ctx.Request.Headers["X-Auth-Source"] = source;
    ForwardingTransforms.AddForwardedIdentityHeaders(ctx);

    await next();
});

// Rate limiting middleware
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    var limiter = ctx.RequestServices.GetRequiredService<IRedisRateLimiter>();
    var cfgRL = cfg.GetSection("RateLimiting");

    // 1) Rate-limit /connect/* (global)
    if (path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
    {
        var win = TimeSpan.FromSeconds(cfgRL.GetValue("AuthWindowSeconds", 60));
        var max = cfgRL.GetValue("AuthMax", 60);
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var key = $"rl:auth:{ip}";

        if (await limiter.ShouldLimitAsync(key, max, win, ctx.RequestAborted))
        {
            ctx.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            ctx.Response.Headers["Retry-After"] = "60";
            await ctx.Response.WriteAsJsonAsync(new { error = "rate_limited_auth" });
            return;
        }
    }

    // 2) Rate-limit /onboarding/identify (abuse-sensitive)
    if (path.Equals("/onboarding/identify", StringComparison.OrdinalIgnoreCase))
    {
        var win = TimeSpan.FromSeconds(cfgRL.GetValue("IdentifyWindowSeconds", 300));
        var max = cfgRL.GetValue("IdentifyMax", 20);
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var key = $"rl:identify:{ip}";

        if (await limiter.ShouldLimitAsync(key, max, win, ctx.RequestAborted))
        {
            ctx.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            ctx.Response.Headers["Retry-After"] = "300";
            await ctx.Response.WriteAsJsonAsync(new { error = "rate_limited_identify" });
            return;
        }
    }

    await next();
});

// Request logging scope
app.Use(async (ctx, next) =>
{
    using (logger.BeginScope(new Dictionary<string, object?>
    {
        ["request_id"] = ctx.TraceIdentifier,
        ["path"] = ctx.Request.Path.Value,
        ["method"] = ctx.Request.Method,
        ["client_ip"] = ctx.Connection.RemoteIpAddress?.ToString()
    }))
    {
        await next();
    }
});

// Map YARP reverse proxy
app.MapReverseProxy(proxyPipeline =>
{
    // Per-request transform hook (add sanitized headers, strip hop-by-hop)
    proxyPipeline.Use((ctx, nxt) =>
    {
        // Ensure a request id
        if (!ctx.Request.Headers.ContainsKey("X-Request-Id"))
            ctx.Request.Headers["X-Request-Id"] = ctx.TraceIdentifier;

        // Remove hop-by-hop headers
        ctx.Request.Headers.Remove("Connection");
        ctx.Request.Headers.Remove("Keep-Alive");
        ctx.Request.Headers.Remove("Proxy-Authenticate");
        ctx.Request.Headers.Remove("Proxy-Authorization");
        ctx.Request.Headers.Remove("TE");
        ctx.Request.Headers.Remove("Trailers");
        ctx.Request.Headers.Remove("Transfer-Encoding");
        ctx.Request.Headers.Remove("Upgrade");

        return nxt();
    });
});

// Health endpoints
app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));

app.MapGet("/health/ready", async (IConnectionMultiplexer mux) =>
{
    try
    {
        var db = mux.GetDatabase();
        await db.PingAsync();
        return Results.Ok(new { status = "ready", redis = "connected" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "redis_unavailable", detail: ex.Message, statusCode: 503);
    }
});

app.Run();