using Gateway.Auth;
using Gateway.Infrastructure;
using Gateway.Policies;
using Gateway.Transforms;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using StackExchange.Redis;
using System.Net;
using System.Security.Claims;
using Yarp.ReverseProxy.Forwarder;


var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// Redis: multiplexer + distributed cache
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(cfg["Redis:Configuration"] ?? "localhost:6379"));
builder.Services.AddStackExchangeRedisCache(opt =>
{
    opt.Configuration = cfg["Redis:Configuration"] ?? "localhost:6379";
});
builder.Services.AddSingleton<IRedisRateLimiter, RedisRateLimiter>();
builder.Services.AddSingleton<IForwarderHttpClientFactory, MtlsForwarderHttpClientFactory>();

// HTTP clients
builder.Services.AddHttpClient("jwks");
builder.Services.AddHttpClient("introspection");

builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("Gateway", serviceVersion: "1.0.0"))
    .WithMetrics(m => m
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddRuntimeInstrumentation())
    .WithTracing(t => t
        .AddAspNetCoreInstrumentation(o => { o.RecordException = true; })
        .AddHttpClientInstrumentation());
// .UseConsoleExporter();  // uncomment if you want console output


// Auth services
builder.Services.AddSingleton<IJwksProvider, JwksProvider>();
builder.Services.AddSingleton<IIntrospectionClient, IntrospectionClient>();
builder.Services.AddSingleton<ITokenAuthenticator, TokenAuthenticator>();

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

// YARP from config
builder.Services.AddReverseProxy().LoadFromConfig(cfg.GetSection("ReverseProxy"));

var app = builder.Build();
var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Gateway.RequestScope");

app.UseHttpsRedirection();

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

// If you front Nuxt from a different origin:
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("Nuxt", p => p
        .WithOrigins("https://nuxt.example.com")
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});
app.UseCors("Nuxt");


// Auth middleware: validate Authorization Bearer before proxying
app.Use(async (ctx, next) =>
{
    // Allow /auth/* to flow without Gateway auth (AuthServer handles its own)
    var path = ctx.Request.Path.Value ?? "";
    var isAuthPath = path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase);

    if (!isAuthPath)
    {
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
        var (ok, principal, source, err) = await authenticator.AuthenticateAsync(token!, ctx.RequestAborted);
        if (!ok || principal is null)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            await ctx.Response.WriteAsJsonAsync(new { error = "invalid_token", reason = err });
            return;
        }

        if (string.IsNullOrEmpty(token))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsJsonAsync(new { title = "unauthorized", detail = "missing_bearer", requestId = ctx.TraceIdentifier });
            return;
        }

        // Set user and mark source
        ctx.User = principal;
        ctx.Request.Headers["X-Auth-Source"] = source;
        ForwardingTransforms.AddForwardedIdentityHeaders(ctx);
    }

    await next();
});

app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    var limiter = ctx.RequestServices.GetRequiredService<IRedisRateLimiter>();
    var cfgRL = ctx.RequestServices.GetRequiredService<IConfiguration>().GetSection("RateLimiting");

    // 1) Rate-limit /auth/* (global)
    if (path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase))
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

    // 2) Rate-limit /api/onboarding/identify (abuse-sensitive)
    if (path.Equals("/api/onboarding/identify", StringComparison.OrdinalIgnoreCase))
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


// Authorization after we have a principal (YARP respects endpoint metadata)
app.UseAuthorization();

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


// Map YARP (adds endpoint metadata from config; we attach route-level auth via policies)
app.MapReverseProxy(proxyPipeline =>
{
    // Per-request transform hook (add sanitized headers, strip hop-by-hop)
    proxyPipeline.Use((ctx, nxt) =>
    {
        // ensure a request id
        if (!ctx.Request.Headers.ContainsKey("X-Request-Id"))
            ctx.Request.Headers["X-Request-Id"] = ctx.TraceIdentifier;

        // remove hop-by-hop headers
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
        return Results.Ok(new { status = "ready" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "redis_unavailable", detail: ex.Message, statusCode: 503);
    }
});

app.Run();
