using AuthServer.Data;
using AuthServer.Identity;
using AuthServer.Infrastructure;
using AuthServer.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// DbContexts
builder.Services.AddDbContext<ApplicationDbContext>(opt =>
    opt.UseSqlServer(cfg.GetConnectionString("Default")));

builder.Services.AddDbContext<DataProtectionKeyContext>(opt =>
    opt.UseSqlServer(cfg.GetConnectionString("DataProtection")));

// Data Protection keys (for multi-instance)
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<DataProtectionKeyContext>();

// Identity
builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>(opt =>
    {
        opt.User.RequireUniqueEmail = true;
        opt.Password.RequiredLength = 8;
        opt.Lockout.MaxFailedAccessAttempts = 5;
        opt.SignIn.RequireConfirmedEmail = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();



builder.Services.AddControllers();

//// Redis (future: OTP/magic link state, etc.)
//// Redis (Cloud instance with SSL and password)
//builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
//{
//    var redisConfig = cfg["Redis:Configuration"];
//    if (string.IsNullOrEmpty(redisConfig))
//        throw new InvalidOperationException("Redis configuration is missing");
//
//    var options = ConfigurationOptions.Parse(redisConfig);
//    options.ConnectTimeout = 10000; // 10 seconds
//    options.SyncTimeout = 10000;
//    options.AbortOnConnectFail = false; // Important for cloud Redis
//
//    return ConnectionMultiplexer.Connect(options);
//});

// Redis (local instance - simple configuration)
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(cfg["Redis:Configuration"]!));

// Configure HttpClient for ResourceAPI calls through Gateway
builder.Services.AddHttpClient<IResourceApiClient, ResourceApiClient>(client =>
{
    client.BaseAddress = new Uri("https://localhost:5000"); // Gateway URL
    client.Timeout = TimeSpan.FromSeconds(30);
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true // Dev only!
});

// Add a second HttpClient for direct ResourceAPI calls (manager sync)
builder.Services.AddHttpClient("ResourceApiDirect", client =>
{
    client.BaseAddress = new Uri("https://localhost:5173"); // Direct to ResourceAPI
    client.Timeout = TimeSpan.FromSeconds(30);
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true // Dev only!
});

builder.Services.AddSingleton<IMagicLinkService, MagicLinkService>();

// OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(opt => opt.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>())
    .AddServer(opt =>
    {
        opt.SetIssuer(new Uri(cfg["OpenIddict:Issuer"]!));
        opt.DisableAccessTokenEncryption(); // Optional, depending on your needs

        opt.UseAspNetCore().DisableTransportSecurityRequirement(); //Remove in production!

        // Endpoints (7.x)
        opt.SetAuthorizationEndpointUris("/connect/authorize")
           .SetTokenEndpointUris("/connect/token")
           .SetIntrospectionEndpointUris("/connect/introspect")
           .SetRevocationEndpointUris("/connect/revocation")
           .SetEndSessionEndpointUris("/connect/endsession")
           .SetUserInfoEndpointUris("/connect/userinfo");
        // Omit .SetVerificationEndpointUris(...) unless you implement device flow.
        // Omit .SetCryptographyEndpointUris(...) unless you must change the default.

        // Flows
        opt.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
        opt.AllowRefreshTokenFlow();

        // Keys (dev only; persist/rotate in prod)
        opt.AddEphemeralEncryptionKey()
           .AddEphemeralSigningKey();

        // Scopes you support (registration)
        opt.RegisterScopes(
            OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
            OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
            OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
            OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
            "onboarding.read", "onboarding.write");

        // Lifetimes
        opt.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));
        opt.SetRefreshTokenLifetime(TimeSpan.FromDays(30));

        // ASP.NET Core host integration
        opt.UseAspNetCore()
           .EnableAuthorizationEndpointPassthrough()
           .EnableTokenEndpointPassthrough()
           //.EnableIntrospectionEndpointPassthrough() Not available in 7.x; handled by middleware
           .EnableUserInfoEndpointPassthrough(); // keep if you’ll handle /userinfo
                                                 // (No EnableLogoutEndpointPassthrough in 7.x; use EndSession via built-in pipeline)
                                                 // Keep HTTPS enforced in prod; this sample is dev-friendly.
    })
    .AddValidation(opt => { opt.UseLocalServer(); opt.UseAspNetCore(); });


// Configure Identity cookie options (Identity.Application scheme already registered by AddIdentity)
// Configure Identity cookie options
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;

    // Critical for Gateway proxying
    options.Cookie.Name = ".AspNetCore.Identity.Application";
    options.Cookie.Path = "/";  // Root path since we removed /auth prefix
    options.Cookie.Domain = null; // Allow cookie to work across localhost ports
});

builder.Services.AddAuthorization();

// Minimal UI
builder.Services.AddRazorPages();

var app = builder.Build();

// Migrate/seed
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();

    var dp = scope.ServiceProvider.GetRequiredService<DataProtectionKeyContext>();
    await dp.Database.MigrateAsync();

    await Seed.InitializeAsync(app.Services, cfg["OpenIddict:Issuer"]!);
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Razor Pages (login form)
app.MapRazorPages();

app.MapControllers();

// OpenIddict endpoints are mapped by UseAspNetCore() passthrough + MVC.
// We’ll keep a health endpoint:
app.MapGet("/health/ready", () => Results.Ok(new { status = "ok" }));

// Test endpoint for Redis connectivity
// Test endpoint for Redis connectivity
app.MapGet("/health/redis", async (IConnectionMultiplexer mux) =>
{
    try
    {
        var db = mux.GetDatabase();
        var testKey = "health:test";

        // Set a test value
        await db.StringSetAsync(testKey, $"OK-{DateTime.UtcNow:HH:mm:ss}");

        // Get it back
        var value = await db.StringGetAsync(testKey);

        // Clean up
        await db.KeyDeleteAsync(testKey);

        return Results.Ok(new
        {
            status = "connected",
            server = "localhost:6379",
            value = value.ToString()
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Redis connection failed: {ex.Message}", statusCode: 500);
    }
});

app.Run();
