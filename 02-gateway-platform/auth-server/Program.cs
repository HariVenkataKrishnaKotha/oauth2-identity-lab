using AuthServer.Data;
using AuthServer.Identity;
using AuthServer.Infrastructure;
using AuthServer.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using StackExchange.Redis;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

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

// Redis (future: OTP/magic link state, etc.)
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(cfg.GetSection("Redis")["Configuration"]!));

builder.Services.AddHttpClient<IResourceApiClient, ResourceApiClient>();
builder.Services.AddSingleton<IMagicLinkService, MagicLinkService>();

// OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(opt => opt.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>())
    .AddServer(opt =>
    {
        opt.SetIssuer(new Uri(cfg["OpenIddict:Issuer"]!));

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
           .EnableUserInfoEndpointPassthrough(); // keep if you’ll handle /userinfo
                                                 // (No EnableLogoutEndpointPassthrough in 7.x; use EndSession via built-in pipeline)
                                                 // Keep HTTPS enforced in prod; this sample is dev-friendly.
    })
    .AddValidation(opt => { opt.UseLocalServer(); opt.UseAspNetCore(); });


// Auth cookie (used for /connect/authorize user login)
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
})
    .AddCookie(IdentityConstants.ApplicationScheme, options =>
    {
        options.LoginPath = "/Account/Login";
        options.SlidingExpiration = true;
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

// OpenIddict endpoints are mapped by UseAspNetCore() passthrough + MVC.
// We’ll keep a health endpoint:
app.MapGet("/health/ready", () => Results.Ok(new { status = "ok" }));

app.Run();
