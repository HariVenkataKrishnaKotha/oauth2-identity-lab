using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using ResourceApi.Security; // for BearerErrors helpers
using System.Net;
using Microsoft.IdentityModel.Logging; // add


var builder = WebApplication.CreateBuilder(args);

// ---- Must match AuthServer token settings ----
var issuer = "http://localhost:5018";
var audience = "resource-api";
var realm = "resource-api";

// ---- AuthN: let JwtBearer use OIDC discovery & JWKS automatically ----
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.MetadataAddress = $"{issuer}/oauth/.well-known/openid-configuration";
        o.Authority = issuer;                 // <— uses /.well-known/openid-configuration
        o.RequireHttpsMetadata = false;       // dev only (http)
        o.Audience = audience;                // validates "aud"

        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
            // No IssuerSigningKeyResolver needed — keys come from discovery/JWKS
        };

        // RFC 6750 responses
        o.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                // This is the raw token string ASP.NET extracted after stripping "Bearer "
                var raw = ctx.Request.Headers.Authorization.ToString();
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    var val = raw.Trim().Trim('"');
                    const string prefix = "Bearer ";
                    if (val.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Token = val.Substring(prefix.Length).Trim().Trim('"');
                    }
                }
                Console.WriteLine("[ResourceApi] Token received: " + (ctx.Token ?? "<null>"));
                return Task.CompletedTask;
            },
            OnChallenge = async ctx =>
            {
                ctx.HandleResponse();
                var (error, desc) = ResourceApi.Security.BearerErrors.FromAuthenticateFailure(ctx.AuthenticateFailure);
                Console.WriteLine($"[ResourceApi] 401: {error} - {desc}");
                var www = ResourceApi.Security.BearerErrors.BuildWwwAuthenticate("resource-api", error, desc);
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                ctx.Response.Headers["WWW-Authenticate"] = www;
                ResourceApi.Security.BearerErrors.ApplyNoStore(ctx.Response);
                await ctx.Response.WriteAsJsonAsync(new { error, error_description = desc });
            },
            OnForbidden = async ctx =>
            {
                var endpoint = ctx.HttpContext.GetEndpoint();
                var scopes = endpoint?.Metadata.GetMetadata<RequiredScopesMetadata>()?.Scopes ?? Array.Empty<string>();
                var error = "insufficient_scope";
                var desc = scopes.Length > 0 ? $"Required scope: {string.Join(' ', scopes)}." : "Insufficient scope.";

                var www = BearerErrors.BuildWwwAuthenticate(realm, error, desc, scopes);
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                ctx.Response.Headers["WWW-Authenticate"] = www;
                BearerErrors.ApplyNoStore(ctx.Response);

                await ctx.Response.WriteAsJsonAsync(new { error, error_description = desc, scope = scopes.Length > 0 ? string.Join(' ', scopes) : null });
            }
        };
    });

// ---- Authorization: scope policy ----
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("scope:weather.read", p => p.AddRequirements(new ScopeRequirement("weather.read")));
});
builder.Services.AddSingleton<IAuthorizationHandler, ScopeRequirementHandler>();

// ---- CORS for your SPA origin ----
const string SpaCors = "SpaCors";
builder.Services.AddCors(opts =>
{
    opts.AddPolicy(SpaCors, p => p
        .WithOrigins("http://localhost:4200", "http://127.0.0.1:4200")  // change if your SPA runs elsewhere
        .AllowAnyHeader()
        .AllowAnyMethod());
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    IdentityModelEventSource.ShowPII = true; // <-- only for dev
}

app.UseCors(SpaCors);
app.Use(async (ctx, next) =>
{
    var rawAuth = ctx.Request.Headers.Authorization.ToString();
    Console.WriteLine($"[ResourceApi] Incoming Authorization header: {(string.IsNullOrEmpty(rawAuth) ? "<none>" : rawAuth)}");
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", role = "ResourceServer" }));

app.MapGet("/api/weather", () => Results.Ok(new { tempC = 24, summary = "Sunny" }))
   .WithMetadata(new RequiredScopesMetadata("weather.read"))
   .RequireAuthorization("scope:weather.read");

app.Run();
