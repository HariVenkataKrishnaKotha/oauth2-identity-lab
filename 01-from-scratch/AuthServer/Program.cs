using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using ResourceApi.Security;
using ResourceApi.Services;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

// ---- MUST mirror AuthServer ----
var issuer = "http://localhost:5018";
var audience = "resource-api";
var jwksUri = $"{issuer}/oauth/.well-known/jwks.json";
var realm = "resource-api"; // RFC 6750 realm value

// ---- JWKS provider + refresher ----
builder.Services.AddHttpClient<JwksProvider>();
builder.Services.AddSingleton(sp =>
{
    var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient();
    return new JwksProvider(http, jwksUri);
});
builder.Services.AddHostedService<JwksRefreshService>();

// ---- AuthN with RFC6750-compliant events ----
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (token, st, kid, p) =>
            {
                // Resolve keys from cache (supports rotation by kid)
                var provider = builder.Services.BuildServiceProvider().GetRequiredService<JwksProvider>();
                var keys = provider.Resolve(kid);
                return keys.Any() ? keys : provider.GetAllKeys();
            },
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        // RFC 6750 error mapping
        o.Events = new JwtBearerEvents
        {
            OnChallenge = async ctx =>
            {
                // Suppress default HTML response
                ctx.HandleResponse();

                // No token or invalid token
                var (error, desc) = BearerErrors.FromAuthenticateFailure(ctx.AuthenticateFailure);

                // Build RFC 6750 WWW-Authenticate header
                var www = BearerErrors.BuildWwwAuthenticate(realm, error, desc);

                ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                ctx.Response.Headers["WWW-Authenticate"] = www;
                BearerErrors.ApplyNoStore(ctx.Response);

                await ctx.Response.WriteAsJsonAsync(new { error, error_description = desc });
            },
            OnForbidden = async ctx =>
            {
                // Authorization failed (typically insufficient scope)
                // Try to read required scopes metadata from endpoint
                var endpoint = ctx.HttpContext.GetEndpoint();
                var requiredScopes = endpoint?.Metadata.GetMetadata<RequiredScopesMetadata>()?.Scopes ?? Array.Empty<string>();

                var error = "insufficient_scope";
                var desc = requiredScopes.Length > 0
                    ? $"Required scope: {string.Join(' ', requiredScopes)}."
                    : "The request requires higher privileges than provided by the access token.";

                var www = BearerErrors.BuildWwwAuthenticate(realm, error, desc, requiredScopes);

                ctx.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                ctx.Response.Headers["WWW-Authenticate"] = www;
                BearerErrors.ApplyNoStore(ctx.Response);

                await ctx.Response.WriteAsJsonAsync(new { error, error_description = desc, scope = requiredScopes.Length > 0 ? string.Join(' ', requiredScopes) : null });
            }
        };
    });

// ---- AuthZ using a dedicated Scope requirement ----
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("scope:weather.read", p => p.AddRequirements(new ScopeRequirement("weather.read")));
});
builder.Services.AddSingleton<IAuthorizationHandler, ScopeRequirementHandler>();

// ---- CORS for SPA ----
const string SpaCors = "SpaCors";
builder.Services.AddCors(opts =>
{
    opts.AddPolicy(SpaCors, p => p
        .WithOrigins("http://localhost:4200")
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
}

app.UseCors(SpaCors);
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", role = "ResourceServer" }));

// Attach required scope metadata so OnForbidden can advertise it per RFC 6750
app.MapGet("/api/weather", () => Results.Ok(new { tempC = 24, summary = "Sunny" }))
   .WithMetadata(new RequiredScopesMetadata("weather.read"))
   .RequireAuthorization("scope:weather.read");

app.Run();
