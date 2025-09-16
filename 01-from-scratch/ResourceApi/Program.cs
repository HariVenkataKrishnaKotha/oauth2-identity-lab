using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ResourceApi.Services;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);

// --- Config must mirror AuthServer TokenOptions ---
var issuer = "http://localhost:5018";
var audience = "resource-api";
var jwksUri = $"{issuer}/oauth/.well-known/jwks.json";

// --- JWKS provider + refresher ---
builder.Services.AddHttpClient<JwksProvider>();
builder.Services.AddSingleton(sp =>
{
    var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(JwksProvider));
    return new JwksProvider(http, jwksUri);
});
builder.Services.AddHostedService<JwksRefreshService>();

// --- AuthN/Z using dynamic key resolver (by `kid`) ---
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
            // Resolve keys from JWKS cache (supports rotation)
            IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                var provider = builder.Services.BuildServiceProvider().GetRequiredService<JwksProvider>();
                var keys = provider.Resolve(kid);
                // If no kid match, return all keys so validator can try them
                return keys.Any() ? keys : provider.GetAllKeys();
            },
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("scope:weather.read", p =>
        p.RequireAssertion(ctx =>
            ctx.User.HasClaim(c => c.Type == "scope" && c.Value.Split(' ').Contains("weather.read"))));
});

// --- CORS for SPA ---
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

app.MapGet("/api/weather", () => Results.Ok(new { tempC = 24, summary = "Sunny" }))
   .RequireAuthorization("scope:weather.read");

app.Run();
