using AuthServer.Endpoints;
using AuthServer.Infrastructure;
using AuthServer.Logic;
using AuthServer.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// --- Eager-create keys ---
{
    var keysDir = Path.Combine(builder.Environment.ContentRootPath, "keys");
    var store = new RsaKeyStore(keysDir);
    store.GetOrCreate();
    Console.WriteLine($"[AuthServer] Keys directory: {keysDir}");
}

// --- CORS ---
const string SpaCors = "SpaCors";
builder.Services.AddCors(opts =>
{
    opts.AddPolicy(SpaCors, p => p
        .WithOrigins("http://localhost:4200", "http://127.0.0.1:4200")
        .AllowAnyHeader()
        .AllowAnyMethod()
        // You can keep this on or remove; it’s fine either way for simple fetches:
        .AllowCredentials()
    );
});

// --- EF Core ---
builder.Services.AddDbContext<AuthDbContext>(opt =>
    opt.UseSqlServer(builder.Configuration.GetConnectionString("AuthDb")));

// --- Swagger ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// --- Keys + Token options ---
builder.Services.AddSingleton<SigningCredentials>(sp =>
{
    var env = sp.GetRequiredService<IHostEnvironment>();
    var store = new RsaKeyStore(Path.Combine(env.ContentRootPath, "keys"));
    var (priv, _) = store.GetOrCreate();
    return new SigningCredentials(new RsaSecurityKey(priv) { KeyId = "dev-rsa-1" }, SecurityAlgorithms.RsaSha256);
});
builder.Services.AddSingleton<SecurityKey>(sp =>
{
    var env = sp.GetRequiredService<IHostEnvironment>();
    var store = new RsaKeyStore(Path.Combine(env.ContentRootPath, "keys"));
    var (_, pub) = store.GetOrCreate();
    return new RsaSecurityKey(pub) { KeyId = "dev-rsa-1" };
});

// IMPORTANT: issuer must match the port you’re actually using (5018 per your error)
builder.Services.AddSingleton(new OAuthTokenOptions
{
    Issuer = "http://localhost:5018",
    Audience = "resource-api",
    AccessTokenLifetime = TimeSpan.FromMinutes(10),
    RefreshTokenLifetime = TimeSpan.FromDays(30)
});

builder.Services.AddScoped<TokenService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// CORS MUST run before endpoints
app.UseCors(SpaCors);

// --- DB migrate + seed ---
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.MigrateAsync();
    await DbSeeder.SeedAsync(db);
}

// --- Endpoints ---
app.MapGet("/health", () => Results.Ok(new { status = "ok", role = "AuthorizationServer" }));
app.MapAuthorize();
app.MapToken();
app.MapAdminClients();
app.MapDiscovery(); // Discovery endpoints (see below)

app.Run();
