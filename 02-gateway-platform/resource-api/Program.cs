using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ResourceApi.Data;
using ResourceApi.Services;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

builder.Services.AddDbContext<OnboardingDbContext>(opt =>
    opt.UseSqlServer(cfg.GetConnectionString("OnboardingDb")));

builder.Services.AddScoped<AuthServerSyncService>();

// ✅ ADD: JWT Bearer Authentication (for protected endpoints)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:5018/";
        options.Audience = "resource-api";
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:5018/",
            ValidateAudience = true,
            ValidAudience = "resource-api",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(60)
        };

        // Dev only: Skip certificate validation
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ManagerOnly", policy => policy.RequireRole("Manager"));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();

var app = builder.Build();

// init db + seed
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<OnboardingDbContext>();
    await Seed.EnsureAsync(db);
}

app.UseHttpsRedirection();

// ✅ ADD: Authentication & Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.UseSwagger();
app.UseSwaggerUI();

app.MapControllers();

// Health endpoint
app.MapGet("/health/ready", () => Results.Ok(new { status = "ready" }));

app.Run();