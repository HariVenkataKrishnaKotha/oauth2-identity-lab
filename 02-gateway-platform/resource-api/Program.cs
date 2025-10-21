using Microsoft.EntityFrameworkCore;
using ResourceApi.Data;
using ResourceApi.Services;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

builder.Services.AddDbContext<OnboardingDbContext>(opt =>
    opt.UseSqlServer(cfg.GetConnectionString("OnboardingDb")));

builder.Services.AddScoped<AuthServerSyncService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// init db + seed
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<OnboardingDbContext>();
    await Seed.EnsureAsync(db);
}

app.UseHttpsRedirection();
app.UseSwagger();
app.UseSwaggerUI();

app.MapControllers();
app.Run();
