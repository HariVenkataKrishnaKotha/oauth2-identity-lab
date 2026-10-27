using System.IO;
using AuthServer.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace AuthServer.Infrastructure;

// This is ONLY used by `dotnet ef` at design time (migrations, etc.)
public sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        // Build configuration relative to the AuthServer project directory
        var basePath = Directory.GetCurrentDirectory();
        var config = new ConfigurationBuilder()
            .SetBasePath(basePath)
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        // Fallback lets migrations run even if appsettings.json is missing
        var cs = config.GetConnectionString("AuthDb")
                 ?? "Server=localhost;Database=AuthDb;Trusted_Connection=True;TrustServerCertificate=True";

        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseSqlServer(cs)
            .Options;

        return new AuthDbContext(options);
    }
}
